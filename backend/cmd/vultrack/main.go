package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/ai"
	"github.com/vultrack/vultrack/internal/aiqueue"
	"github.com/vultrack/vultrack/internal/autoassess"
	"github.com/vultrack/vultrack/internal/config"
	"github.com/vultrack/vultrack/internal/database"
	"github.com/vultrack/vultrack/internal/exploitdb"
	"github.com/vultrack/vultrack/internal/handlers"
	"github.com/vultrack/vultrack/internal/jira"
	"github.com/vultrack/vultrack/internal/kernelintel"
	"github.com/vultrack/vultrack/internal/metrics"
	"github.com/vultrack/vultrack/internal/nvd"
	"github.com/vultrack/vultrack/internal/oidc"
	"github.com/vultrack/vultrack/internal/oval"
	"github.com/vultrack/vultrack/internal/preconditions"
	"github.com/vultrack/vultrack/internal/scanner"
	"github.com/vultrack/vultrack/internal/scanqueue"
	"github.com/vultrack/vultrack/internal/scheduler"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/session"
	"github.com/vultrack/vultrack/internal/threatintel"
	"github.com/vultrack/vultrack/internal/vex"
)

func main() {
	// Initialize logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Set log level
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(level)

	log.Info().Str("version", Version).Msg("Starting VulTrack server...")

	// Connect to database
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer db.Close()

	// Run migrations
	if err := database.Migrate(db); err != nil {
		log.Fatal().Err(err).Msg("Failed to run database migrations")
	}

	// Register Prometheus DB collector
	prometheus.MustRegister(metrics.NewDBCollector(db))

	// Initialize services
	serverService := services.NewServerService(db)
	findingService := services.NewFindingService(db)
	assessmentService := services.NewAssessmentService(db)
	statsService := services.NewStatsService(db)
	reasonTemplateService := services.NewReasonTemplateService(db)
	settingsService := services.NewSettingsService(db)
	serverGroupService := services.NewServerGroupService(db)
	reportService := services.NewReportService(db)

	// New services for agent-based architecture
	enrollmentService := services.NewEnrollmentService(db)
	agentService := services.NewAgentService(db)
	packageService := services.NewPackageService(db)

	// Email service
	emailService := services.NewEmailService(cfg)

	// Report schedule service
	reportScheduleService := services.NewReportScheduleService(db)

	// OVAL services, plus Canonical's package vulnerability feed
	ovalService := services.NewOVALService(db)
	pkgFeedService := services.NewPkgFeedService(db)
	ovalSyncer := oval.NewSyncer(ovalService, settingsService, pkgFeedService)

	// Give already-enabled distribution versions the sources their distribution
	// has gained since, so an upgrade picks up the package feed on its own.
	if created, err := ovalService.EnsureOptionalSources(context.Background()); err != nil {
		log.Warn().Err(err).Msg("Failed to create newly available OVAL sources")
	} else if created > 0 {
		log.Info().Int("created", created).Msg("Created newly available OVAL sources")
	}

	// NVD syncer
	nvdSyncer := nvd.New(db, settingsService)

	// ExploitDB syncer
	exploitDBSyncer := exploitdb.New(db, settingsService)

	// CISA KEV and FIRST EPSS
	threatIntelService := services.NewThreatIntelService(db)
	threatIntelSyncer := threatintel.New(db, settingsService)

	// Automated assessment: re-evaluated after every scan, after a KEV/EPSS
	// sync, on configuration changes and at start-up.
	autoAssessmentService := services.NewAutoAssessmentService(db)
	runtimeFactsService := services.NewRuntimeFactsService(db)
	autoEvaluator := autoassess.New(db, settingsService)
	for _, r := range autoassess.Rules {
		metrics.RuleIDs = append(metrics.RuleIDs, r.ID())
	}
	threatIntelSyncer.SetAfterSync(func(src threatintel.Source) {
		autoEvaluator.TriggerAll(string(src) + " sync")
	})
	// Kernel code map for R-KMOD (CVE records, kernel build makefiles).
	kernelSyncer := kernelintel.NewSyncer(db, settingsService, kernelintel.NewFetcher())
	kernelSyncer.AfterChange = autoEvaluator.TriggerAll

	// VEX service + syncer
	vexService := services.NewVEXService(db)
	vexSyncer := vex.New(vexService, settingsService)

	// Vulnerability scanner + scan queue
	vulnScanner := scanner.NewScanner(db, vexService, pkgFeedService)
	scanQ := scanqueue.New(db, vulnScanner, cfg)
	scanQ.SetAfterScan(func(ctx context.Context, serverID int64) {
		r, err := autoEvaluator.EvaluateServer(ctx, serverID)
		if err != nil {
			log.Error().Err(err).Int64("serverId", serverID).Msg("Automated assessment after scan failed")
			return
		}
		if r.Created+r.Changed+r.Revoked > 0 {
			log.Info().Int64("serverId", serverID).Int("created", r.Created).Int("changed", r.Changed).
				Int("revoked", r.Revoked).Msg("Automated assessment updated")
		}
	})

	// AI assessment service + queue (inactive when ANTHROPIC_API_KEY is unset)
	aiAssessmentService := services.NewAIAssessmentService(db)
	var aiClient *ai.Client
	if cfg.AIConfigured() {
		aiClient = ai.New(cfg.AIAPIKey, cfg.AIWorkspaceID, cfg.AIRequestTimeout)
	}
	aiQueue := aiqueue.New(aiClient, aiAssessmentService, findingService, settingsService, cfg)

	// AI precondition analysis (inactive without API key or when disabled)
	preconditionAnalyzer := preconditions.New(db, settingsService, findingService, aiClient)
	preconditionAnalyzer.AfterChange = autoEvaluator.TriggerAll

	// OIDC auth (provider is nil when OIDC disabled)
	var oidcProvider *oidc.Provider
	if cfg.OIDCEnabled {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		p, err := oidc.NewProvider(ctx, cfg)
		cancel()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize OIDC provider")
		}
		oidcProvider = p
	}
	sessionStore := session.NewStore(db, 0) // 0 = use default 24h
	userService := services.NewUserService(db)

	// API token service (machine credentials for the MCP interface)
	apiTokenService := services.NewAPITokenService(db)

	// Jira client (safe no-op when disabled)
	jiraClient := jira.New(cfg)

	// Report scheduler
	reportScheduler := scheduler.NewReportScheduler(reportScheduleService, reportService, emailService)

	// Start OVAL syncer
	go ovalSyncer.Start()

	// Start NVD syncer
	go nvdSyncer.Start()

	// Start ExploitDB syncer
	go exploitDBSyncer.Start()

	// Start VEX syncer
	go vexSyncer.Start()

	// Start KEV/EPSS syncer
	threatIntelSyncer.Start()

	// Start kernel code map syncer (idle while automated assessment is off)
	kernelSyncer.Start()

	// Re-evaluate all automated decisions once at start-up: a new release may
	// have changed a rule.
	autoEvaluator.TriggerAll("start-up")

	// Daily cleanup of runtime fact snapshots nothing refers to any more, and
	// of kernel builds no server has run for 30 days.
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			snaps, idx, err := runtimeFactsService.CleanupSnapshots(context.Background(), 30*24*time.Hour)
			if err != nil {
				log.Error().Err(err).Msg("Runtime facts cleanup failed")
				continue
			}
			if snaps > 0 || idx > 0 {
				log.Info().Int64("snapshots", snaps).Int64("moduleIndexes", idx).Msg("Runtime facts cleaned up")
			}
			builds, cves, err := kernelSyncer.Cleanup(context.Background(), 30*24*time.Hour)
			if err != nil {
				log.Error().Err(err).Msg("Kernel data cleanup failed")
				continue
			}
			if builds > 0 || cves > 0 {
				log.Info().Int64("kernelBuilds", builds).Int64("cveRecords", cves).Msg("Kernel data cleaned up")
			}
		}
	}()

	// Start scan queue
	scanQ.Start()

	// Start AI assessment queue (no-op when not configured)
	aiQueue.Start()

	// Start AI precondition analysis (no-op without API key)
	preconditionAnalyzer.Start()

	// Start report scheduler
	go reportScheduler.Start()

	// Initialize HTTP handlers
	handler := handlers.New(
		cfg,
		serverService,
		findingService,
		assessmentService,
		statsService,
		reasonTemplateService,
		settingsService,
		serverGroupService,
		reportService,
		enrollmentService,
		agentService,
		packageService,
		ovalService,
		ovalSyncer,
		nvdSyncer,
		exploitDBSyncer,
		vexService,
		vexSyncer,
		vulnScanner,
		scanQ,
		reportScheduleService,
		reportScheduler,
		jiraClient,
		oidcProvider,
		sessionStore,
		userService,
		apiTokenService,
		aiAssessmentService,
		autoAssessmentService,
		autoEvaluator,
		runtimeFactsService,
		threatIntelService,
		threatIntelSyncer,
		kernelSyncer,
		preconditionAnalyzer,
	)

	// Start server
	go func() {
		if err := handler.Start(); err != nil {
			log.Fatal().Err(err).Msg("Failed to start HTTP server")
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down VulTrack server...")
	scanQ.Stop()
	aiQueue.Stop()
	reportScheduler.Stop()
	ovalSyncer.Stop()
	nvdSyncer.Stop()
	exploitDBSyncer.Stop()
	threatIntelSyncer.Stop()
	kernelSyncer.Stop()
	preconditionAnalyzer.Stop()
	vexSyncer.Stop()
	handler.Shutdown()
}
