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

	"github.com/vultrack/vultrack/internal/config"
	"github.com/vultrack/vultrack/internal/database"
	"github.com/vultrack/vultrack/internal/exploitdb"
	"github.com/vultrack/vultrack/internal/handlers"
	"github.com/vultrack/vultrack/internal/jira"
	"github.com/vultrack/vultrack/internal/metrics"
	"github.com/vultrack/vultrack/internal/nvd"
	"github.com/vultrack/vultrack/internal/oidc"
	"github.com/vultrack/vultrack/internal/oval"
	"github.com/vultrack/vultrack/internal/scanner"
	"github.com/vultrack/vultrack/internal/scanqueue"
	"github.com/vultrack/vultrack/internal/scheduler"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/session"
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

	// OVAL services
	ovalService := services.NewOVALService(db)
	ovalSyncer := oval.NewSyncer(ovalService, settingsService)

	// NVD syncer
	nvdSyncer := nvd.New(db, settingsService)

	// ExploitDB syncer
	exploitDBSyncer := exploitdb.New(db, settingsService)

	// VEX service + syncer
	vexService := services.NewVEXService(db)
	vexSyncer := vex.New(vexService, settingsService)

	// Vulnerability scanner + scan queue
	vulnScanner := scanner.NewScanner(db, vexService)
	scanQ := scanqueue.New(db, vulnScanner, cfg)

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

	// Start scan queue
	scanQ.Start()

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
	reportScheduler.Stop()
	ovalSyncer.Stop()
	nvdSyncer.Stop()
	exploitDBSyncer.Stop()
	vexSyncer.Stop()
	handler.Shutdown()
}
