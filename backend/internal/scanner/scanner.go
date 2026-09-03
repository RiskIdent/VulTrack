package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/services"
)

// Scanner handles vulnerability scanning using OVAL definitions
type Scanner struct {
	db         *pgxpool.Pool
	vexService *services.VEXService
	// pkgFeedService is optional: without it, sources of type 'pkg' are skipped
	// and only the OVAL sources contribute findings.
	pkgFeedService *services.PkgFeedService
}

// NewScanner creates a new Scanner. Both services may be nil, in which case the
// corresponding enrichment or source is skipped.
func NewScanner(db *pgxpool.Pool, vexService *services.VEXService, pkgFeedService *services.PkgFeedService) *Scanner {
	return &Scanner{db: db, vexService: vexService, pkgFeedService: pkgFeedService}
}

// ScanResult contains the results of a vulnerability scan
type ScanResult struct {
	ServerID         int64
	NewFindings      int
	UpdatedFindings  int
	ResolvedFindings int
	TotalChecks      int
	Duration         time.Duration
}

// OVALTestData contains preloaded OVAL test data for scanning
type OVALTestData struct {
	TestID         int64
	TestType       string
	PackageNames   []string       // every package the referenced object matches
	EVROperation   string         // operation of the referenced state ("" = existence-only test)
	EVRValue       string         // value of the referenced state
	ReleasePattern *regexp.Regexp // compiled EVRValue for uname_test "pattern match"
}

// kernelInfo describes the running kernel the way OVAL looks at it.
type kernelInfo struct {
	// Release is `uname -r` (e.g. "6.8.0-79-generic"), compared against
	// uname_state/os_release.
	Release string
	// EVR is the kernel package version derived from Release (e.g. "0:6.8.0-79"),
	// compared against variable_state values. Canonical builds it in the OVAL
	// variable "kernel version in evr format"; comparing the raw uname string
	// instead puts the flavour suffix into the Debian revision field and yields
	// wrong results.
	EVR string
}

// OVALDefinitionData contains definition data with associated CVEs
type OVALDefinitionData struct {
	DefinitionID int64
	OvalID       string
	Title        string
	Description  string
	Severity     string
	CVEIDs       []string
}

// ScanServer scans a server for vulnerabilities based on its packages
func (s *Scanner) ScanServer(ctx context.Context, serverID int64) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{ServerID: serverID}

	// Get server info
	server, err := s.getServer(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to get server: %w", err)
	}

	log.Info().
		Int64("serverId", serverID).
		Str("hostname", server.Name).
		Str("osFamily", server.OSFamily).
		Str("osRelease", server.OSRelease).
		Msg("Starting vulnerability scan")

	// Find all matching OVAL sources (USN + CVE)
	sources, err := s.findOVALSources(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("failed to find OVAL sources: %w", err)
	}
	if len(sources) == 0 {
		log.Warn().
			Str("osFamily", server.OSFamily).
			Str("osRelease", server.OSRelease).
			Msg("No matching OVAL source found for server")
		return result, nil
	}

	// Get server packages
	packages, err := s.getServerPackages(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to get packages: %w", err)
	}

	if len(packages) == 0 {
		log.Warn().Int64("serverId", serverID).Msg("No packages found for server")
		return result, nil
	}

	// Build package map for quick lookup
	packageMap := make(map[string]*models.ServerPackage)
	packageNames := make([]string, 0, len(packages))
	for i := range packages {
		key := packages[i].Name
		packageMap[key] = &packages[i]
		packageNames = append(packageNames, key)
	}

	// Track current findings across all sources (cve_id|package_name -> true if still present)
	currentFindings := make(map[string]bool)

	kernel := kernelInfo{Release: server.Kernel, EVR: KernelEVR(server.Kernel)}
	if server.Kernel != "" && kernel.EVR == "" {
		log.Warn().
			Int64("serverId", serverID).
			Str("kernel", server.Kernel).
			Msg("Cannot derive kernel EVR from reported kernel release; kernel version tests will not match")
	}

	kernelFilter := s.newKernelFeedFilter(ctx, serverID, sources, packageMap, kernel, server.PackageManager)
	suppressedKernelFindings := 0

	// Process each source. Findings from a weaker source never overwrite a
	// stronger one (see models.SourceTypeRank), so the order does not matter.
	for _, source := range sources {
		if source.SourceType == models.SourceTypePkg {
			if err := s.scanPkgFeedSource(ctx, serverID, source, server, currentFindings, result); err != nil {
				// The package feed is supplementary: a release without it, or a
				// source that has not synced yet, must not fail the whole scan.
				log.Warn().Err(err).
					Str("distribution", source.Distribution).
					Str("version", source.Version).
					Msg("Skipping package vulnerability feed for this scan")
			}
			continue
		}

		// Load OVAL test data - OPTIMIZED: only for installed packages
		tests, err := s.loadOVALPackageTests(ctx, source.ID, packageNames)
		if err != nil {
			return nil, fmt.Errorf("failed to load OVAL tests for source %s: %w", source.SourceType, err)
		}

		// Also load kernel tests (uname_test, variable_test)
		kernelTests, err := s.loadOVALKernelTests(ctx, source.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to load OVAL kernel tests for source %s: %w", source.SourceType, err)
		}
		for k, v := range kernelTests {
			tests[k] = v
		}

		testIDs := make([]int64, 0, len(tests))
		for testID := range tests {
			testIDs = append(testIDs, testID)
		}

		definitions, err := s.loadOVALDefinitionsForTests(ctx, source.ID, testIDs)
		if err != nil {
			return nil, fmt.Errorf("failed to load OVAL definitions for source %s: %w", source.SourceType, err)
		}

		log.Debug().
			Str("sourceType", source.SourceType).
			Int("tests", len(tests)).
			Int("definitions", len(definitions)).
			Msg("Loaded scan data for source")

			// Bulk-load all criteria for all definitions at once (avoids N+1 queries)
		defIDs := make([]int64, len(definitions))
		for i, def := range definitions {
			defIDs[i] = def.DefinitionID
		}
		allCriteria, err := s.loadCriteriaBulk(ctx, defIDs)
		if err != nil {
			return nil, fmt.Errorf("failed to bulk-load criteria for source %s: %w", source.SourceType, err)
		}

		log.Debug().
			Str("sourceType", source.SourceType).
			Int("criteriaLoaded", len(allCriteria)).
			Msg("Bulk-loaded criteria for definitions")

		// Evaluate each definition for this source
		for _, def := range definitions {
			if len(def.CVEIDs) == 0 {
				continue
			}

			evaluation := s.evaluateDefinitionWithCriteria(ctx, source.ID, def.DefinitionID, packageMap, tests, server.PackageManager, kernel, allCriteria)
			result.TotalChecks++

			if !evaluation.Matched {
				continue
			}

			if len(evaluation.Packages) > 0 {
				for _, cveID := range def.CVEIDs {
					for _, pkgInfo := range evaluation.Packages {
						key := cveID + "|" + pkgInfo.Package.Name
						currentFindings[key] = true

						// Fixed version and fix_state come directly from the matching test/criterion
						err := s.upsertFinding(ctx, serverID, cveID, pkgInfo.Package, def, pkgInfo.FixedIn, pkgInfo.FixState, server.OSFamily, source.SourceType)
						if err != nil {
							log.Warn().Err(err).
								Str("cve", cveID).
								Str("package", pkgInfo.Package.Name).
								Str("fixState", pkgInfo.FixState).
								Str("sourceType", source.SourceType).
								Msg("Failed to upsert finding")
						} else {
							result.NewFindings++
						}
					}
				}
				continue
			}

			// No package matched, but a test on the running kernel did: the
			// definition covers the kernel itself, which dpkg does not report as
			// an installed package here.
			if evaluation.KernelMatch {
				for _, cveID := range def.CVEIDs {
					// Ubuntu's uname tests carry no architecture predicate, and the
					// riscv64 kernel flavour is also called "generic", so a criterion
					// for a foreign flavour can match the running kernel. Where the
					// package feed can name the source package this kernel was built
					// from, its verdict decides.
					if !kernelFilter.justifies(cveID) {
						suppressedKernelFindings++
						continue
					}

					key := cveID + "|kernel"
					currentFindings[key] = true

					kernelPkg := &models.ServerPackage{
						Name:    "kernel",
						Version: server.Kernel,
					}
					err := s.upsertFinding(ctx, serverID, cveID, kernelPkg, def, "", "affected", server.OSFamily, source.SourceType)
					if err != nil {
						log.Warn().Err(err).
							Str("cve", cveID).
							Str("sourceType", source.SourceType).
							Msg("Failed to upsert kernel finding")
					} else {
						result.NewFindings++
					}
				}
			}
		}
	}

	if suppressedKernelFindings > 0 {
		log.Info().
			Int64("serverId", serverID).
			Str("kernel", kernel.Release).
			Str("kernelSource", kernelFilter.source).
			Int("suppressed", suppressedKernelFindings).
			Msg("Dropped kernel findings the package feed attributes to another kernel flavour")
	}

	// Resolve findings that are no longer detected
	resolved, err := s.resolveOldFindings(ctx, serverID, currentFindings)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to resolve old findings")
	}
	result.ResolvedFindings = resolved

	// Enrich active findings with VEX data (single bulk UPDATE)
	if s.vexService != nil && server.OSCodename != "" {
		enriched, err := s.vexService.EnrichFindings(ctx, serverID, server.OSCodename)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to enrich findings with VEX data")
		} else if enriched > 0 {
			log.Debug().Int64("enriched", enriched).Str("distro", server.OSCodename).Msg("VEX enrichment applied")
		}
	}

	result.Duration = time.Since(startTime)

	log.Info().
		Int64("serverId", serverID).
		Int("newFindings", result.NewFindings).
		Int("resolvedFindings", result.ResolvedFindings).
		Int("totalChecks", result.TotalChecks).
		Dur("duration", result.Duration).
		Msg("Vulnerability scan completed")

	return result, nil
}

// getServer retrieves server information
func (s *Scanner) getServer(ctx context.Context, serverID int64) (*models.Server, error) {
	var server models.Server
	err := s.db.QueryRow(ctx, `
		SELECT id, name, os_family, os_release, 
		       COALESCE(os_codename, ''), COALESCE(kernel, ''), COALESCE(package_manager, 'dpkg')
		FROM servers WHERE id = $1
	`, serverID).Scan(
		&server.ID, &server.Name, &server.OSFamily, &server.OSRelease,
		&server.OSCodename, &server.Kernel, &server.PackageManager,
	)
	return &server, err
}

// findOVALSources returns all enabled OVAL sources matching the server (USN + CVE).
func (s *Scanner) findOVALSources(ctx context.Context, server *models.Server) ([]*models.OVALSource, error) {
	// Match by distribution and version, or by distribution and codename
	rows, err := s.db.Query(ctx, `
		SELECT id, distribution, version, COALESCE(source_type, 'usn'), codename, url, is_enabled
		FROM oval_sources
		WHERE distribution = LOWER($1) AND is_enabled = true
		  AND (version = $2 OR ($3 != '' AND codename = $3))
		ORDER BY source_type
	`, server.OSFamily, server.OSRelease, server.OSCodename)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sources []*models.OVALSource
	for rows.Next() {
		var src models.OVALSource
		err := rows.Scan(
			&src.ID, &src.Distribution, &src.Version, &src.SourceType, &src.Codename, &src.URL, &src.IsEnabled,
		)
		if err != nil {
			return nil, err
		}
		sources = append(sources, &src)
	}
	return sources, rows.Err()
}

// findOVALSource returns the first matching OVAL source (for callers that need a single source).
func (s *Scanner) findOVALSource(ctx context.Context, server *models.Server) (*models.OVALSource, error) {
	sources, err := s.findOVALSources(ctx, server)
	if err != nil || len(sources) == 0 {
		return nil, err
	}
	return sources[0], nil
}

// getServerPackages retrieves active packages for a server
func (s *Scanner) getServerPackages(ctx context.Context, serverID int64) ([]models.ServerPackage, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, server_id, name, version, COALESCE(arch, ''), COALESCE(source_package, '')
		FROM server_packages
		WHERE server_id = $1 AND removed_at IS NULL
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packages []models.ServerPackage
	for rows.Next() {
		var pkg models.ServerPackage
		err := rows.Scan(&pkg.ID, &pkg.ServerID, &pkg.Name, &pkg.Version, &pkg.Arch, &pkg.SourcePackage)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}
	return packages, nil
}

// loadOVALPackageTests loads the dpkginfo/rpminfo tests whose referenced object
// matches at least one installed package, resolving object and state through the
// object_ref/state_ref links stored at import time.
func (s *Scanner) loadOVALPackageTests(ctx context.Context, sourceID int64, packageNames []string) (map[int64]*OVALTestData, error) {
	tests := make(map[int64]*OVALTestData)
	if len(packageNames) == 0 {
		return tests, nil
	}

	rows, err := s.db.Query(ctx, `
		SELECT t.id, t.test_type, o.names,
		       COALESCE(st.evr_operation, ''), COALESCE(st.evr_value, '')
		FROM oval_tests t
		JOIN oval_objects o
		  ON o.source_id = t.source_id AND o.oval_id = t.object_ref
		LEFT JOIN oval_states st
		  ON st.source_id = t.source_id AND st.oval_id = t.state_ref
		WHERE t.source_id = $1
		  AND t.test_type IN ('dpkginfo_test', 'rpminfo_test')
		  AND o.names && $2::text[]
	`, sourceID, packageNames)
	if err != nil {
		return nil, fmt.Errorf("failed to query package tests: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var test OVALTestData
		if err := rows.Scan(&test.TestID, &test.TestType, &test.PackageNames,
			&test.EVROperation, &test.EVRValue); err != nil {
			return nil, err
		}
		tests[test.TestID] = &test
	}
	return tests, rows.Err()
}

// loadOVALKernelTests loads the tests that inspect the running kernel
// (uname_test on `uname -r`, variable_test on the derived kernel EVR).
func (s *Scanner) loadOVALKernelTests(ctx context.Context, sourceID int64) (map[int64]*OVALTestData, error) {
	rows, err := s.db.Query(ctx, `
		SELECT t.id, t.test_type,
		       COALESCE(st.evr_operation, ''), COALESCE(st.evr_value, '')
		FROM oval_tests t
		LEFT JOIN oval_states st
		  ON st.source_id = t.source_id AND st.oval_id = t.state_ref
		WHERE t.source_id = $1 AND t.test_type IN ('uname_test', 'variable_test')
	`, sourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to query kernel tests: %w", err)
	}
	defer rows.Close()

	tests := make(map[int64]*OVALTestData)
	for rows.Next() {
		var test OVALTestData
		if err := rows.Scan(&test.TestID, &test.TestType,
			&test.EVROperation, &test.EVRValue); err != nil {
			return nil, err
		}
		// Compile once here rather than per definition: a single uname pattern is
		// referenced by thousands of definitions.
		if test.TestType == "uname_test" && test.EVROperation == "pattern match" && test.EVRValue != "" {
			pattern, err := regexp.Compile(test.EVRValue)
			if err != nil {
				log.Warn().Err(err).
					Int64("testId", test.TestID).
					Str("pattern", test.EVRValue).
					Msg("Skipping uname test with unusable os_release pattern")
				continue
			}
			test.ReleasePattern = pattern
		}
		tests[test.TestID] = &test
	}
	return tests, rows.Err()
}

// loadOVALDefinitionsForTests loads only definitions that reference the given tests (OPTIMIZED)
func (s *Scanner) loadOVALDefinitionsForTests(ctx context.Context, sourceID int64, testIDs []int64) ([]OVALDefinitionData, error) {
	if len(testIDs) == 0 {
		return []OVALDefinitionData{}, nil
	}

	// Find definition IDs that reference any of our tests via criteria
	// Uses oval_criteria + oval_criteria_tests to link definitions to tests
	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT d.id, d.oval_id, COALESCE(d.title, ''), COALESCE(d.description, ''), 
		       COALESCE(d.severity, ''), COALESCE(d.cve_ids, '{}')
		FROM oval_definitions d
		INNER JOIN oval_criteria c ON c.definition_id = d.id
		INNER JOIN oval_criteria_tests ct ON ct.criteria_id = c.id
		WHERE d.source_id = $1 
		  AND d.class IN ('vulnerability', 'patch')
		  AND ct.test_id = ANY($2)
	`, sourceID, testIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to query definitions: %w", err)
	}
	defer rows.Close()

	var definitions []OVALDefinitionData
	for rows.Next() {
		var def OVALDefinitionData
		err := rows.Scan(&def.DefinitionID, &def.OvalID, &def.Title, &def.Description, &def.Severity, &def.CVEIDs)
		if err != nil {
			return nil, err
		}
		definitions = append(definitions, def)
	}
	return definitions, nil
}

// criterionRef represents a single criterion (test reference) with its metadata
type criterionRef struct {
	TestID  int64
	Negate  bool
	Comment string // Criterion comment carrying semantic meaning (e.g. "affected and needs fixing")
}

type criteriaNode struct {
	ID                int64
	ParentID          *int64
	Operator          string
	Negate            bool
	Tests             []criterionRef // Was TestIDs []int64 — now includes comment
	Children          []*criteriaNode
	ExtendDefinitions []extendDefinitionRef
}

// AffectedPackageInfo contains an affected package with its fix status from the OVAL evaluation
type AffectedPackageInfo struct {
	Package  *models.ServerPackage
	FixedIn  string // EVR value from the matching test (empty for existence-only checks)
	FixState string // "fix_available", "affected", "will_not_fix", "deferred"
}

type extendDefinitionRef struct {
	DefinitionOvalID   string
	ApplicabilityCheck bool
	Negate             bool
}

func (s *Scanner) loadCriteria(ctx context.Context, definitionID int64) ([]*criteriaNode, error) {
	// Load criteria
	criteriaRows, err := s.db.Query(ctx, `
		SELECT id, parent_id, operator, negate
		FROM oval_criteria
		WHERE definition_id = $1
	`, definitionID)
	if err != nil {
		return nil, err
	}
	defer criteriaRows.Close()

	var criteria []*criteriaNode
	for criteriaRows.Next() {
		var c criteriaNode
		err := criteriaRows.Scan(&c.ID, &c.ParentID, &c.Operator, &c.Negate)
		if err != nil {
			return nil, err
		}
		criteria = append(criteria, &c)
	}

	// Load test links with criterion comments
	for _, c := range criteria {
		testRows, err := s.db.Query(ctx, `
			SELECT test_id, negate, COALESCE(comment, '') FROM oval_criteria_tests WHERE criteria_id = $1
		`, c.ID)
		if err != nil {
			continue
		}
		for testRows.Next() {
			var ref criterionRef
			if err := testRows.Scan(&ref.TestID, &ref.Negate, &ref.Comment); err == nil {
				c.Tests = append(c.Tests, ref)
			}
		}
		testRows.Close()
	}

	// Load extend_definition links
	for _, c := range criteria {
		extDefRows, err := s.db.Query(ctx, `
			SELECT definition_oval_id, applicability_check, negate 
			FROM oval_criteria_extend_definitions 
			WHERE criteria_id = $1
		`, c.ID)
		if err != nil {
			continue
		}
		for extDefRows.Next() {
			var extDef extendDefinitionRef
			if err := extDefRows.Scan(&extDef.DefinitionOvalID, &extDef.ApplicabilityCheck, &extDef.Negate); err == nil {
				c.ExtendDefinitions = append(c.ExtendDefinitions, extDef)
			}
		}
		extDefRows.Close()
	}

	return criteria, nil
}

// loadCriteriaBulk loads all criteria, their test links, and extend_definition links
// for a batch of definition IDs in 3 queries total (instead of 3 per definition).
func (s *Scanner) loadCriteriaBulk(ctx context.Context, definitionIDs []int64) (map[int64][]*criteriaNode, error) {
	if len(definitionIDs) == 0 {
		return make(map[int64][]*criteriaNode), nil
	}

	// Step 1: Load all criteria for all definitions
	criteriaRows, err := s.db.Query(ctx, `
		SELECT id, definition_id, parent_id, operator, negate
		FROM oval_criteria
		WHERE definition_id = ANY($1)
	`, definitionIDs)
	if err != nil {
		return nil, fmt.Errorf("bulk load criteria: %w", err)
	}
	defer criteriaRows.Close()

	// Index: criteriaID -> node, and definitionID -> list of nodes
	allNodes := make(map[int64]*criteriaNode)
	byDefinition := make(map[int64][]*criteriaNode)
	var allCriteriaIDs []int64

	for criteriaRows.Next() {
		var c criteriaNode
		var defID int64
		err := criteriaRows.Scan(&c.ID, &defID, &c.ParentID, &c.Operator, &c.Negate)
		if err != nil {
			return nil, err
		}
		allNodes[c.ID] = &c
		byDefinition[defID] = append(byDefinition[defID], &c)
		allCriteriaIDs = append(allCriteriaIDs, c.ID)
	}

	if len(allCriteriaIDs) == 0 {
		return byDefinition, nil
	}

	// Step 2: Load ALL test links for all criteria in one query
	testRows, err := s.db.Query(ctx, `
		SELECT criteria_id, test_id, negate, COALESCE(comment, '')
		FROM oval_criteria_tests
		WHERE criteria_id = ANY($1)
	`, allCriteriaIDs)
	if err != nil {
		return nil, fmt.Errorf("bulk load criteria tests: %w", err)
	}
	defer testRows.Close()

	for testRows.Next() {
		var criteriaID int64
		var ref criterionRef
		if err := testRows.Scan(&criteriaID, &ref.TestID, &ref.Negate, &ref.Comment); err != nil {
			return nil, err
		}
		if node, ok := allNodes[criteriaID]; ok {
			node.Tests = append(node.Tests, ref)
		}
	}

	// Step 3: Load ALL extend_definition links for all criteria in one query
	extDefRows, err := s.db.Query(ctx, `
		SELECT criteria_id, definition_oval_id, applicability_check, negate
		FROM oval_criteria_extend_definitions
		WHERE criteria_id = ANY($1)
	`, allCriteriaIDs)
	if err != nil {
		return nil, fmt.Errorf("bulk load criteria extend defs: %w", err)
	}
	defer extDefRows.Close()

	for extDefRows.Next() {
		var criteriaID int64
		var extDef extendDefinitionRef
		if err := extDefRows.Scan(&criteriaID, &extDef.DefinitionOvalID, &extDef.ApplicabilityCheck, &extDef.Negate); err != nil {
			return nil, err
		}
		if node, ok := allNodes[criteriaID]; ok {
			node.ExtendDefinitions = append(node.ExtendDefinitions, extDef)
		}
	}

	return byDefinition, nil
}

// criteriaResult is the outcome of evaluating one criterion or criteria node.
//
// Packages and KernelMatch are only ever propagated out of a subtree that
// actually holds: an OVAL definition lists the affected packages of every
// release channel it knows about, so collecting matches from branches that
// evaluated to false would blame packages the definition does not apply to.
type criteriaResult struct {
	Matched bool
	// KernelMatch reports that a uname_test or variable_test matched inside the
	// satisfied part of the subtree, i.e. the running kernel really is affected.
	KernelMatch bool
	// Packages are the installed packages the satisfied tests matched.
	Packages []AffectedPackageInfo
}

// evaluateDefinitionWithCriteria evaluates a definition against the server using
// pre-loaded criteria.
func (s *Scanner) evaluateDefinitionWithCriteria(ctx context.Context, sourceID, definitionID int64, packages map[string]*models.ServerPackage, tests map[int64]*OVALTestData, packageManager string, kernel kernelInfo, allCriteria map[int64][]*criteriaNode) criteriaResult {
	rootCriteria := buildCriteriaTree(allCriteria[definitionID])
	if rootCriteria == nil {
		return criteriaResult{}
	}
	return s.evaluateCriteriaNode(ctx, sourceID, rootCriteria, packages, tests, packageManager, kernel)
}

// buildCriteriaTree links a definition's flat criteria rows into a tree and
// returns its root, or nil if the definition has no criteria.
func buildCriteriaTree(criteria []*criteriaNode) *criteriaNode {
	if len(criteria) == 0 {
		return nil
	}

	criteriaMap := make(map[int64]*criteriaNode, len(criteria))
	for _, c := range criteria {
		c.Children = nil
		criteriaMap[c.ID] = c
	}

	var root *criteriaNode
	for _, c := range criteria {
		if c.ParentID == nil {
			if root == nil {
				root = c
			}
			continue
		}
		if parent, ok := criteriaMap[*c.ParentID]; ok {
			parent.Children = append(parent.Children, c)
		}
	}
	return root
}

func (s *Scanner) evaluateCriteriaNode(ctx context.Context, sourceID int64, node *criteriaNode, packages map[string]*models.ServerPackage, tests map[int64]*OVALTestData, packageManager string, kernel kernelInfo) criteriaResult {
	if node == nil {
		return criteriaResult{}
	}

	results := make([]criteriaResult, 0, len(node.Tests)+len(node.Children))

	for _, criterion := range node.Tests {
		results = append(results, evaluateCriterion(criterion, packages, tests, packageManager, kernel))
	}

	for _, child := range node.Children {
		results = append(results, s.evaluateCriteriaNode(ctx, sourceID, child, packages, tests, packageManager, kernel))
	}

	for _, extDef := range node.ExtendDefinitions {
		extDefResult := s.evaluateExtendDefinition(ctx, sourceID, extDef, packages, tests, packageManager, kernel)
		if extDef.Negate {
			extDefResult = negate(extDefResult)
		}

		// Applicability checks are pre-conditions ("Ubuntu 24.04 is installed"):
		// if one fails the definition does not apply to this system at all, and a
		// passing one is not part of the surrounding AND/OR logic.
		if extDef.ApplicabilityCheck {
			if !extDefResult.Matched {
				return criteriaResult{}
			}
			continue
		}

		results = append(results, extDefResult)
	}

	combined := combineCriteriaResults(node.Operator, results)
	if node.Negate {
		combined = negate(combined)
	}
	return combined
}

// combineCriteriaResults applies a criteria node's operator. An absent operator
// means AND per the OVAL specification, and a node without any criteria cannot
// hold.
func combineCriteriaResults(operator string, results []criteriaResult) criteriaResult {
	var combined criteriaResult
	if len(results) == 0 {
		return combined
	}

	if operator == "OR" {
		for _, r := range results {
			if !r.Matched {
				continue
			}
			combined.Matched = true
			combined.KernelMatch = combined.KernelMatch || r.KernelMatch
			combined.Packages = append(combined.Packages, r.Packages...)
		}
		return combined
	}

	for _, r := range results {
		if !r.Matched {
			return criteriaResult{}
		}
	}
	combined.Matched = true
	for _, r := range results {
		combined.KernelMatch = combined.KernelMatch || r.KernelMatch
		combined.Packages = append(combined.Packages, r.Packages...)
	}
	return combined
}

// negate inverts a result. Whatever the negated subtree matched says nothing
// about the system once the sense is flipped, so the evidence is dropped.
func negate(r criteriaResult) criteriaResult {
	return criteriaResult{Matched: !r.Matched}
}

// evaluateCriterion evaluates a single criterion (one test reference).
func evaluateCriterion(criterion criterionRef, packages map[string]*models.ServerPackage, tests map[int64]*OVALTestData, packageManager string, kernel kernelInfo) criteriaResult {
	test, ok := tests[criterion.TestID]
	if !ok {
		// The test was not loaded: either its object matches no installed package,
		// or it is a test type we cannot evaluate (family_test, file_test and
		// textfilecontent54_test, used by the OS inventory and Livepatch notices).
		// Either way the criterion does not hold — skipping it instead would drop
		// it out of the enclosing AND and weaken the condition.
		var unmatched criteriaResult
		if criterion.Negate {
			unmatched.Matched = true
		}
		return unmatched
	}

	var result criteriaResult

	switch test.TestType {
	case "uname_test":
		result.Matched = matchOSRelease(kernel.Release, test)
		result.KernelMatch = result.Matched

	case "variable_test":
		if kernel.EVR != "" && test.EVROperation != "" && test.EVRValue != "" {
			result.Matched = EvaluateVersionOperation(kernel.EVR, test.EVRValue, test.EVROperation, "dpkg")
		}
		result.KernelMatch = result.Matched

	default:
		// Package tests (dpkginfo_test, rpminfo_test). The criterion comment
		// carries the vendor's stance for existence-only tests.
		fixState := classifyCriterionComment(criterion.Comment)

		for _, pkgName := range test.PackageNames {
			pkg, installed := packages[pkgName]
			if !installed {
				continue
			}

			if test.EVROperation == "" || test.EVRValue == "" {
				// Existence-only check: the package is present and the vendor has
				// no fixed version for it yet.
				result.Matched = true
				result.Packages = append(result.Packages, AffectedPackageInfo{
					Package:  pkg,
					FixedIn:  "",
					FixState: fixState,
				})
				continue
			}

			if EvaluateVersionOperation(pkg.Version, test.EVRValue, test.EVROperation, packageManager) {
				result.Matched = true
				result.Packages = append(result.Packages, AffectedPackageInfo{
					Package:  pkg,
					FixedIn:  test.EVRValue,
					FixState: "fix_available", // a known fixed version always means fix_available
				})
			}
		}
	}

	if criterion.Negate {
		result = negate(result)
	}
	return result
}

// matchOSRelease evaluates a uname_test against `uname -r`. OVAL's
// "pattern match" is an unanchored regular expression search, so the pattern
// must not be wrapped in ^...$.
func matchOSRelease(release string, test *OVALTestData) bool {
	if release == "" || test.EVRValue == "" {
		return false
	}

	switch test.EVROperation {
	case "pattern match":
		return test.ReleasePattern != nil && test.ReleasePattern.MatchString(release)
	case "not equal":
		return release != test.EVRValue
	default:
		return release == test.EVRValue
	}
}

// classifyCriterionComment determines the fix_state from the OVAL criterion comment.
// These comments are machine-generated by Canonical's OVAL tools and follow consistent patterns.
// Falls back to "affected" if the comment doesn't match any known pattern.
func classifyCriterionComment(comment string) string {
	switch {
	case comment == "":
		return "affected"
	case strings.Contains(comment, "was vulnerable but has been fixed"):
		return "fix_available"
	case strings.Contains(comment, "decision has been made to ignore"):
		return "will_not_fix"
	case strings.Contains(comment, "decision has been made to defer"):
		return "deferred"
	default:
		// "affected and needs fixing" / "affected and may need fixing", and the
		// fallback for unrecognized comments.
		return "affected"
	}
}

// evaluateExtendDefinition evaluates a referenced definition by its OVAL ID.
func (s *Scanner) evaluateExtendDefinition(ctx context.Context, sourceID int64, extDef extendDefinitionRef, packages map[string]*models.ServerPackage, tests map[int64]*OVALTestData, packageManager string, kernel kernelInfo) criteriaResult {
	// For applicability_check definitions (like "Ubuntu 24.04 is installed"):
	// the scan only loads the OVAL source matching the server's release, so the
	// check is implicitly satisfied. This avoids implementing family_test and
	// textfilecontent54_test, which OVAL uses for OS detection only.
	if extDef.ApplicabilityCheck {
		return criteriaResult{Matched: true}
	}

	// For non-applicability extend_definitions, evaluate the referenced definition.
	// Filtering by source_id keeps the lookup inside the same OVAL source (same
	// distribution release) and prevents cross-version contamination.
	var definitionID int64
	err := s.db.QueryRow(ctx, `
		SELECT id FROM oval_definitions WHERE oval_id = $1 AND source_id = $2
	`, extDef.DefinitionOvalID, sourceID).Scan(&definitionID)
	if err != nil {
		// Definition not found in this source - expected for cross-version references
		return criteriaResult{}
	}

	criteria, err := s.loadCriteria(ctx, definitionID)
	if err != nil {
		log.Warn().Err(err).
			Str("definitionRef", extDef.DefinitionOvalID).
			Msg("Failed to load criteria of extended definition")
		return criteriaResult{}
	}

	rootCriteria := buildCriteriaTree(criteria)
	if rootCriteria == nil {
		return criteriaResult{}
	}

	return s.evaluateCriteriaNode(ctx, sourceID, rootCriteria, packages, tests, packageManager, kernel)
}

// kernelFeedFilter decides whether a kernel finding really applies to the
// kernel a server runs.
//
// Ubuntu's OVAL identifies the running kernel with a uname pattern against
// `uname -r` and has no way to express an architecture, while the riscv64
// kernel flavour is also named "generic". Every "-generic" release string is
// therefore matched by two flavour criteria — linux and linux-riscv,
// linux-hwe-6.14 and linux-riscv-6.14, and so on — and since the criteria sit
// in an OR, one match is enough. On an amd64 host the riscv criterion fires for
// every CVE that affects the riscv kernel but not the one actually booted; that
// was 63% of the kernel findings on Ubuntu 24.04 with 6.8.0-124-generic.
//
// Canonical's package feed records its verdict per kernel source package, which
// resolves the ambiguity the uname pattern cannot. A zero filter is inert, so
// every reason the verdict is unavailable simply leaves OVAL's result standing.
type kernelFeedFilter struct {
	// source is the kernel source package the running kernel was built from.
	source string
	// verdicts is the feed's position on every CVE it tracks for that source.
	verdicts map[string]services.KernelVerdict
	// kernelEVR is the running kernel in the form the feed's fixed versions use.
	kernelEVR      string
	packageManager string
}

// justifies reports whether a kernel finding for cveID should be filed.
//
// It fails open at every step: an inert filter, or a CVE the feed does not
// track, keeps whatever OVAL determined.
func (f *kernelFeedFilter) justifies(cveID string) bool {
	if f == nil || f.source == "" || len(f.verdicts) == 0 {
		return true
	}

	verdict, tracked := f.verdicts[cveID]
	if !tracked {
		// The feed does not cover this CVE at all — it may be newer in the OVAL
		// feed than in the package feed. Not evidence of anything.
		return true
	}

	switch verdict.Status {
	case "vulnerable":
		return true
	case "fixed":
		// Affected as long as the running kernel is older than the fix.
		return EvaluateVersionOperation(f.kernelEVR, verdict.SourceFixedVersion, "less than", f.packageManager)
	default:
		// The feed tracks the CVE but records no status for this source package,
		// which is how a dropped 'not-vulnerable' row shows up: Canonical triaged
		// this kernel as unaffected.
		return false
	}
}

// newKernelFeedFilter resolves which kernel source package the running kernel
// belongs to and loads the feed's verdicts for it. It returns nil — an inert
// filter — whenever any step is unavailable.
func (s *Scanner) newKernelFeedFilter(ctx context.Context, serverID int64, sources []*models.OVALSource, packages map[string]*models.ServerPackage, kernel kernelInfo, packageManager string) *kernelFeedFilter {
	if s.pkgFeedService == nil || kernel.Release == "" || kernel.EVR == "" {
		return nil
	}

	var feedSource *models.OVALSource
	for _, source := range sources {
		if source.SourceType == models.SourceTypePkg {
			feedSource = source
			break
		}
	}
	if feedSource == nil {
		return nil
	}

	kernelSource := s.resolveKernelSource(ctx, feedSource.ID, packages, kernel.Release)
	if kernelSource == "" {
		log.Debug().
			Int64("serverId", serverID).
			Str("kernel", kernel.Release).
			Msg("Cannot tell which kernel source package the running kernel came from; keeping all kernel findings")
		return nil
	}

	verdicts, err := s.pkgFeedService.KernelVerdicts(ctx, feedSource.ID, kernelSource)
	if err != nil {
		log.Warn().Err(err).
			Str("kernelSource", kernelSource).
			Msg("Failed to load kernel verdicts from the package feed; keeping all kernel findings")
		return nil
	}
	if len(verdicts) == 0 {
		return nil
	}

	log.Debug().
		Int64("serverId", serverID).
		Str("kernel", kernel.Release).
		Str("kernelSource", kernelSource).
		Int("verdicts", len(verdicts)).
		Msg("Cross-checking kernel findings against the package feed")

	return &kernelFeedFilter{
		source:         kernelSource,
		verdicts:       verdicts,
		kernelEVR:      kernel.EVR,
		packageManager: packageManager,
	}
}

// resolveKernelSource determines the kernel source package the running kernel
// was built from, or "" when it cannot be established.
//
// The agent's dpkg metadata is asked first because it is authoritative, and
// linux-modules/linux-headers are used rather than linux-image: Ubuntu builds
// the signed image in a separate "linux-signed" source package, which does not
// appear in the vulnerability feed at all. Every candidate is checked against
// the feed's own list of kernel source packages, so a name the feed does not
// know is discarded instead of being treated as a kernel with no vulnerabilities.
func (s *Scanner) resolveKernelSource(ctx context.Context, feedSourceID int64, packages map[string]*models.ServerPackage, release string) string {
	for _, prefix := range []string{"linux-modules-", "linux-headers-"} {
		pkg, installed := packages[prefix+release]
		if !installed || pkg.SourcePackage == "" {
			continue
		}
		known, err := s.pkgFeedService.IsKernelSourcePackage(ctx, feedSourceID, pkg.SourcePackage)
		if err != nil {
			log.Warn().Err(err).Str("candidate", pkg.SourcePackage).Msg("Failed to check kernel source package")
			return ""
		}
		if known {
			return pkg.SourcePackage
		}
	}

	// No usable dpkg metadata: fall back to the feed's own binary map, which is
	// unambiguous for most releases but not for the HWE/riscv pairs.
	kernelSource, err := s.pkgFeedService.KernelSourceForRelease(ctx, feedSourceID, release)
	if err != nil {
		log.Warn().Err(err).Str("kernel", release).Msg("Failed to resolve kernel source package from the package feed")
		return ""
	}
	return kernelSource
}

// scanPkgFeedSource evaluates Canonical's package vulnerability feed for the
// server. This is the same computation `pro cves` performs on the machine
// itself: an installed binary package is affected when its source package has a
// CVE that is either unfixed, or fixed in a source version whose corresponding
// binary version is newer than the installed one.
//
// It complements the OVAL sources rather than replacing them. OVAL enumerates
// only the binary packages its constant_variables list, so the feed adds the
// ones it omits, and it names the pocket a fix comes from. Kernel source
// packages are excluded at the query level: OVAL evaluates the kernel against
// the *running* kernel, which is both more precise and vastly less noisy than
// reporting every installed kernel's binary packages.
func (s *Scanner) scanPkgFeedSource(ctx context.Context, serverID int64, source *models.OVALSource, server *models.Server, currentFindings map[string]bool, result *ScanResult) error {
	if s.pkgFeedService == nil {
		return fmt.Errorf("package vulnerability feed support is not configured")
	}

	candidates, err := s.pkgFeedService.GetScanCandidates(ctx, source.ID, serverID)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return nil
	}

	log.Debug().
		Str("sourceType", source.SourceType).
		Int("candidates", len(candidates)).
		Msg("Loaded package vulnerability feed candidates")

	for _, candidate := range candidates {
		result.TotalChecks++

		fixState := "affected"
		fixedIn := ""
		pocket := ""

		if candidate.Status == "fixed" {
			if candidate.FixedBinaryVersion == "" {
				// The fixing source version no longer builds this binary package.
				// Canonical's own client reports that as affected without a fix,
				// because there is no version to tell the operator to install.
				fixState = "affected"
			} else {
				if !EvaluateVersionOperation(candidate.InstalledVersion, candidate.FixedBinaryVersion, "less than", server.PackageManager) {
					continue // already at or past the fixed version
				}
				fixState = "fix_available"
				fixedIn = candidate.FixedBinaryVersion
				pocket = candidate.Pocket
			}
		}

		pkg := &models.ServerPackage{Name: candidate.PackageName, Version: candidate.InstalledVersion}
		def := OVALDefinitionData{
			Severity: candidate.UbuntuPriority,
			Title: fmt.Sprintf("%s on Ubuntu %s (%s) - %s",
				candidate.CVEID, source.Version, source.Codename, candidate.UbuntuPriority),
		}

		currentFindings[candidate.CVEID+"|"+candidate.PackageName] = true

		if err := s.upsertFindingWithPocket(ctx, serverID, candidate.CVEID, pkg, def,
			fixedIn, fixState, &pocket, server.OSFamily, source.SourceType); err != nil {
			log.Warn().Err(err).
				Str("cve", candidate.CVEID).
				Str("package", candidate.PackageName).
				Msg("Failed to upsert package feed finding")
			continue
		}
		result.NewFindings++
	}

	return nil
}

// upsertFinding creates or updates a finding from an OVAL source. OVAL says
// nothing about the pocket a fix comes from, so it leaves that field alone.
func (s *Scanner) upsertFinding(ctx context.Context, serverID int64, cveID string, pkg *models.ServerPackage, def OVALDefinitionData, fixedVersion string, fixState string, osFamily string, sourceType string) error {
	return s.upsertFindingWithPocket(ctx, serverID, cveID, pkg, def, fixedVersion, fixState, nil, osFamily, sourceType)
}

// upsertFindingWithPocket creates or updates a finding.
//
// What the vendor determined about a package — the fix state, the fixed
// version, the severity — is only overwritten by a source that is at least as
// authoritative (see finding_source_rank in the schema). The pocket is handled
// separately: only the package feed knows it, so it is additive and is written
// whichever source owns the rest of the row. Pass a nil fixPocket to mean "this
// source has no opinion"; pass a pointer to "" to record that there is no
// pocket, which clears a stale one.
//
// The precedence is applied per column in SQL rather than as a WHERE guard, so
// that last_seen_at still advances when a weaker source reports the finding —
// otherwise the row would look stale purely because a stronger source got there
// first.
func (s *Scanner) upsertFindingWithPocket(ctx context.Context, serverID int64, cveID string, pkg *models.ServerPackage, def OVALDefinitionData, fixedVersion, fixState string, fixPocket *string, osFamily, sourceType string) error {
	now := time.Now()
	if sourceType == "" {
		sourceType = models.SourceTypeUSN
	}
	if fixState == "" {
		fixState = "affected"
	}

	// Map vendor severity to our severity
	severity := mapSeverity(def.Severity)

	// Generate vendor advisory link
	sourceLink := getVendorLink(osFamily, cveID)

	_, err := s.db.Exec(ctx, upsertFindingQuery,
		serverID, cveID, pkg.Name, pkg.Version,
		fixState, fixedVersion, fixPocket, severity, def.Title, sourceLink, sourceType, now)

	return err
}

// findingSourceWins is true when the incoming source ($11) is at least as
// authoritative as the one already on the row.
const findingSourceWins = `finding_source_rank($11) >= finding_source_rank(findings.source_type)`

// upsertFindingQuery is assembled once: it is executed for every single finding
// of every scan.
var upsertFindingQuery = fmt.Sprintf(`
	INSERT INTO findings (
		server_id, cve_id, package_name, package_version,
		fix_state, fixed_in, fix_pocket, severity, summary, source_link, source_type,
		first_seen_at, last_seen_at, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9, $10, $11, $12, $12, $12, $12)
	ON CONFLICT (server_id, cve_id, package_name)
	DO UPDATE SET
		package_version = CASE WHEN %[1]s THEN EXCLUDED.package_version ELSE findings.package_version END,
		fix_state       = CASE WHEN %[1]s THEN EXCLUDED.fix_state       ELSE findings.fix_state       END,
		fixed_in        = CASE WHEN %[1]s THEN EXCLUDED.fixed_in        ELSE findings.fixed_in        END,
		severity        = CASE WHEN %[1]s THEN EXCLUDED.severity        ELSE findings.severity        END,
		summary         = CASE WHEN %[1]s THEN EXCLUDED.summary         ELSE findings.summary         END,
		source_link     = CASE WHEN %[1]s THEN EXCLUDED.source_link     ELSE findings.source_link     END,
		source_type     = CASE WHEN %[1]s THEN EXCLUDED.source_type     ELSE findings.source_type     END,
		fix_pocket      = CASE WHEN $7::text IS NULL THEN findings.fix_pocket ELSE NULLIF($7, '') END,
		last_seen_at    = EXCLUDED.last_seen_at,
		updated_at      = EXCLUDED.updated_at,
		resolved_at     = NULL
`, findingSourceWins)

func mapSeverity(ovalSeverity string) string {
	switch ovalSeverity {
	case "Critical", "critical":
		return "critical"
	case "Important", "important", "High", "high":
		return "high"
	case "Moderate", "moderate", "Medium", "medium":
		return "medium"
	case "Low", "low":
		return "low"
	case "Negligible", "negligible":
		return "negligible"
	default:
		return "unknown"
	}
}

// getVendorLink returns the vendor CVE advisory URL based on OS family
func getVendorLink(osFamily, cveID string) string {
	switch osFamily {
	case "ubuntu":
		return fmt.Sprintf("https://ubuntu.com/security/%s", cveID)
	case "debian":
		return fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", cveID)
	case "rhel", "centos", "rocky", "alma":
		return fmt.Sprintf("https://access.redhat.com/security/cve/%s", cveID)
	case "oracle":
		return fmt.Sprintf("https://linux.oracle.com/cve/%s.html", cveID)
	case "suse", "opensuse":
		return fmt.Sprintf("https://www.suse.com/security/cve/%s/", cveID)
	default:
		return ""
	}
}

// resolveOldFindings marks findings as resolved if they are no longer detected
func (s *Scanner) resolveOldFindings(ctx context.Context, serverID int64, currentFindings map[string]bool) (int, error) {
	// Get existing unresolved findings
	rows, err := s.db.Query(ctx, `
		SELECT id, cve_id, package_name
		FROM findings
		WHERE server_id = $1 AND resolved_at IS NULL
	`, serverID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var toResolve []int64
	for rows.Next() {
		var id int64
		var cveID, pkgName string
		if err := rows.Scan(&id, &cveID, &pkgName); err != nil {
			continue
		}
		key := cveID + "|" + pkgName
		if !currentFindings[key] {
			toResolve = append(toResolve, id)
		}
	}

	// Mark as resolved
	now := time.Now()
	for _, id := range toResolve {
		_, err := s.db.Exec(ctx, `
			UPDATE findings SET resolved_at = $1, updated_at = $1 WHERE id = $2
		`, now, id)
		if err != nil {
			log.Warn().Err(err).Int64("findingId", id).Msg("Failed to resolve finding")
		}
	}

	return len(toResolve), nil
}
