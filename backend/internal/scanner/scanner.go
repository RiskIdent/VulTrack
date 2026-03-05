package scanner

import (
	"context"
	"fmt"
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
}

// NewScanner creates a new Scanner
func NewScanner(db *pgxpool.Pool, vexService *services.VEXService) *Scanner {
	return &Scanner{db: db, vexService: vexService}
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
	TestID       int64
	TestType     string
	PackageName  string   // Primary package name
	PackageNames []string // All package names (for var_ref expanded objects)
	EVROperation string
	EVRValue     string
}

// GetPackageNames returns all package names this test applies to
func (t *OVALTestData) GetPackageNames() []string {
	if len(t.PackageNames) > 0 {
		return t.PackageNames
	}
	if t.PackageName != "" {
		return []string{t.PackageName}
	}
	return nil
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

	// Process each OVAL source (USN, then CVE)
	for _, source := range sources {
		// Load OVAL test data - OPTIMIZED: only for installed packages
		tests, err := s.loadOVALTestsForPackages(ctx, source.ID, packageNames)
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

			vulnerable, affectedPackages := s.evaluateDefinitionWithCriteria(ctx, source.ID, def.DefinitionID, packageMap, tests, server.PackageManager, server.Kernel, allCriteria)
			result.TotalChecks++

			if vulnerable {
				hasKernelTests := s.definitionHasKernelTests(ctx, def.DefinitionID, tests)

				if len(affectedPackages) > 0 {
					for _, cveID := range def.CVEIDs {
						for _, pkgInfo := range affectedPackages {
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
				} else if hasKernelTests {
					for _, cveID := range def.CVEIDs {
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

// loadOVALTests loads all tests for a source with their object and state data
func (s *Scanner) loadOVALTests(ctx context.Context, sourceID int64) (map[int64]*OVALTestData, error) {
	rows, err := s.db.Query(ctx, `
		SELECT t.id, t.test_type, o.name, COALESCE(st.evr_operation, ''), COALESCE(st.evr_value, '')
		FROM oval_tests t
		LEFT JOIN oval_objects o ON o.source_id = t.source_id AND o.oval_id = (
			SELECT oval_id FROM oval_objects WHERE source_id = t.source_id LIMIT 1
		)
		LEFT JOIN oval_states st ON st.source_id = t.source_id
		WHERE t.source_id = $1
	`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// This query is not ideal - we need a better way to link tests to objects/states
	// For now, load them separately
	rows.Close()

	// Load tests with a simpler approach
	tests := make(map[int64]*OVALTestData)

	// Load test -> object -> state mappings
	testRows, err := s.db.Query(ctx, `
		SELECT t.id, t.test_type, t.oval_id
		FROM oval_tests t
		WHERE t.source_id = $1
	`, sourceID)
	if err != nil {
		return nil, err
	}
	defer testRows.Close()

	testOvalIDs := make(map[int64]string)
	for testRows.Next() {
		var testID int64
		var testType, ovalID string
		if err := testRows.Scan(&testID, &testType, &ovalID); err != nil {
			return nil, err
		}
		tests[testID] = &OVALTestData{
			TestID:   testID,
			TestType: testType,
		}
		testOvalIDs[testID] = ovalID
	}

	// Load objects
	objectRows, err := s.db.Query(ctx, `
		SELECT id, oval_id, name FROM oval_objects WHERE source_id = $1
	`, sourceID)
	if err != nil {
		return nil, err
	}
	defer objectRows.Close()

	objects := make(map[string]string)           // oval_id -> name (exact match)
	objectsByPrefix := make(map[string][]string) // base_oval_id -> list of package names
	for objectRows.Next() {
		var id int64
		var ovalID, name string
		if err := objectRows.Scan(&id, &ovalID, &name); err != nil {
			return nil, err
		}
		objects[ovalID] = name

		// Also index by prefix (for var_ref expanded objects like "oval:...:obj:123:pkgname")
		// Extract base ID by taking everything before the last colon if it contains 5+ colons
		colonCount := countColons(ovalID)
		if colonCount >= 4 {
			// Format: oval:namespace:obj:id:pkgname -> base is oval:namespace:obj:id
			lastColon := lastIndexColon(ovalID)
			if lastColon > 0 {
				baseID := ovalID[:lastColon]
				objectsByPrefix[baseID] = append(objectsByPrefix[baseID], name)
			}
		}
	}

	// Load states
	stateRows, err := s.db.Query(ctx, `
		SELECT id, oval_id, evr_operation, evr_value FROM oval_states WHERE source_id = $1
	`, sourceID)
	if err != nil {
		return nil, err
	}
	defer stateRows.Close()

	type stateData struct {
		operation string
		value     string
	}
	states := make(map[string]stateData) // oval_id -> state data
	for stateRows.Next() {
		var id int64
		var ovalID, op, val string
		if err := stateRows.Scan(&id, &ovalID, &op, &val); err != nil {
			return nil, err
		}
		states[ovalID] = stateData{operation: op, value: val}
	}

	// Now we need to link tests to objects and states
	// The OVAL standard uses object_ref and state_ref attributes
	// We stored these during parsing but need to resolve them

	// For now, use a heuristic: extract object/state IDs from test oval_id
	// e.g., oval:com.ubuntu.noble:tst:123 -> look for obj:123 and ste:123
	for testID, ovalID := range testOvalIDs {
		// Extract the numeric part
		parts := splitOvalID(ovalID)
		if parts.id == "" {
			continue
		}

		// Look for matching object (exact match first)
		objOvalID := fmt.Sprintf("oval:%s:obj:%s", parts.namespace, parts.id)
		if name, ok := objects[objOvalID]; ok {
			tests[testID].PackageName = name
		} else if names, ok := objectsByPrefix[objOvalID]; ok && len(names) > 0 {
			// Multiple packages from var_ref expansion - store all names
			tests[testID].PackageNames = names
			tests[testID].PackageName = names[0] // Primary for backwards compat
		}

		// Look for matching state
		steOvalID := fmt.Sprintf("oval:%s:ste:%s", parts.namespace, parts.id)
		if st, ok := states[steOvalID]; ok {
			tests[testID].EVROperation = st.operation
			tests[testID].EVRValue = st.value
		}
	}

	return tests, nil
}

// loadOVALTestsForPackages loads only tests relevant to the given packages (OPTIMIZED)
func (s *Scanner) loadOVALTestsForPackages(ctx context.Context, sourceID int64, packageNames []string) (map[int64]*OVALTestData, error) {
	if len(packageNames) == 0 {
		return make(map[int64]*OVALTestData), nil
	}

	// Step 1: Find all objects matching the installed packages
	// This is the key optimization - we filter at the DB level
	objectRows, err := s.db.Query(ctx, `
		SELECT id, oval_id, name FROM oval_objects 
		WHERE source_id = $1 AND name = ANY($2)
	`, sourceID, packageNames)
	if err != nil {
		return nil, fmt.Errorf("failed to query objects: %w", err)
	}
	defer objectRows.Close()

	// Build reverse index: extract base OVAL IDs to find matching tests
	// Object OVAL ID format: oval:namespace:obj:123 or oval:namespace:obj:123:pkgname
	testOvalIDsNeeded := make(map[string]bool)    // set of test oval_ids we need
	objectPackageMap := make(map[string][]string) // base_obj_id -> package names

	for objectRows.Next() {
		var id int64
		var ovalID, name string
		if err := objectRows.Scan(&id, &ovalID, &name); err != nil {
			return nil, err
		}

		// Extract base object ID and derive test ID
		parts := splitOvalID(ovalID)
		if parts.id == "" {
			continue
		}

		// Handle composite IDs (oval:ns:obj:123:pkgname)
		baseID := parts.id
		if colonCount := countColons(ovalID); colonCount >= 4 {
			// Extract just the numeric part
			lastColon := lastIndexColon(ovalID)
			if lastColon > 0 {
				baseParts := splitOvalID(ovalID[:lastColon])
				baseID = baseParts.id
			}
		}

		// Derive test OVAL ID from object ID
		testOvalID := fmt.Sprintf("oval:%s:tst:%s", parts.namespace, baseID)
		testOvalIDsNeeded[testOvalID] = true

		objKey := fmt.Sprintf("oval:%s:obj:%s", parts.namespace, baseID)
		objectPackageMap[objKey] = append(objectPackageMap[objKey], name)
	}

	if len(testOvalIDsNeeded) == 0 {
		return make(map[int64]*OVALTestData), nil
	}

	// Step 2: Load only the tests we need
	testOvalIDs := make([]string, 0, len(testOvalIDsNeeded))
	for ovalID := range testOvalIDsNeeded {
		testOvalIDs = append(testOvalIDs, ovalID)
	}

	testRows, err := s.db.Query(ctx, `
		SELECT id, test_type, oval_id FROM oval_tests 
		WHERE source_id = $1 AND oval_id = ANY($2)
	`, sourceID, testOvalIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to query tests: %w", err)
	}
	defer testRows.Close()

	tests := make(map[int64]*OVALTestData)
	testIDToOvalID := make(map[int64]string)

	for testRows.Next() {
		var testID int64
		var testType, ovalID string
		if err := testRows.Scan(&testID, &testType, &ovalID); err != nil {
			return nil, err
		}
		tests[testID] = &OVALTestData{
			TestID:   testID,
			TestType: testType,
		}
		testIDToOvalID[testID] = ovalID
	}

	// Step 3: Load only the states we need
	stateOvalIDs := make([]string, 0, len(testOvalIDsNeeded))
	for testOvalID := range testOvalIDsNeeded {
		parts := splitOvalID(testOvalID)
		stateOvalID := fmt.Sprintf("oval:%s:ste:%s", parts.namespace, parts.id)
		stateOvalIDs = append(stateOvalIDs, stateOvalID)
	}

	stateRows, err := s.db.Query(ctx, `
		SELECT oval_id, evr_operation, evr_value FROM oval_states 
		WHERE source_id = $1 AND oval_id = ANY($2)
	`, sourceID, stateOvalIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to query states: %w", err)
	}
	defer stateRows.Close()

	type stateData struct {
		operation string
		value     string
	}
	states := make(map[string]stateData)
	for stateRows.Next() {
		var ovalID, op, val string
		if err := stateRows.Scan(&ovalID, &op, &val); err != nil {
			return nil, err
		}
		states[ovalID] = stateData{operation: op, value: val}
	}

	// Step 4: Link tests to packages and states
	for testID, testOvalID := range testIDToOvalID {
		parts := splitOvalID(testOvalID)
		if parts.id == "" {
			continue
		}

		// Get package names for this test
		objOvalID := fmt.Sprintf("oval:%s:obj:%s", parts.namespace, parts.id)
		if names, ok := objectPackageMap[objOvalID]; ok {
			tests[testID].PackageNames = names
			if len(names) > 0 {
				tests[testID].PackageName = names[0]
			}
		}

		// Get state data
		steOvalID := fmt.Sprintf("oval:%s:ste:%s", parts.namespace, parts.id)
		if st, ok := states[steOvalID]; ok {
			tests[testID].EVROperation = st.operation
			tests[testID].EVRValue = st.value
		}
	}

	return tests, nil
}

// loadOVALKernelTests loads uname_test and variable_test tests (kernel version checks)
func (s *Scanner) loadOVALKernelTests(ctx context.Context, sourceID int64) (map[int64]*OVALTestData, error) {
	// Load all kernel-related tests
	testRows, err := s.db.Query(ctx, `
		SELECT t.id, t.test_type, t.oval_id
		FROM oval_tests t
		WHERE t.source_id = $1 AND t.test_type IN ('uname_test', 'variable_test')
	`, sourceID)
	if err != nil {
		return nil, err
	}
	defer testRows.Close()

	tests := make(map[int64]*OVALTestData)
	testOvalIDs := make(map[int64]string)

	for testRows.Next() {
		var testID int64
		var testType, ovalID string
		if err := testRows.Scan(&testID, &testType, &ovalID); err != nil {
			return nil, err
		}
		tests[testID] = &OVALTestData{
			TestID:   testID,
			TestType: testType,
		}
		testOvalIDs[testID] = ovalID
	}

	if len(tests) == 0 {
		return tests, nil
	}

	// Load states for kernel tests
	stateRows, err := s.db.Query(ctx, `
		SELECT id, oval_id, evr_operation, evr_value FROM oval_states 
		WHERE source_id = $1 AND state_type IN ('uname_state', 'variable_state')
	`, sourceID)
	if err != nil {
		return nil, err
	}
	defer stateRows.Close()

	type stateData struct {
		operation string
		value     string
	}
	states := make(map[string]stateData)
	for stateRows.Next() {
		var id int64
		var ovalID, op, val string
		if err := stateRows.Scan(&id, &ovalID, &op, &val); err != nil {
			return nil, err
		}
		states[ovalID] = stateData{operation: op, value: val}
	}

	// Link tests to states using OVAL ID heuristic
	for testID, ovalID := range testOvalIDs {
		parts := splitOvalID(ovalID)
		if parts.id == "" {
			continue
		}

		// Build state OVAL ID: oval:namespace:ste:123
		steOvalID := fmt.Sprintf("oval:%s:ste:%s", parts.namespace, parts.id)
		if st, ok := states[steOvalID]; ok {
			tests[testID].EVROperation = st.operation
			tests[testID].EVRValue = st.value
		}
	}

	return tests, nil
}

func countColons(s string) int {
	count := 0
	for _, c := range s {
		if c == ':' {
			count++
		}
	}
	return count
}

func lastIndexColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

type ovalIDParts struct {
	namespace string
	typ       string
	id        string
}

func splitOvalID(ovalID string) ovalIDParts {
	// Format: oval:com.ubuntu.noble:tst:12345
	parts := ovalIDParts{}
	segments := splitString(ovalID, ":")
	if len(segments) >= 4 {
		parts.namespace = segments[1]
		parts.typ = segments[2]
		parts.id = segments[3]
	}
	return parts
}

func splitString(s, sep string) []string {
	var result []string
	for len(s) > 0 {
		idx := indexOf(s, sep)
		if idx < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// loadOVALDefinitions loads all definitions for a source (kept for backwards compat)
func (s *Scanner) loadOVALDefinitions(ctx context.Context, sourceID int64) ([]OVALDefinitionData, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, oval_id, COALESCE(title, ''), COALESCE(description, ''), 
		       COALESCE(severity, ''), COALESCE(cve_ids, '{}')
		FROM oval_definitions
		WHERE source_id = $1 AND class IN ('vulnerability', 'patch')
	`, sourceID)
	if err != nil {
		return nil, err
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

// evaluateDefinition evaluates a definition's criteria against installed packages.
// Returns whether the system is vulnerable and the list of affected packages with fix status.
func (s *Scanner) evaluateDefinition(ctx context.Context, sourceID, definitionID int64, packages map[string]*models.ServerPackage, tests map[int64]*OVALTestData, packageManager string, kernelVersion string) (bool, []AffectedPackageInfo) {
	// Load criteria for this definition
	criteria, err := s.loadCriteria(ctx, definitionID)
	if err != nil {
		log.Warn().Err(err).Int64("definitionId", definitionID).Msg("Failed to load criteria")
		return false, nil
	}

	if len(criteria) == 0 {
		return false, nil
	}

	// Find root criteria (no parent)
	var rootCriteria *criteriaNode
	for _, c := range criteria {
		if c.ParentID == nil {
			rootCriteria = c
			break
		}
	}

	if rootCriteria == nil {
		return false, nil
	}

	// Build criteria tree
	criteriaMap := make(map[int64]*criteriaNode)
	for _, c := range criteria {
		criteriaMap[c.ID] = c
	}
	for _, c := range criteria {
		if c.ParentID != nil {
			if parent, ok := criteriaMap[*c.ParentID]; ok {
				parent.Children = append(parent.Children, c)
			}
		}
	}

	// Evaluate the criteria tree
	var affectedPackages []AffectedPackageInfo
	vulnerable := s.evaluateCriteriaNode(ctx, sourceID, rootCriteria, packages, tests, packageManager, kernelVersion, &affectedPackages)

	return vulnerable, affectedPackages
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

// evaluateDefinitionWithCriteria evaluates a definition using pre-loaded criteria.
// The evaluation logic is identical to evaluateDefinition — only the data source differs.
func (s *Scanner) evaluateDefinitionWithCriteria(ctx context.Context, sourceID, definitionID int64, packages map[string]*models.ServerPackage, tests map[int64]*OVALTestData, packageManager string, kernelVersion string, allCriteria map[int64][]*criteriaNode) (bool, []AffectedPackageInfo) {
	criteria, ok := allCriteria[definitionID]
	if !ok || len(criteria) == 0 {
		return false, nil
	}

	// Find root criteria (no parent)
	var rootCriteria *criteriaNode
	for _, c := range criteria {
		if c.ParentID == nil {
			rootCriteria = c
			break
		}
	}

	if rootCriteria == nil {
		return false, nil
	}

	// Build criteria tree
	criteriaMap := make(map[int64]*criteriaNode)
	for _, c := range criteria {
		criteriaMap[c.ID] = c
	}
	for _, c := range criteria {
		if c.ParentID != nil {
			if parent, ok := criteriaMap[*c.ParentID]; ok {
				parent.Children = append(parent.Children, c)
			}
		}
	}

	// Evaluate the criteria tree (same logic as evaluateDefinition)
	var affectedPackages []AffectedPackageInfo
	vulnerable := s.evaluateCriteriaNode(ctx, sourceID, rootCriteria, packages, tests, packageManager, kernelVersion, &affectedPackages)

	return vulnerable, affectedPackages
}

func (s *Scanner) evaluateCriteriaNode(ctx context.Context, sourceID int64, node *criteriaNode, packages map[string]*models.ServerPackage, tests map[int64]*OVALTestData, packageManager string, kernelVersion string, affectedPackages *[]AffectedPackageInfo) bool {
	if node == nil {
		return false
	}

	var results []bool

	// Evaluate direct test references (now with criterion comments)
	for _, criterion := range node.Tests {
		test, ok := tests[criterion.TestID]
		if !ok {
			continue
		}

		testMatched := false

		// Handle kernel tests (uname_test, variable_test)
		if test.TestType == "uname_test" || test.TestType == "variable_test" {
			if kernelVersion == "" {
				// No kernel version available - skip kernel tests
				continue
			}

			if test.TestType == "uname_test" {
				// Pattern matching for kernel version (e.g., "6.8.*")
				if test.EVRValue != "" {
					matched := matchKernelPattern(kernelVersion, test.EVRValue)
					if matched {
						testMatched = true
					}
				}
			} else if test.TestType == "variable_test" {
				// Version comparison for kernel version
				if test.EVROperation != "" && test.EVRValue != "" {
					vulnerable := EvaluateVersionOperation(kernelVersion, test.EVRValue, test.EVROperation, "generic")
					if vulnerable {
						testMatched = true
					}
				}
			}
		} else {
			// Handle package tests (dpkginfo_test, rpminfo_test)
			pkgNames := test.GetPackageNames()

			// Determine the fix_state from the criterion comment
			fixState := classifyCriterionComment(criterion.Comment)

			for _, pkgName := range pkgNames {
				pkg, ok := packages[pkgName]
				if !ok {
					// Package not installed - continue checking other names
					continue
				}

				// Evaluate version comparison
				if test.EVROperation != "" && test.EVRValue != "" {
					vulnerable := EvaluateVersionOperation(pkg.Version, test.EVRValue, test.EVROperation, packageManager)
					if vulnerable {
						*affectedPackages = append(*affectedPackages, AffectedPackageInfo{
							Package:  pkg,
							FixedIn:  test.EVRValue,
							FixState: fixState, // Typically "fix_available" for version-checked tests
						})
						testMatched = true
					}
				} else {
					// Existence-only check - package is present.
					// The fix_state (from criterion comment) determines the categorization:
					// - "affected": known vulnerability, no fix available yet
					// - "will_not_fix": vendor decided to ignore this issue
					// - "deferred": vendor acknowledged but deferred the fix
					*affectedPackages = append(*affectedPackages, AffectedPackageInfo{
						Package:  pkg,
						FixedIn:  "", // No fixed version for existence-only checks
						FixState: fixState,
					})
					testMatched = true
				}
			}
		}

		// Apply criterion-level negate if needed
		if criterion.Negate {
			testMatched = !testMatched
		}

		results = append(results, testMatched)
	}

	// Evaluate child criteria
	for _, child := range node.Children {
		childResult := s.evaluateCriteriaNode(ctx, sourceID, child, packages, tests, packageManager, kernelVersion, affectedPackages)
		results = append(results, childResult)
	}

	// Evaluate extend_definition references
	for _, extDef := range node.ExtendDefinitions {
		extDefResult := s.evaluateExtendDefinition(ctx, sourceID, extDef, packages, tests, packageManager, kernelVersion, affectedPackages)

		// Apply negation if needed
		if extDef.Negate {
			extDefResult = !extDefResult
		}

		// Applicability checks are pre-conditions:
		// If failed, the vulnerability doesn't apply to this system
		if extDef.ApplicabilityCheck {
			if !extDefResult {
				return false
			}
			// If passed, don't add to results - it's a pre-condition, not part of AND/OR logic
			continue
		}

		// Non-applicability extend_definitions are regular conditions
		results = append(results, extDefResult)
	}

	// Combine results based on operator
	var result bool
	switch node.Operator {
	case "AND":
		// Empty results means no tests matched - not vulnerable
		if len(results) == 0 {
			result = false
		} else {
			result = true
			for _, r := range results {
				if !r {
					result = false
					break
				}
			}
		}
	case "OR":
		result = false
		for _, r := range results {
			if r {
				result = true
				break
			}
		}
	default:
		// Default to AND
		result = len(results) > 0
		for _, r := range results {
			if !r {
				result = false
				break
			}
		}
	}

	// Apply negation
	if node.Negate {
		result = !result
	}

	return result
}

// classifyCriterionComment determines the fix_state from the OVAL criterion comment.
// These comments are machine-generated by Canonical's OVAL tools and follow consistent patterns.
// Falls back to "affected" if the comment doesn't match any known pattern.
func classifyCriterionComment(comment string) string {
	if comment == "" {
		return "affected"
	}

	// Check for version-fixed pattern: "was vulnerable but has been fixed"
	if indexOf(comment, "was vulnerable but has been fixed") >= 0 {
		return "fix_available"
	}

	// Check for vendor ignore: "decision has been made to ignore"
	if indexOf(comment, "decision has been made to ignore") >= 0 {
		return "will_not_fix"
	}

	// Check for deferred: "decision has been made to defer"
	if indexOf(comment, "decision has been made to defer") >= 0 {
		return "deferred"
	}

	// "affected and needs fixing" or "affected and may need fixing" → affected (no fix available)
	// This is also the fallback for unrecognized comments
	return "affected"
}

// evaluateExtendDefinition evaluates a referenced definition by its OVAL ID
func (s *Scanner) evaluateExtendDefinition(ctx context.Context, sourceID int64, extDef extendDefinitionRef, packages map[string]*models.ServerPackage, tests map[int64]*OVALTestData, packageManager string, kernelVersion string, affectedPackages *[]AffectedPackageInfo) bool {
	// For applicability_check definitions (like "Ubuntu 24.04 is installed"):
	// Since VulTrack already loads only the OVAL source matching the server's OS codename,
	// the applicability check is implicitly satisfied. We return true to indicate
	// that the server matches the expected OS/distribution.
	//
	// This is a pragmatic optimization that avoids implementing family_test and
	// textfilecontent54_test which are only used for OS detection in OVAL.
	if extDef.ApplicabilityCheck {
		return true
	}

	// For non-applicability extend_definitions, evaluate the referenced definition
	// IMPORTANT: Filter by source_id to ensure we only use definitions from the same OVAL source
	// (same Ubuntu version). This prevents cross-version contamination.
	var definitionID int64
	err := s.db.QueryRow(ctx, `
		SELECT id FROM oval_definitions WHERE oval_id = $1 AND source_id = $2
	`, extDef.DefinitionOvalID, sourceID).Scan(&definitionID)
	if err != nil {
		// Definition not found in this source - this is expected for cross-version references
		return false
	}

	// Load criteria for the referenced definition
	criteria, err := s.loadCriteria(ctx, definitionID)
	if err != nil || len(criteria) == 0 {
		return false
	}

	// Find root criteria (parent_id is NULL)
	var rootCriteria *criteriaNode
	for _, c := range criteria {
		if c.ParentID == nil {
			rootCriteria = c
			break
		}
	}
	if rootCriteria == nil {
		return false
	}

	// Build criteria tree
	criteriaMap := make(map[int64]*criteriaNode)
	for _, c := range criteria {
		criteriaMap[c.ID] = c
	}
	for _, c := range criteria {
		if c.ParentID != nil {
			if parent, ok := criteriaMap[*c.ParentID]; ok {
				parent.Children = append(parent.Children, c)
			}
		}
	}

	// Evaluate the criteria tree of the referenced definition
	result := s.evaluateCriteriaNode(ctx, sourceID, rootCriteria, packages, tests, packageManager, kernelVersion, affectedPackages)

	return result
}

// getFixedVersion is no longer used - fixed version is now determined per-test
// during criteria evaluation and returned as part of AffectedPackageInfo.

// definitionHasKernelTests checks if a definition uses kernel tests
func (s *Scanner) definitionHasKernelTests(ctx context.Context, definitionID int64, tests map[int64]*OVALTestData) bool {
	// Load test IDs for this definition
	rows, err := s.db.Query(ctx, `
		SELECT test_id FROM oval_criteria_tests 
		WHERE criteria_id IN (
			SELECT id FROM oval_criteria WHERE definition_id = $1
		)
	`, definitionID)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var testID int64
		if err := rows.Scan(&testID); err != nil {
			continue
		}
		if test, ok := tests[testID]; ok {
			if test.TestType == "uname_test" || test.TestType == "variable_test" {
				return true
			}
		}
	}
	return false
}

// upsertFinding creates or updates a finding. Precedence: USN overwrites CVE; CVE does not overwrite USN.
func (s *Scanner) upsertFinding(ctx context.Context, serverID int64, cveID string, pkg *models.ServerPackage, def OVALDefinitionData, fixedVersion string, fixState string, osFamily string, sourceType string) error {
	now := time.Now()
	if sourceType == "" {
		sourceType = "usn"
	}
	if fixState == "" {
		fixState = "affected"
	}

	// Map OVAL severity to our severity
	severity := mapSeverity(def.Severity)

	// Generate vendor advisory link
	sourceLink := getVendorLink(osFamily, cveID)

	_, err := s.db.Exec(ctx, `
		INSERT INTO findings (
			server_id, cve_id, package_name, package_version, 
			fix_state, fixed_in, severity, summary, source_link, source_type,
			first_seen_at, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, $11, $11)
		ON CONFLICT (server_id, cve_id, package_name) 
		DO UPDATE SET
			package_version = EXCLUDED.package_version,
			fix_state = EXCLUDED.fix_state,
			fixed_in = EXCLUDED.fixed_in,
			severity = EXCLUDED.severity,
			source_link = EXCLUDED.source_link,
			source_type = EXCLUDED.source_type,
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = EXCLUDED.updated_at,
			resolved_at = NULL
		WHERE NOT (findings.source_type = 'usn' AND EXCLUDED.source_type = 'cve')
	`, serverID, cveID, pkg.Name, pkg.Version,
		fixState, fixedVersion, severity, def.Title, sourceLink, sourceType, now)

	return err
}

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
