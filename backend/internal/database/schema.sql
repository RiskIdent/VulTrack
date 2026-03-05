-- VulTrack Database Schema
-- This file contains the complete database schema for VulTrack
-- Run with: psql -f schema.sql or via database.go

-- ============================================================================
-- CORE TABLES (from original VulTrack)
-- ============================================================================

-- Servers table
CREATE TABLE IF NOT EXISTS servers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    os_family VARCHAR(50),
    os_release VARCHAR(50),
    os_codename VARCHAR(50),
    kernel VARCHAR(100),
    arch VARCHAR(20),
    package_manager VARCHAR(10),              -- 'dpkg' or 'rpm'
    ipv4_addrs TEXT[],
    last_scan_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    cve_id VARCHAR(30) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100),
    fix_state VARCHAR(20),
    fixed_in VARCHAR(100),
    cvss3_score DECIMAL(3,1),
    severity VARCHAR(20),
    summary TEXT,
    source_link TEXT,
    source_type VARCHAR(20),                    -- 'usn' or 'cve' (OVAL source); NULL = legacy
    first_seen_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL,
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(server_id, cve_id, package_name)
);

-- Assessments table
CREATE TABLE IF NOT EXISTS assessments (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) UNIQUE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    comment TEXT,
    ticket_url TEXT,
    assessed_by VARCHAR(255),
    assessed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Reason templates table
CREATE TABLE IF NOT EXISTS reason_templates (
    id SERIAL PRIMARY KEY,
    reason TEXT NOT NULL UNIQUE,
    applies_to VARCHAR(20) NOT NULL DEFAULT 'both',
    is_active BOOLEAN DEFAULT true,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT valid_applies_to CHECK (applies_to IN ('not_relevant', 'accepted_risk', 'both'))
);

-- Settings table (key-value store for app configuration)
CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Server groups table
CREATE TABLE IF NOT EXISTS server_groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    color VARCHAR(7) DEFAULT '#4ade80',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Server group members (many-to-many)
CREATE TABLE IF NOT EXISTS server_group_members (
    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    group_id INTEGER REFERENCES server_groups(id) ON DELETE CASCADE,
    added_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (server_id, group_id)
);

-- Users table (for future OIDC integration)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    is_admin BOOLEAN DEFAULT false,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ============================================================================
-- SERVER PACKAGES
-- ============================================================================

-- Server packages with soft-delete for history tracking
CREATE TABLE IF NOT EXISTS server_packages (
    id SERIAL PRIMARY KEY,
    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    previous_version VARCHAR(100),            -- For update tracking
    arch VARCHAR(20),
    source_package VARCHAR(255),              -- Source package (important for OVAL matching)
    first_seen_at TIMESTAMP NOT NULL,         -- When first seen
    last_seen_at TIMESTAMP NOT NULL,          -- Last report with this package
    removed_at TIMESTAMP,                     -- NULL = installed, otherwise = removed (soft-delete)
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(server_id, name, arch)
);

-- Index for active packages (most common query)
CREATE INDEX IF NOT EXISTS idx_server_packages_active 
    ON server_packages(server_id) WHERE removed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_server_packages_name 
    ON server_packages(name);

-- ============================================================================
-- AGENT AUTHENTICATION (NEW)
-- ============================================================================

-- Enrollment keys for automatic agent deployment
CREATE TABLE IF NOT EXISTS enrollment_keys (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,            -- SHA-256 hash of the key
    key_prefix VARCHAR(8) NOT NULL,           -- First 8 chars for identification
    is_active BOOLEAN DEFAULT true,
    auto_approve BOOLEAN DEFAULT true,        -- Automatically approve agents?
    usage_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

-- Registered agents with individual tokens
CREATE TABLE IF NOT EXISTS registered_agents (
    id SERIAL PRIMARY KEY,
    server_id INTEGER REFERENCES servers(id) ON DELETE SET NULL,
    hostname VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,          -- SHA-256 hash of the token
    token_prefix VARCHAR(8) NOT NULL,         -- First 8 chars for identification
    enrolled_via INTEGER REFERENCES enrollment_keys(id) ON DELETE SET NULL,
    status VARCHAR(20) DEFAULT 'pending',     -- pending, active, revoked
    last_seen_at TIMESTAMP,
    last_ip VARCHAR(45),
    agent_version VARCHAR(20),                -- Agent software version
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_registered_agents_token_prefix 
    ON registered_agents(token_prefix);

CREATE INDEX IF NOT EXISTS idx_registered_agents_status 
    ON registered_agents(status);

-- ============================================================================
-- OVAL DEFINITIONS (NEW)
-- ============================================================================

-- Known distributions with URL templates and available versions
CREATE TABLE IF NOT EXISTS oval_distributions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,         -- 'ubuntu', 'debian', 'rhel', etc.
    display_name VARCHAR(100) NOT NULL,       -- 'Ubuntu', 'Debian', etc.
    url_template TEXT NOT NULL,               -- USN / primary OVAL URL template
    url_template_cve TEXT,                    -- Optional CVE OVAL URL template (e.g. Ubuntu)
    package_manager VARCHAR(10) NOT NULL,     -- 'dpkg' or 'rpm'
    versions JSONB NOT NULL                   -- [{"version": "24.04", "codename": "noble", "lts": true}, ...]
);

-- User-enabled OVAL sources (per distribution + version + source_type)
CREATE TABLE IF NOT EXISTS oval_sources (
    id SERIAL PRIMARY KEY,
    distribution VARCHAR(50) NOT NULL,        -- 'ubuntu', 'debian', 'rhel', etc.
    version VARCHAR(20) NOT NULL,             -- '24.04', '12', '9', etc.
    source_type VARCHAR(20) NOT NULL DEFAULT 'usn',  -- 'usn' or 'cve'
    codename VARCHAR(50),                     -- 'noble', 'bookworm', etc.
    url TEXT NOT NULL,                        -- Generated URL from template
    package_manager VARCHAR(10) NOT NULL,     -- 'dpkg' or 'rpm'
    is_enabled BOOLEAN DEFAULT true,
    last_sync_at TIMESTAMP,
    definition_count INTEGER DEFAULT 0,
    sync_status VARCHAR(20),                  -- 'pending', 'syncing', 'success', 'error'
    sync_error TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(distribution, version, source_type)
);

-- OVAL definitions
CREATE TABLE IF NOT EXISTS oval_definitions (
    id SERIAL PRIMARY KEY,
    source_id INTEGER REFERENCES oval_sources(id) ON DELETE CASCADE,
    oval_id VARCHAR(255) NOT NULL,            -- e.g., 'oval:com.ubuntu.noble:def:100' (CVE OVAL uses longer IDs)
    class VARCHAR(20) NOT NULL,               -- 'vulnerability', 'patch', etc.
    title TEXT,
    description TEXT,
    severity VARCHAR(20),
    cve_ids TEXT[],                           -- Array of CVE IDs referenced
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(source_id, oval_id)
);

CREATE INDEX IF NOT EXISTS idx_oval_definitions_cve_ids 
    ON oval_definitions USING GIN(cve_ids);

-- OVAL criteria (tree structure)
CREATE TABLE IF NOT EXISTS oval_criteria (
    id SERIAL PRIMARY KEY,
    definition_id INTEGER REFERENCES oval_definitions(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES oval_criteria(id) ON DELETE CASCADE,
    operator VARCHAR(10),                     -- 'AND', 'OR'
    negate BOOLEAN DEFAULT false,
    comment TEXT
);

-- OVAL tests
CREATE TABLE IF NOT EXISTS oval_tests (
    id SERIAL PRIMARY KEY,
    source_id INTEGER REFERENCES oval_sources(id) ON DELETE CASCADE,
    oval_id VARCHAR(255) NOT NULL,            -- e.g., 'oval:com.ubuntu.noble:tst:100' (CVE OVAL uses longer IDs)
    test_type VARCHAR(50) NOT NULL,           -- 'dpkginfo_test', 'rpminfo_test', etc.
    object_id INTEGER,                        -- References oval_objects
    state_id INTEGER,                         -- References oval_states
    comment TEXT,
    UNIQUE(source_id, oval_id)
);

-- OVAL objects (package name patterns)
CREATE TABLE IF NOT EXISTS oval_objects (
    id SERIAL PRIMARY KEY,
    source_id INTEGER REFERENCES oval_sources(id) ON DELETE CASCADE,
    oval_id VARCHAR(255) NOT NULL,            -- e.g., 'oval:com.ubuntu.noble:obj:100' (CVE OVAL uses longer IDs with pkg name)
    object_type VARCHAR(50) NOT NULL,         -- 'dpkginfo_object', 'rpminfo_object', etc.
    name VARCHAR(255),                        -- Package name or pattern
    UNIQUE(source_id, oval_id)
);

-- OVAL states (version comparisons)
CREATE TABLE IF NOT EXISTS oval_states (
    id SERIAL PRIMARY KEY,
    source_id INTEGER REFERENCES oval_sources(id) ON DELETE CASCADE,
    oval_id VARCHAR(255) NOT NULL,            -- e.g., 'oval:com.ubuntu.noble:ste:100'
    state_type VARCHAR(50) NOT NULL,          -- 'dpkginfo_state', 'rpminfo_state', etc.
    evr_operation VARCHAR(20),                -- 'less than', 'less than or equal', etc.
    evr_value VARCHAR(100),                   -- Version to compare against
    UNIQUE(source_id, oval_id)
);

-- Link criteria to tests
CREATE TABLE IF NOT EXISTS oval_criteria_tests (
    criteria_id INTEGER REFERENCES oval_criteria(id) ON DELETE CASCADE,
    test_id INTEGER REFERENCES oval_tests(id) ON DELETE CASCADE,
    negate BOOLEAN DEFAULT false,
    PRIMARY KEY (criteria_id, test_id)
);

-- Link criteria to extended definitions (extend_definition elements)
CREATE TABLE IF NOT EXISTS oval_criteria_extend_definitions (
    id SERIAL PRIMARY KEY,
    criteria_id INTEGER REFERENCES oval_criteria(id) ON DELETE CASCADE,
    definition_oval_id VARCHAR(255) NOT NULL,  -- The referenced definition OVAL ID
    applicability_check BOOLEAN DEFAULT false,  -- If true, this is a pre-condition check
    negate BOOLEAN DEFAULT false,
    comment TEXT
);

-- ============================================================================
-- NVD CVE DATABASE (NEW)
-- ============================================================================

-- CVE catalog from NVD
CREATE TABLE IF NOT EXISTS cve_catalog (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) UNIQUE NOT NULL,       -- e.g., 'CVE-2024-1234'
    description TEXT,
    cvss2_score DECIMAL(3,1),
    cvss2_vector TEXT,
    cvss3_score DECIMAL(3,1),
    cvss3_vector TEXT,
    cvss3_severity VARCHAR(20),
    cwe_ids TEXT[],                           -- Array of CWE IDs
    published_at TIMESTAMP,
    modified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cve_catalog_cvss3 
    ON cve_catalog(cvss3_score DESC);

-- CVE references (URLs)
CREATE TABLE IF NOT EXISTS cve_references (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) REFERENCES cve_catalog(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source VARCHAR(100),
    tags TEXT[]
);

CREATE INDEX IF NOT EXISTS idx_cve_references_cve_id 
    ON cve_references(cve_id);

-- ============================================================================
-- EXPLOITDB (NEW)
-- ============================================================================

-- Exploits from ExploitDB
CREATE TABLE IF NOT EXISTS exploits (
    id SERIAL PRIMARY KEY,
    edb_id INTEGER UNIQUE NOT NULL,           -- ExploitDB ID
    cve_ids TEXT[],                           -- Array of related CVE IDs
    title TEXT,
    exploit_type VARCHAR(50),                 -- 'local', 'remote', 'webapps', etc.
    platform VARCHAR(50),                     -- 'linux', 'windows', 'multiple', etc.
    verified BOOLEAN DEFAULT false,
    published_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_exploits_cve_ids 
    ON exploits USING GIN(cve_ids);

-- ============================================================================
-- SYNC STATUS (NEW)
-- ============================================================================

-- Tracking for all sync jobs
CREATE TABLE IF NOT EXISTS sync_status (
    id SERIAL PRIMARY KEY,
    source_type VARCHAR(50) NOT NULL,         -- 'oval', 'nvd', 'exploitdb'
    source_name VARCHAR(100),                 -- e.g., 'ubuntu-24.04', 'nvd', 'exploitdb'
    last_sync_at TIMESTAMP,
    next_sync_at TIMESTAMP,
    status VARCHAR(20),                       -- 'idle', 'syncing', 'success', 'error'
    error_message TEXT,
    records_processed INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(source_type, source_name)
);

-- ============================================================================
-- INDEXES FOR EXISTING TABLES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_findings_server_id ON findings(server_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve_id ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_cvss3_score ON findings(cvss3_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_resolved ON findings(resolved_at) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- ============================================================================
-- MIGRATIONS (idempotent, for existing databases)
-- ============================================================================

-- Add url_template_cve to oval_distributions (CVE OVAL support)
ALTER TABLE oval_distributions ADD COLUMN IF NOT EXISTS url_template_cve TEXT;

-- Add source_type to oval_sources and update unique constraint (CVE OVAL support)
ALTER TABLE oval_sources ADD COLUMN IF NOT EXISTS source_type VARCHAR(20) NOT NULL DEFAULT 'usn';

-- Drop old unique constraint if present (pre-migration schema)
ALTER TABLE oval_sources DROP CONSTRAINT IF EXISTS oval_sources_distribution_version_key;

-- Add new unique constraint (idempotent)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'oval_sources_distribution_version_source_type_key'
  ) THEN
    ALTER TABLE oval_sources
    ADD CONSTRAINT oval_sources_distribution_version_source_type_key
    UNIQUE (distribution, version, source_type);
  END IF;
END $$;

-- Add source_type to findings (USN vs CVE; precedence: USN overwrites CVE, not vice versa)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS source_type VARCHAR(20);

-- Widen OVAL oval_id columns for CVE OVAL (long composite IDs with package names)
ALTER TABLE oval_definitions ALTER COLUMN oval_id TYPE VARCHAR(255);
ALTER TABLE oval_tests ALTER COLUMN oval_id TYPE VARCHAR(255);
ALTER TABLE oval_objects ALTER COLUMN oval_id TYPE VARCHAR(255);
ALTER TABLE oval_states ALTER COLUMN oval_id TYPE VARCHAR(255);
ALTER TABLE oval_criteria_extend_definitions ALTER COLUMN definition_oval_id TYPE VARCHAR(255);

-- ============================================================================
-- OIDC: extend users, add sessions
-- ============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer VARCHAR(500);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'users_oidc_issuer_subject_key'
  ) THEN
    ALTER TABLE users
    ADD CONSTRAINT users_oidc_issuer_subject_key
    UNIQUE (oidc_issuer, oidc_subject);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- ============================================================================
-- OVAL Scanner: add criterion comment to oval_criteria_tests for fix_state differentiation
-- ============================================================================

ALTER TABLE oval_criteria_tests ADD COLUMN IF NOT EXISTS comment TEXT DEFAULT '';

-- Add fix_state to findings to differentiate vendor statuses
-- Possible values: 'affected', 'fix_available', 'will_not_fix', 'deferred'
-- Update existing 'affected' rows: if they have a fixed_in version, they are 'fix_available'
DO $$
BEGIN
  -- Only run migration if fix_state column still has the old default
  IF EXISTS (
    SELECT 1 FROM findings WHERE fix_state = 'affected' AND fixed_in IS NOT NULL AND fixed_in != ''
  ) THEN
    UPDATE findings SET fix_state = 'fix_available' WHERE fix_state = 'affected' AND fixed_in IS NOT NULL AND fixed_in != '';
  END IF;
END $$;

-- ============================================================================
-- Report Schedules: recurring automated report generation & email delivery
-- ============================================================================

CREATE TABLE IF NOT EXISTS report_schedules (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,

    -- Schedule definition
    schedule_type   VARCHAR(20) NOT NULL,          -- 'weekly', 'monthly_dom', 'monthly_dow'
    interval_value  INT NOT NULL DEFAULT 1,        -- every N weeks/months
    day_of_week     INT,                           -- 0=Sun, 1=Mon, ..., 6=Sat
    week_of_month   INT,                           -- 1-5 (for monthly_dow, e.g. 2nd Tuesday)
    day_of_month    INT,                           -- 1-31 (for monthly_dom)
    time_hour       INT NOT NULL DEFAULT 8,
    time_minute     INT NOT NULL DEFAULT 0,
    timezone        VARCHAR(50) NOT NULL DEFAULT 'Europe/Berlin',

    -- Report scope
    server_ids      INT[] DEFAULT '{}',
    group_ids       INT[] DEFAULT '{}',

    -- Report period
    period_type     VARCHAR(20) NOT NULL DEFAULT 'last_month',  -- 'last_month', 'last_week', 'last_n_days'
    period_days     INT,                                        -- only for 'last_n_days'

    -- Report content options
    include_severity_chart BOOLEAN NOT NULL DEFAULT true,
    include_trend_chart    BOOLEAN NOT NULL DEFAULT true,
    include_top_cves       BOOLEAN NOT NULL DEFAULT true,
    include_full_cve_list  BOOLEAN NOT NULL DEFAULT false,

    -- Email recipients
    recipients      TEXT[] NOT NULL,

    -- Status
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMP,
    next_run_at     TIMESTAMP,
    last_error      TEXT,

    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- ============================================================================
-- SCAN JOBS
-- ============================================================================

CREATE TABLE IF NOT EXISTS scan_jobs (
    id              VARCHAR(36) PRIMARY KEY,
    server_id       BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    server_name     VARCHAR(255) NOT NULL DEFAULT '',
    trigger_type    VARCHAR(20) NOT NULL,         -- 'agent_report', 'manual', 'scheduled'
    status          VARCHAR(20) NOT NULL DEFAULT 'queued', -- 'queued', 'running', 'completed', 'failed', 'cancelled'
    retry_count     INT NOT NULL DEFAULT 0,
    max_retries     INT NOT NULL DEFAULT 3,
    error           TEXT,
    new_findings      INT,
    updated_findings  INT,
    resolved_findings INT,
    total_checks      INT,
    duration_ms       BIGINT,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMP,
    finished_at     TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_server_id ON scan_jobs(server_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at DESC);

-- ============================================================================
-- OVAL scan performance: indexes for criteria loading
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_oval_criteria_definition_id ON oval_criteria(definition_id);
CREATE INDEX IF NOT EXISTS idx_oval_criteria_parent_id ON oval_criteria(parent_id);
CREATE INDEX IF NOT EXISTS idx_oval_criteria_tests_criteria_id ON oval_criteria_tests(criteria_id);
CREATE INDEX IF NOT EXISTS idx_oval_criteria_tests_test_id ON oval_criteria_tests(test_id);
CREATE INDEX IF NOT EXISTS idx_oval_criteria_extend_defs_criteria_id ON oval_criteria_extend_definitions(criteria_id);
CREATE INDEX IF NOT EXISTS idx_oval_definitions_source_id ON oval_definitions(source_id);
CREATE INDEX IF NOT EXISTS idx_oval_definitions_oval_id_source ON oval_definitions(oval_id, source_id);
CREATE INDEX IF NOT EXISTS idx_oval_tests_source_id ON oval_tests(source_id);
CREATE INDEX IF NOT EXISTS idx_oval_objects_source_id ON oval_objects(source_id);
CREATE INDEX IF NOT EXISTS idx_oval_states_source_id ON oval_states(source_id);

-- ============================================================================
-- VEX (Vulnerability Exploitability eXchange) — Ubuntu/Canonical VEX data
-- ============================================================================

CREATE TABLE IF NOT EXISTS vex_statements (
    id              BIGSERIAL PRIMARY KEY,
    cve_id          VARCHAR(30)  NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    distro          VARCHAR(50)  NOT NULL,       -- Ubuntu codename, e.g. "focal", "jammy", "noble"
    status          VARCHAR(30)  NOT NULL,       -- 'fixed' | 'not_affected' | 'affected' | 'under_investigation'
    justification   TEXT,                        -- action_statement or status_notes from Canonical
    source_type     VARCHAR(5)   NOT NULL,       -- 'cve' | 'usn'
    source_id       VARCHAR(50)  NOT NULL,       -- e.g. 'CVE-2024-0046' or 'USN-2169-1'
    sync_generation INT          NOT NULL DEFAULT 0,
    UNIQUE (cve_id, package_name, distro, source_type)
);

CREATE INDEX IF NOT EXISTS idx_vex_lookup ON vex_statements (cve_id, package_name, distro);
CREATE INDEX IF NOT EXISTS idx_vex_generation ON vex_statements (sync_generation);

-- VEX enrichment columns on findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS vex_status VARCHAR(30);
    -- 'not_affected' | 'will_not_fix' | 'under_investigation' | NULL
ALTER TABLE findings ADD COLUMN IF NOT EXISTS vex_justification TEXT;
