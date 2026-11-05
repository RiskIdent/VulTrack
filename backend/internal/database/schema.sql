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
    -- BIGSERIAL, not SERIAL: an ON CONFLICT upsert consumes a sequence value on
    -- every call, including the ones that only update, so this sequence advances
    -- once per finding per scan rather than once per row. See the migration at
    -- the end of this file.
    id BIGSERIAL PRIMARY KEY,
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

-- AI assessments table (one advisory LLM assessment per CVE).
-- The row also acts as the work queue: status 'pending' rows are picked up by
-- the AI assessment worker. Results are advisory only and never auto-fill the
-- human assessment in the assessments table.
CREATE TABLE IF NOT EXISTS ai_assessments (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) UNIQUE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, processing, completed, failed
    attack_vector TEXT,                            -- how the attack works
    prerequisites TEXT,                            -- conditions required for the attack
    recommended_status VARCHAR(20),                -- relevant, not_relevant, accepted_risk
    recommendation_reasoning TEXT,                 -- why the model recommends that status
    confidence VARCHAR(10),                        -- low, medium, high
    model VARCHAR(60),                             -- model id that produced the result
    prompt_hash VARCHAR(64),                       -- hash of (system prompt + schema) used
    input_tokens INTEGER,                          -- token usage for cost tracking
    output_tokens INTEGER,
    error TEXT,                                    -- failure detail when status = 'failed'
    retry_count INTEGER NOT NULL DEFAULT 0,
    requested_by VARCHAR(255),                     -- user who triggered a (re-)run; NULL = reconciler
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT valid_ai_status CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
);
CREATE INDEX IF NOT EXISTS idx_ai_assessments_status ON ai_assessments(status);

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
    status VARCHAR(20) DEFAULT 'pending',     -- pending, active, revoked (by an admin), superseded (replaced by a forced re-enrollment)
    last_seen_at TIMESTAMP,
    last_ip VARCHAR(45),
    agent_version VARCHAR(20),                -- Agent software version
    last_auth_failure_at TIMESTAMP,           -- Last JWT auth failure timestamp
    auth_failure_ip VARCHAR(45),              -- IP that sent the invalid token
    created_at TIMESTAMP DEFAULT NOW()
);

-- Add auth failure columns to existing deployments
ALTER TABLE registered_agents ADD COLUMN IF NOT EXISTS last_auth_failure_at TIMESTAMP;
ALTER TABLE registered_agents ADD COLUMN IF NOT EXISTS auth_failure_ip VARCHAR(45);

CREATE INDEX IF NOT EXISTS idx_registered_agents_token_prefix 
    ON registered_agents(token_prefix);

CREATE INDEX IF NOT EXISTS idx_registered_agents_status 
    ON registered_agents(status);

CREATE INDEX IF NOT EXISTS idx_registered_agents_hostname
    ON registered_agents(hostname, created_at DESC);

-- One-time data migrations, recorded so they never run twice.
CREATE TABLE IF NOT EXISTS schema_migrations (
    name       VARCHAR(100) PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Forced re-enrollments used to mark the replaced registration 'revoked',
-- exactly like an admin revocation. They are now 'superseded'. Existing rows:
-- a revoked registration for which a newer one of the same host exists was
-- replaced; any other revoked registration was revoked by an admin. Runs once,
-- because after it an admin-revoked row can legitimately have newer rows.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE name = '2026-11-agents-superseded') THEN
    UPDATE registered_agents ra
    SET status = 'superseded'
    WHERE ra.status = 'revoked'
      AND EXISTS (SELECT 1 FROM registered_agents n
                  WHERE n.hostname = ra.hostname AND n.created_at > ra.created_at);
    INSERT INTO schema_migrations (name) VALUES ('2026-11-agents-superseded');
  END IF;
END $$;

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
    object_ref VARCHAR(255),                  -- oval_id of the referenced oval_objects row
    state_ref VARCHAR(255),                   -- oval_id of the referenced oval_states row
    comment TEXT,
    UNIQUE(source_id, oval_id)
);

-- OVAL objects (package name patterns)
CREATE TABLE IF NOT EXISTS oval_objects (
    id SERIAL PRIMARY KEY,
    source_id INTEGER REFERENCES oval_sources(id) ON DELETE CASCADE,
    oval_id VARCHAR(255) NOT NULL,            -- e.g., 'oval:com.ubuntu.noble:obj:100'
    object_type VARCHAR(50) NOT NULL,         -- 'dpkginfo_object', 'rpminfo_object', etc.
    name VARCHAR(255),                        -- First package name (for single-name display)
    names TEXT[],                             -- All package names the object matches
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
-- THREAT INTELLIGENCE: CISA KEV and FIRST EPSS
-- ============================================================================

-- CISA Known Exploited Vulnerabilities catalog. Synced daily in full; CVEs that
-- leave the catalog are deleted. See docs/AUTO_ASSESSMENT_PLAN.md.
CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id               VARCHAR(30) PRIMARY KEY,
    vendor_project       TEXT,
    product              TEXT,
    vulnerability_name   TEXT,
    date_added           DATE,
    due_date             DATE,
    known_ransomware_use BOOLEAN NOT NULL DEFAULT false,
    notes                TEXT,
    updated_at           TIMESTAMP NOT NULL DEFAULT NOW()
);

-- FIRST EPSS scores: probability of exploitation activity in the next 30 days
-- and its percentile. Replaced in full once a day (TRUNCATE + COPY), which
-- leaves no dead tuples behind, unlike an upsert of ~400,000 rows.
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id     VARCHAR(30) PRIMARY KEY,
    epss       NUMERIC(6,5) NOT NULL,
    percentile NUMERIC(6,5) NOT NULL,
    score_date DATE NOT NULL
);

-- ============================================================================
-- AUTOMATED ASSESSMENT (docs/AUTO_ASSESSMENT_PLAN.md)
-- ============================================================================

-- Current automated decision per (server, CVE). A row exists only when every
-- active finding of the CVE on the server is dismissed by a rule. Whether a row
-- takes effect is decided when it is read: the global mode and each rule's mode
-- live in settings, and any guard blocks it. Rows are rewritten only when the
-- computed decision changes.
CREATE TABLE IF NOT EXISTS auto_decisions (
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    cve_id     VARCHAR(30) NOT NULL,
    verdict    VARCHAR(20) NOT NULL DEFAULT 'not_relevant',
    source     VARCHAR(10) NOT NULL DEFAULT 'rule',    -- 'rule' (later also 'ai')
    rule_ids   TEXT[] NOT NULL,                        -- every rule that dismissed one of the findings
    guards     TEXT[] NOT NULL DEFAULT '{}',           -- guards that block the decision; empty = not blocked
    reason     TEXT NOT NULL,
    evidence   JSONB NOT NULL DEFAULT '{}',            -- per package: rule, version, detail; guard details
    decided_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_id, cve_id),
    CONSTRAINT valid_auto_verdict CHECK (verdict IN ('not_relevant'))
);
CREATE INDEX IF NOT EXISTS idx_auto_decisions_cve ON auto_decisions(cve_id);

-- Append-only audit trail of automated decisions and per-server human
-- decisions. Written only when something changes.
CREATE TABLE IF NOT EXISTS decision_events (
    id         BIGSERIAL PRIMARY KEY,
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    cve_id     VARCHAR(30) NOT NULL,
    event      VARCHAR(30) NOT NULL,  -- auto_created, auto_changed, auto_revoked, override_set, override_removed
    verdict    VARCHAR(20),
    rule_ids   TEXT[],
    guards     TEXT[],
    reason     TEXT,
    evidence   JSONB,
    actor      VARCHAR(255),          -- user for human events; NULL for automation
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_decision_events_pair ON decision_events(server_id, cve_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_decision_events_created ON decision_events(created_at);

-- A human decision for one server, which overrides automation and the CVE's
-- assessment for that server. 'manual' switches automation off for the pair
-- without deciding: the server stays open until a human assesses the CVE.
CREATE TABLE IF NOT EXISTS assessment_overrides (
    server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    cve_id      VARCHAR(30) NOT NULL,
    status      VARCHAR(20) NOT NULL,
    comment     TEXT,
    assessed_by VARCHAR(255),
    assessed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_id, cve_id),
    CONSTRAINT valid_override_status CHECK (status IN ('relevant', 'not_relevant', 'accepted_risk', 'manual'))
);
CREATE INDEX IF NOT EXISTS idx_assessment_overrides_cve ON assessment_overrides(cve_id);

-- A CVE assessment marked binding applies to every server, and automation never
-- overrides it.
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS binding_all_servers BOOLEAN NOT NULL DEFAULT false;

-- ============================================================================
-- RUNTIME FACTS FROM THE AGENT (docs/AUTO_ASSESSMENT_PLAN.md §6)
-- ============================================================================

-- Content-addressed snapshots of one fact category; one row per distinct
-- content, shared by every server and every point in time that had it.
CREATE TABLE IF NOT EXISTS fact_snapshots (
    hash       VARCHAR(64) PRIMARY KEY,     -- sha256 of the canonical JSON
    category   VARCHAR(30) NOT NULL,
    data       JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- The current facts of each server, per category. A category the agent did
-- not report has no row: it is unknown, and rules never rely on it.
CREATE TABLE IF NOT EXISTS server_facts (
    server_id    INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    category     VARCHAR(30) NOT NULL,     -- kernel, listeners, packagesInUse, services, virtualization
    hash         VARCHAR(64) NOT NULL REFERENCES fact_snapshots(hash),
    truncated    BOOLEAN NOT NULL DEFAULT false, -- the agent cut the list at its size limit
    stable_since TIMESTAMP NOT NULL,       -- when the content last changed
    reported_at  TIMESTAMP NOT NULL,       -- last report that carried it
    PRIMARY KEY (server_id, category)
);

-- Per server: what the last report said about the collection itself.
CREATE TABLE IF NOT EXISTS server_runtime (
    server_id      INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    schema_version INTEGER,
    collected_at   TIMESTAMP,
    errors         JSONB NOT NULL DEFAULT '[]',  -- [{collector, error}]
    truncated      TEXT[] NOT NULL DEFAULT '{}',
    reported_at    TIMESTAMP NOT NULL
);

-- Kernel module index (available and built-in module paths) per kernel
-- release; shared by every server running that kernel build.
CREATE TABLE IF NOT EXISTS kernel_module_index (
    kernel_release VARCHAR(100) NOT NULL,
    hash           VARCHAR(80) NOT NULL,   -- "sha256:…" as computed by the agent
    available      TEXT[] NOT NULL,
    builtin        TEXT[] NOT NULL,
    received_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kernel_release, hash)
);

-- When each package was last seen in use on a server (packagesInUse: mapped
-- by a process, also in a replaced version). Rows exist only for packages seen
-- in use at least once.
CREATE TABLE IF NOT EXISTS package_usage (
    server_id      INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    package        VARCHAR(255) NOT NULL,
    first_in_use_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_in_use_at TIMESTAMP NOT NULL,
    PRIMARY KEY (server_id, package)
);

-- Since when package usage has been observed on a server without a gap: every
-- report carried complete packagesInUse and no two were more than six hours
-- apart. A report without it, or with it truncated, ends the observation.
CREATE TABLE IF NOT EXISTS package_usage_observation (
    server_id        INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    observed_since   TIMESTAMP,          -- NULL: not observed at the moment
    last_observed_at TIMESTAMP
);

-- ============================================================================
-- AI PRECONDITION ANALYSIS (docs/AUTO_ASSESSMENT_PLAN.md §8)
-- ============================================================================

-- The current analysis per CVE. It is redone when the CVE data (input_hash),
-- the prompt or the model (prompt_hash) changes.
CREATE TABLE IF NOT EXISTS precondition_analyses (
    cve_id        VARCHAR(30) PRIMARY KEY,
    status        VARCHAR(20) NOT NULL,   -- pending (in a batch), ok, error
    model         VARCHAR(60) NOT NULL,
    prompt_hash   VARCHAR(64) NOT NULL,
    input_hash    VARCHAR(64) NOT NULL,
    batch_id      VARCHAR(100),
    determinable  BOOLEAN,
    result        JSONB,                  -- paths, reasoning, recommendation
    error         TEXT,
    terminal      BOOLEAN NOT NULL DEFAULT false, -- retrying will not help
    refused_by    VARCHAR(60),            -- the main model declined; set on its refusal and on the fallback's result
    requested_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    analysed_at   TIMESTAMP
);
ALTER TABLE precondition_analyses ADD COLUMN IF NOT EXISTS refused_by VARCHAR(60);
CREATE INDEX IF NOT EXISTS idx_precondition_analyses_batch ON precondition_analyses(batch_id) WHERE batch_id IS NOT NULL;

-- Message Batches submitted for the analysis.
CREATE TABLE IF NOT EXISTS precondition_batches (
    id            VARCHAR(100) PRIMARY KEY,
    model         VARCHAR(60) NOT NULL,
    requests      INTEGER NOT NULL,
    status        VARCHAR(20) NOT NULL,   -- in_progress, ended
    created_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    ended_at      TIMESTAMP
);

-- Every model call that cost money, for the budget and statistics.
CREATE TABLE IF NOT EXISTS ai_usage (
    id                    BIGSERIAL PRIMARY KEY,
    stage                 VARCHAR(30) NOT NULL,   -- preconditions
    model                 VARCHAR(60) NOT NULL,
    cve_id                VARCHAR(30),
    batch                 BOOLEAN NOT NULL DEFAULT false,
    input_tokens          BIGINT NOT NULL DEFAULT 0,
    output_tokens         BIGINT NOT NULL DEFAULT 0,
    cache_read_tokens     BIGINT NOT NULL DEFAULT 0,
    cache_creation_tokens BIGINT NOT NULL DEFAULT 0,
    cost_usd              NUMERIC(12,6) NOT NULL DEFAULT 0,
    created_at            TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_usage_stage_time ON ai_usage(stage, created_at);

-- ============================================================================
-- KERNEL CODE MAP FOR R-KMOD (docs/AUTO_ASSESSMENT_PLAN.md §7)
-- ============================================================================

-- Source files a kernel CVE affects, from its CVE record
-- (containers.cna.affected[].programFiles; filled by the Linux kernel CNA).
CREATE TABLE IF NOT EXISTS kernel_cve_files (
    cve_id        VARCHAR(30) PRIMARY KEY,
    status        VARCHAR(20) NOT NULL,      -- ok, no_files, not_found, error
    assigner      VARCHAR(60),
    program_files TEXT[] NOT NULL DEFAULT '{}',
    error         TEXT,
    fetched_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- One kernel build (uname -r + package version + architecture) whose Kbuild
-- makefiles and .config were read from Ubuntu's linux-headers packages.
CREATE TABLE IF NOT EXISTS kernel_builds (
    id               SERIAL PRIMARY KEY,
    release          VARCHAR(100) NOT NULL,  -- uname -r, e.g. 6.8.0-147-generic
    version          VARCHAR(100) NOT NULL,  -- package version, e.g. 6.8.0-147.147
    arch             VARCHAR(20) NOT NULL,   -- Debian architecture, e.g. amd64
    status           VARCHAR(20) NOT NULL,   -- ok, error
    error            TEXT,
    headers_package  VARCHAR(150),
    source_files     INTEGER NOT NULL DEFAULT 0,
    modules_verified BOOLEAN NOT NULL DEFAULT false, -- module packages were listed
    shipped_modules  INTEGER NOT NULL DEFAULT 0,
    built_at         TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at     TIMESTAMP,              -- last daily check that found a server running it
    UNIQUE (release, version, arch)
);
ALTER TABLE kernel_builds ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP;

-- How each source file is built in a kernel build: built in, as a module, or
-- not at all (see internal/kernelintel).
CREATE TABLE IF NOT EXISTS kernel_source_files (
    build_id INTEGER NOT NULL REFERENCES kernel_builds(id) ON DELETE CASCADE,
    path     TEXT NOT NULL,
    targets  JSONB NOT NULL,
    PRIMARY KEY (build_id, path)
);

-- ============================================================================
-- SYNC STATUS (NEW)
-- ============================================================================

-- Tracking for all sync jobs.
-- last_sync_at: timestamp of the last *successful* sync (used by Prometheus and the UI status APIs).
-- synced_until: resume cursor for chunked/incremental syncers (NVD). Updated continuously during a
--               sync and on success advanced to NOW(); always >= last_sync_at.
CREATE TABLE IF NOT EXISTS sync_status (
    id SERIAL PRIMARY KEY,
    source_type VARCHAR(50) NOT NULL,         -- 'oval', 'nvd', 'exploitdb'
    source_name VARCHAR(100),                 -- e.g., 'ubuntu-24.04', 'nvd', 'exploitdb'
    last_sync_at TIMESTAMP,
    synced_until TIMESTAMP,
    next_sync_at TIMESTAMP,
    status VARCHAR(20),                       -- 'idle', 'syncing', 'success', 'error'
    error_message TEXT,
    records_processed INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(source_type, source_name)
);

-- Add synced_until on existing deployments and seed it from last_sync_at so the
-- next NVD run resumes from where it left off (the old code stored the resume
-- point in last_sync_at).
ALTER TABLE sync_status ADD COLUMN IF NOT EXISTS synced_until TIMESTAMP;
UPDATE sync_status
   SET synced_until = last_sync_at
 WHERE source_type = 'nvd' AND synced_until IS NULL;

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
    include_auto_assessments BOOLEAN NOT NULL DEFAULT false,

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
ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS include_auto_assessments BOOLEAN NOT NULL DEFAULT false;


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
    cve_id          VARCHAR(50)  NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    distro          VARCHAR(50)  NOT NULL,       -- Ubuntu codename, e.g. "focal", "jammy", "noble"
    status          VARCHAR(30)  NOT NULL,       -- 'fixed' | 'not_affected' | 'affected' | 'under_investigation'
    justification   TEXT,                        -- action_statement or status_notes from Canonical
    source_type     VARCHAR(5)   NOT NULL,       -- 'cve' | 'usn'
    source_id       TEXT         NOT NULL,        -- e.g. 'CVE-2024-0046' or 'USN-2169-1'
    sync_generation INT          NOT NULL DEFAULT 0,
    UNIQUE (cve_id, package_name, distro, source_type)
);

-- Widen columns on existing deployments (no-op on fresh installs).
ALTER TABLE vex_statements ALTER COLUMN cve_id TYPE VARCHAR(50);
ALTER TABLE vex_statements ALTER COLUMN source_id TYPE TEXT;

CREATE INDEX IF NOT EXISTS idx_vex_lookup ON vex_statements (cve_id, package_name, distro);
CREATE INDEX IF NOT EXISTS idx_vex_generation ON vex_statements (sync_generation);

-- VEX enrichment columns on findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS vex_status VARCHAR(30);
    -- 'not_affected' | 'will_not_fix' | 'under_investigation' | NULL
ALTER TABLE findings ADD COLUMN IF NOT EXISTS vex_justification TEXT;

-- ============================================================================
-- AGENT V2: refresh tokens (long-lived, rotated on use)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_refresh_tokens (
    id           SERIAL PRIMARY KEY,
    agent_id     INTEGER NOT NULL REFERENCES registered_agents(id) ON DELETE CASCADE,
    token_hash   VARCHAR(64) NOT NULL,   -- SHA-256 hash of the full token
    token_prefix VARCHAR(8)  NOT NULL,   -- first 8 hex chars for identification
    expires_at   TIMESTAMP   NOT NULL,
    created_at   TIMESTAMP   DEFAULT NOW(),
    last_used_at TIMESTAMP,
    revoked_at   TIMESTAMP               -- NULL = active
);

CREATE INDEX IF NOT EXISTS idx_agent_refresh_tokens_agent_id
    ON agent_refresh_tokens(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_refresh_tokens_expires_at
    ON agent_refresh_tokens(expires_at);

-- ============================================================================
-- API TOKENS: machine credentials for the MCP interface (admin-managed)
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_tokens (
    id           SERIAL PRIMARY KEY,
    description  VARCHAR(255) NOT NULL,     -- what the token is used for
    token_hash   VARCHAR(64)  NOT NULL,     -- SHA-256 hash of the full token
    token_prefix VARCHAR(8)   NOT NULL,     -- first 8 hex chars for identification
    is_read_only BOOLEAN      DEFAULT false,
    is_active    BOOLEAN      DEFAULT true,
    created_by   INTEGER      REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMP    DEFAULT NOW(),
    last_used_at TIMESTAMP,
    expires_at   TIMESTAMP                  -- NULL = never expires
);

-- token_hash is the authentication lookup key; enforce uniqueness so a hash can
-- never map to two tokens and duplicate inserts are rejected at the DB layer.
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_token_hash
    ON api_tokens(token_hash);

-- ============================================================================
-- OVAL: store the real test -> object / test -> state references
-- ============================================================================
-- Tests used to be linked to their object and state by guessing that all three
-- OVAL IDs share the same numeric suffix (oval:ns:tst:123 -> oval:ns:obj:123).
-- Canonical reuses objects and states across tests, so that guess silently
-- dropped 660/1162 (USN) and 965/3391 (CVE) package tests in the Ubuntu 24.04
-- feeds and stripped the version comparison off others. The refs are now stored
-- verbatim and joined on.
--
-- oval_objects.names holds every binary package a dpkginfo/rpminfo object
-- expands to (previously encoded as one row per name with a synthetic
-- "oval:ns:obj:123:pkgname" ID, which broke the object_ref equality join).

ALTER TABLE oval_objects ADD COLUMN IF NOT EXISTS names TEXT[];
ALTER TABLE oval_tests   ADD COLUMN IF NOT EXISTS state_ref VARCHAR(255);

-- object_id/state_id were meant to hold the resolved links but were never
-- populated, which is what made the ID-suffix guess necessary in the first place.
ALTER TABLE oval_tests DROP COLUMN IF EXISTS object_id;
ALTER TABLE oval_tests DROP COLUMN IF EXISTS state_id;

DO $$
BEGIN
  -- object_ref is the sentinel for this migration: stored OVAL data predates the
  -- reference columns and cannot be repaired in place, so drop it and let the
  -- syncer re-import every enabled source (last_sync_at = NULL forces a sync).
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'oval_tests'
      AND column_name = 'object_ref'
  ) THEN
    ALTER TABLE oval_tests ADD COLUMN object_ref VARCHAR(255);

    TRUNCATE oval_definitions, oval_tests, oval_objects, oval_states CASCADE;

    UPDATE oval_sources
    SET last_sync_at = NULL, sync_status = 'pending', definition_count = 0, sync_error = NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_oval_tests_object_ref ON oval_tests(source_id, object_ref);
CREATE INDEX IF NOT EXISTS idx_oval_tests_state_ref ON oval_tests(source_id, state_ref);
CREATE INDEX IF NOT EXISTS idx_oval_tests_source_type ON oval_tests(source_id, test_type);
CREATE INDEX IF NOT EXISTS idx_oval_objects_names ON oval_objects USING GIN(names);

-- ============================================================================
-- Ubuntu package vulnerability feed (OVAL source_type 'pkg')
-- ============================================================================
-- Canonical publishes com.ubuntu.<series>.pkg.json.xz next to the OVAL files.
-- It is what `pro cves` evaluates: a complete source -> binary -> version matrix
-- plus a per-source-package CVE status. It closes two gaps in the OVAL feeds:
-- binary packages that OVAL's constant_variables do not enumerate, and CVSS
-- scores, Canonical triage notes and mitigations that VulTrack otherwise has to
-- source from NVD (rate-limited) or does not have at all.
--
-- The feed is optional: a distribution without url_template_pkg never gets a
-- 'pkg' source, and a source whose feed is missing simply fails its own sync.

ALTER TABLE oval_distributions ADD COLUMN IF NOT EXISTS url_template_pkg TEXT;

-- Pocket a fix comes from ('security', 'updates', 'esm-infra', 'esm-apps', ...).
-- An esm-* pocket means the fix needs an Ubuntu Pro subscription.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fix_pocket VARCHAR(30);

-- Source packages of the feed. is_kernel marks the 53 kernel source packages,
-- which are excluded from detection: they carry 95% of the feed's CVE statuses,
-- and OVAL already covers the kernel through uname tests against the RUNNING
-- kernel, which is both more accurate and far less noisy than reporting every
-- installed kernel's binary packages. Their metadata is still imported, because
-- the OVAL kernel findings benefit from it.
CREATE TABLE IF NOT EXISTS pkg_source_packages (
    id        BIGSERIAL PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES oval_sources(id) ON DELETE CASCADE,
    name      VARCHAR(255) NOT NULL,
    is_kernel BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (source_id, name)
);

-- source_version -> binary package versions. Needed because a CVE is fixed in a
-- SOURCE version while a server reports installed BINARY versions.
CREATE TABLE IF NOT EXISTS pkg_binary_versions (
    id             BIGSERIAL PRIMARY KEY,
    source_id      INTEGER NOT NULL REFERENCES oval_sources(id) ON DELETE CASCADE,
    source_package VARCHAR(255) NOT NULL,
    source_version VARCHAR(255) NOT NULL,
    binary_package VARCHAR(255) NOT NULL,
    binary_version VARCHAR(255) NOT NULL,
    pocket         VARCHAR(30),
    UNIQUE (source_id, source_package, source_version, binary_package)
);

CREATE INDEX IF NOT EXISTS idx_pkg_binary_versions_binary
    ON pkg_binary_versions(source_id, binary_package);

-- Per source package, the status Canonical tracks for a CVE. 'not-vulnerable'
-- rows are not imported: they are 56% of the feed and can never yield a finding.
CREATE TABLE IF NOT EXISTS pkg_cve_status (
    id                   BIGSERIAL PRIMARY KEY,
    source_id            INTEGER NOT NULL REFERENCES oval_sources(id) ON DELETE CASCADE,
    source_package       VARCHAR(255) NOT NULL,
    cve_id               VARCHAR(30) NOT NULL,
    status               VARCHAR(20) NOT NULL,   -- 'vulnerable' | 'fixed'
    source_fixed_version VARCHAR(255),            -- set iff status = 'fixed'
    UNIQUE (source_id, source_package, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_pkg_cve_status_source_package
    ON pkg_cve_status(source_id, source_package);

-- Per-CVE metadata from the feed, for every CVE the feed knows about.
CREATE TABLE IF NOT EXISTS pkg_cve_metadata (
    id              BIGSERIAL PRIMARY KEY,
    source_id       INTEGER NOT NULL REFERENCES oval_sources(id) ON DELETE CASCADE,
    cve_id          VARCHAR(30) NOT NULL,
    ubuntu_priority VARCHAR(20),
    cvss_score      DECIMAL(3,1),
    cvss_severity   VARCHAR(20),
    description     TEXT,
    notes           TEXT[],
    mitigation      TEXT,
    published_at    TIMESTAMP,
    UNIQUE (source_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_pkg_cve_metadata_cve ON pkg_cve_metadata(cve_id);

-- Finding precedence. A USN advisory is the most specific statement Ubuntu
-- makes about a package; the per-CVE OVAL adds the vendor's triage state
-- (will_not_fix, deferred); the package feed only distinguishes vulnerable from
-- fixed. A weaker source must therefore never overwrite what a stronger one
-- determined. This is the single definition of that order.
CREATE OR REPLACE FUNCTION finding_source_rank(p_source_type TEXT) RETURNS INT
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $fn$
    SELECT CASE p_source_type
        WHEN 'usn' THEN 3
        WHEN 'cve' THEN 2
        WHEN 'pkg' THEN 1
        ELSE 0
    END
$fn$;

-- ============================================================================
-- findings.id: widen to 64 bit
-- ============================================================================
-- INSERT ... ON CONFLICT DO UPDATE evaluates the column default before it
-- detects the conflict, so every upsert consumes a sequence value even when it
-- only updates an existing row. The scanner upserts every finding of every
-- server on every scan, which advanced findings_id_seq by thousands per scan
-- while the row count barely moved — roughly three orders of magnitude faster
-- than the table grew.
--
-- On a production instance the 32-bit sequence hit its ceiling after a few
-- months. From that point *no* finding could be written at all, not just new
-- ones, and the resulting per-row error log filled the disk.
--
-- The rewrite takes an ACCESS EXCLUSIVE lock, so it is guarded to run only
-- while the column is still 32 bit.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'findings'
      AND column_name = 'id'
      AND data_type = 'integer'
  ) THEN
    RAISE NOTICE 'Widening findings.id to bigint; this rewrites the table';
    ALTER TABLE findings ALTER COLUMN id TYPE bigint;
  END IF;
END $$;

-- Cheap metadata change, and it must also run when the column was already
-- widened by hand during an incident.
ALTER SEQUENCE IF EXISTS findings_id_seq AS bigint MAXVALUE 9223372036854775807;
