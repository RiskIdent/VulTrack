-- VulTrack Seed Data
-- This file contains default data for VulTrack
-- All inserts use ON CONFLICT DO NOTHING to be idempotent

-- ============================================================================
-- OVAL DISTRIBUTIONS (Ubuntu only)
-- ============================================================================

INSERT INTO oval_distributions (name, display_name, url_template, url_template_cve, url_template_pkg, package_manager, versions) VALUES
('ubuntu', 'Ubuntu',
 'https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.usn.oval.xml.bz2',
 'https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.cve.oval.xml.bz2',
 'https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.pkg.json.xz',
 'dpkg',
 '[
   {"version": "20.04", "codename": "focal", "lts": true},
   {"version": "22.04", "codename": "jammy", "lts": true},
   {"version": "24.04", "codename": "noble", "lts": true},
   {"version": "26.04", "codename": "resolute", "lts": true}
 ]'::jsonb)

ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    url_template = EXCLUDED.url_template,
    url_template_cve = EXCLUDED.url_template_cve,
    url_template_pkg = EXCLUDED.url_template_pkg,
    package_manager = EXCLUDED.package_manager,
    versions = EXCLUDED.versions;

-- ============================================================================
-- DEFAULT SETTINGS
-- ============================================================================

INSERT INTO settings (key, value, description) VALUES 
    -- Triage settings
    ('triage_filter_mode', 'cvss', 'Filter mode for triage queue: cvss or vendor_severity'),
    ('triage_cvss_threshold', '7.0', 'Minimum CVSS score for findings to appear in triage queue'),
    ('triage_vendor_severities', 'critical,high', 'Comma-separated vendor severity levels for triage queue'),
    ('triage_include_unrated', 'false', 'Include findings without vendor severity in triage queue'),
    ('triage_hide_vex_not_affected', 'true', 'Hide findings where VEX status is not_affected from the triage queue'),
    
    -- Sync intervals
    ('oval_sync_interval_hours', '24', 'Hours between OVAL feed syncs'),
    ('nvd_sync_interval_hours', '6', 'Hours between NVD CVE database syncs'),
    ('exploitdb_sync_interval_hours', '24', 'Hours between ExploitDB syncs'),
    ('vex_sync_interval_hours', '24', 'Hours between Ubuntu VEX data syncs'),

    -- VEX settings
    ('vex_download_url', 'https://security-metadata.canonical.com/vex/vex-all.tar.xz', 'Download URL for Ubuntu VEX archive'),
    
    -- Agent v2 token TTL settings
    ('agent_access_token_ttl_hours', '24', 'Validity of agent JWT access tokens in hours (v2 API)'),
    ('agent_refresh_token_ttl_days', '90', 'Validity of agent refresh tokens in days (v2 API)'),

    -- NVD settings
    ('nvd_api_key', '', 'NVD API key for faster syncs (optional)'),
    ('nvd_initial_sync_years', '5', 'Years of CVE history to load on initial sync'),
    
    -- Jira integration (kept for future use)
    ('jira_enabled', 'false', 'Enable Jira integration'),
    ('jira_url', '', 'Jira Cloud URL (e.g., https://company.atlassian.net)'),
    ('jira_api_token', '', 'Jira API token (encrypted)'),
    ('jira_user_email', '', 'Jira user email for API authentication'),
    ('jira_project_key', '', 'Default Jira project key for new tickets'),
    ('jira_issue_type', 'Task', 'Default issue type for new tickets')

ON CONFLICT (key) DO NOTHING;

-- ============================================================================
-- DEFAULT REASON TEMPLATES
-- ============================================================================

INSERT INTO reason_templates (reason, applies_to, sort_order) VALUES 
    ('Feature not enabled in our environment', 'not_relevant', 1),
    ('Affected component not installed', 'not_relevant', 2),
    ('Network not exposed / internal only', 'not_relevant', 3),
    ('Already mitigated by other controls', 'both', 4),
    ('False positive - package not vulnerable', 'not_relevant', 5),
    ('Low impact in our environment', 'accepted_risk', 6),
    ('Compensating controls in place', 'both', 7),
    ('Fix not available, monitoring for updates', 'accepted_risk', 8),
    ('End of life system, scheduled for decommission', 'accepted_risk', 9),
    ('Business critical, scheduled maintenance window', 'accepted_risk', 10)

ON CONFLICT (reason) DO NOTHING;
