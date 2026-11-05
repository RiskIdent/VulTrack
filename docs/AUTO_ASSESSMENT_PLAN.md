# Automated assessment

**Status:** agreed on 2026-11-05. Phases 1 (KEV and EPSS), 2 (decision model) and 3 (runtime facts, backend side) implemented; the agent side of phase 3 is specified in AGENT_RUNTIME_FACTS_PROMPT.md.
**Scope:** backend, frontend, agent (separate repository), MCP, reports.

## 1. Goal

The number of findings is too large to assess by hand. VulTrack should decide
automatically wherever a decision is unambiguous, and leave everything else to
a human. Every decision must be explainable after the fact.

Principles, agreed with the product owner:

1. **Deterministic rules first.** Only what the rules cannot decide goes to the AI.
2. **When in doubt, a human decides.** The AI may answer "cannot determine".
3. **Automation only ever sets `not_relevant`.** `relevant` and `accepted_risk`
   are set by humans only. The AI may *recommend* `relevant`; that recommendation
   is shown, never applied.
4. **Every decision is traceable.** A rule decision records the rule ID and
   version; an AI decision records the model's reasoning, model, prompt hash and
   the server facts it was checked against.
5. **Decisions follow the data.** When the facts behind a decision change, the
   decision is re-evaluated. A newly KEV-listed CVE reopens every automated
   dismissal.
6. **Humans always have the last word.** Automated decisions never overwrite a
   human one and can be discarded with one click.
7. **Everything is controllable and verifiable in the UI**: Admin, triage,
   statistics, metrics, reports and MCP.
8. **VulTrack stays fast.** 200 servers report hourly; an unchanged report must
   cost next to nothing.
9. **Rollback stays easy.** Every schema change is additive. Setting the
   automation to *off* restores today's behaviour exactly.

## 2. Terms

| Term | Meaning |
|---|---|
| Affected server | A server with an active (unresolved) finding for the CVE. |
| Decision | The verdict for one (server, CVE) pair: `not_relevant` or `open`. |
| Source | Who produced a decision: `rule`, `ai` or `human`. |
| Guard | A rule that *prevents* automated dismissal (e.g. KEV-listed). |
| Mode | Per rule, per AI stage and globally: `off`, `shadow` (computed and shown, never applied) or `active`. |
| Facts | Runtime data a server's agent reports (modules, listeners, …), see §6. |
| Precondition analysis | The AI's structured list of what an attack on a CVE needs, see §8. |

## 3. Decision cascade

Per (server, CVE), evaluated in this order; the first stage that yields a
result wins:

```
facts: agent runtime data, KEV, EPSS, VEX, ExploitDB, NVD
  1. guards         KEV-listed, verified public exploit, EPSS ≥ threshold
                    → no automated dismissal; only a human may dismiss
  2. rules          first matching rule decides (rule ID + version)
  3. AI             precondition analysis checked against the server's facts;
                    may answer "cannot determine"
  4. human          everything still open
```

### 3.1 From servers to the CVE

- The triage queue still lists CVEs. A CVE stays in the queue while at least one
  affected server is open; the triage view shows only the open servers.
- A **human assessment of a CVE** applies to every affected server without a
  decision of its own, including servers that report the CVE later (as today).
- **Conflict rule:** an unambiguous automated `not_relevant` for a server
  refines a human CVE assessment of `relevant`; the Jira ticket and the reports
  list only the servers the CVE is relevant on. A human who does not want that
  marks the assessment as **binding for all servers**; automation then never
  overrides it.
- A human may also decide for a single server (per-server override). That always
  wins over automation.

Effective status of one (server, CVE), highest precedence first:

1. human per-server override
2. human CVE assessment marked *binding for all servers*
3. automated decision in mode `active`
4. human CVE assessment
5. open

## 4. Data model (all additive)

```sql
-- Phase 1
kev_entries      (cve_id PK, vendor_project, product, vulnerability_name,
                  date_added, due_date, known_ransomware_use, notes, updated_at)
epss_scores      (cve_id PK, epss NUMERIC(6,5), percentile NUMERIC(6,5), score_date)

-- Phase 2
auto_decisions   (server_id, cve_id, verdict, source, rule_id, rule_version,
                  ai_analysis_id, reason, evidence JSONB, mode,
                  stable_since, decided_at, updated_at,
                  PRIMARY KEY (server_id, cve_id))
decision_events  (id BIGSERIAL, server_id, cve_id, event, old_verdict,
                  new_verdict, source, rule_id, rule_version, actor, reason, at)
                  -- append-only audit trail; written only on change
assessment_overrides (server_id, cve_id, status, comment, assessed_by,
                  assessed_at, PRIMARY KEY (server_id, cve_id))
assessments      + binding_all_servers BOOLEAN NOT NULL DEFAULT false
report_schedules + include_auto_assessments BOOLEAN NOT NULL DEFAULT false

-- Phase 3
server_facts     (server_id, category, hash, snapshot_hash, stable_since,
                  reported_at, PRIMARY KEY (server_id, category))
fact_snapshots   (hash PK, category, data JSONB, created_at)
                  -- content-addressed; one row per distinct content
kernel_module_index (kernel_release, hash, modules JSONB, builtin JSONB, received_at,
                  PRIMARY KEY (kernel_release, hash))

-- Phase 5
cve_precondition_analyses (id, cve_id, input_hash, prompt_hash, model, status,
                  determinable, paths JSONB, reasoning, confidence,
                  input_tokens, output_tokens, cache_read_tokens, batch_id,
                  created_at)
```

- **EPSS** is replaced in full once a day: `TRUNCATE` + `COPY` in one
  transaction. About 400,000 rows; this writes no dead tuples, unlike an upsert of
  every row.
- **KEV** is upserted (about 1,800 rows) and rows that left the catalog are
  deleted.
- **fact_snapshots** are referenced by hash from `server_facts` and from
  `auto_decisions.evidence`. Snapshots no longer referenced by either are removed
  by a daily cleanup job.
- `decision_events` is the audit trail; `auto_decisions` holds only the current
  state. A decision that does not change writes nothing.

## 5. Re-evaluation

Load: 200 servers × one report per hour ≈ 3–4 reports per minute. Almost all of
them carry unchanged facts.

1. **Per-category fingerprints.** On a report, the backend normalises (sorts)
   each fact category and hashes it. If every hash equals the stored one, only
   `reported_at` is updated. No re-evaluation, no snapshot write.
2. **Re-evaluate one server, after its scan.** The scan already runs after each
   report. When the server's findings or any fact hash changed, the rules are
   evaluated for that server only: a few thousand findings, in memory, in Go.
   Fine-grained "which rule depends on which fact" tracking is not worth its
   complexity at this cost.
3. **Write only what changed.** Decisions are compared with the stored state;
   only differences are written (`IS DISTINCT FROM`), each with a
   `decision_events` row.
4. **Global triggers are processed per CVE, in batches:** KEV/EPSS sync, a new
   rule version, a new precondition analysis. Only the affected CVEs are
   re-evaluated, across all servers.
5. **Asymmetric hysteresis.** A change that makes a server *more* exposed
   (a port opens, a module loads, a CVE enters KEV) revokes a dismissal
   immediately. A new dismissal needs the exonerating fact to be stable for two
   consecutive reports (`stable_since`). This stops flapping caused by
   short-lived processes without costing safety.
6. **The AI never runs per report.** See §8.

Before Phase 2 goes live, the evaluation of a server with ~13,000 findings and a
full global re-evaluation are benchmarked against a realistic data set, the
same way the VEX fix in v1.5.8 was.

## 6. Runtime facts from the agent

All optional, under a new `runtime` object in the report. The full specification
and the instructions for the agent's coding agent are in
[AGENT_RUNTIME_FACTS_PROMPT.md](AGENT_RUNTIME_FACTS_PROMPT.md).

| Category | Content | Used by |
|---|---|---|
| `kernel` | loaded modules (with path), module index (available + built-in, sent on change), blacklisted modules, `modules_disabled`, selected sysctls (user namespaces, BPF, ptrace), installed kernels, reboot required | R-KMOD, R-KRN-IDLE, preconditions |
| `listeners` | protocol, bind address, port, process, executable, owning package, systemd unit, network namespace | R-NET, preconditions |
| `packagesInUse` | per package: processes that map one of its files; processes still using a replaced (deleted) file | R-UNUSED, preconditions, "restart needed" display |
| `services` | systemd units with active and enabled state, owning package | preconditions |
| `virtualization` | `systemd-detect-virt` result | context |

Semantics that rules rely on: **a missing field means "not collected"
(unknown); an empty list means "collected, none".** A rule that needs a category
never fires when it is unknown.

Command lines and environment variables are **not** collected; they often contain
secrets.

## 7. Rule catalogue

Rules are Go code with an ID, a version, a description and tests. Each rule
declares the fact categories it reads. Changing a rule's logic means bumping its
version, which re-evaluates its decisions.

| ID | Phase | Condition | Verdict |
|---|---|---|---|
| G-KEV | 2 | CVE is in the CISA KEV catalog | guard |
| G-EXPLOIT | 2 | verified public exploit in ExploitDB | guard (configurable) |
| G-EPSS | 2 | EPSS ≥ threshold (default 0.10) | guard (configurable) |
| R-VEX | 2 | Canonical VEX says `not_affected` | not_relevant |
| R-HDR | 2 | package ships only kernel headers, kernel sources or documentation: `linux-libc-dev`, `linux-headers-*`, `linux-*-headers-*`, `linux-source-*`, `linux-doc`, `*-doc`; not `-dev` packages (static libraries end up in programs built on the host) | not_relevant |
| R-KMOD | 4 | kernel CVE whose affected code lies only in modules that are neither loaded nor built-in, **and** cannot be loaded (`modules_disabled=1`, blacklisted with `install … /bin/false`, or not present in the module index at all) | not_relevant |
| R-NET | 4 | network-only CVE (CVSS `AV:N`) in a package whose processes listen on loopback only, and the package has no other attack surface per its precondition analysis | open, with a hint to the AI stage |
| R-UNUSED | 4 | library CVE, package not mapped by any process, and the package ships no executables or services | candidate; enabled only after shadow evaluation shows it safe |

R-KRN-IDLE (a kernel package installed but not running) was dropped while
implementing phase 2: the scanner never reports findings for installed kernel
packages. Kernel findings belong to the pseudo-package `kernel` and always
describe the running kernel (OVAL matches `uname -r`), and the package feed
skips kernel source packages entirely.

"Module not loaded" alone never dismisses: the kernel autoloads many modules on
demand, some at the request of unprivileged users (e.g. network protocols). The
mapping from a kernel CVE to the source files it affects is to be verified in
Phase 4; the kernel CNA's CVE records are expected to list the affected program
files.

## 8. AI stages

| Stage | Purpose | Default model | Runs for |
|---|---|---|---|
| Advisory (exists) | explains attack vector and prerequisites, recommends a status; advisory only | `claude-haiku-5-5` (default since 2026-11-05; was `claude-haiku-4-5`, ~10× more expensive) | every CVE in the triage queue |
| Precondition analysis (new) | structured preconditions per CVE; the system checks them per server | `claude-sonnet-5-5`; `claude-opus-5-5` selectable and as optional escalation | only CVEs no rule decided |

### 8.1 Precondition analysis

The model returns a closed-vocabulary structure, not a free-form verdict:

```json
{
  "determinable": true,
  "paths": [
    { "requires": [
        {"type": "network_listener", "package": "openssh-server", "scope": "non_loopback",
         "necessary": true, "confidence": "high", "reason": "…"}
    ]},
    { "requires": [
        {"type": "local_user", "necessary": true, "confidence": "high", "reason": "…"},
        {"type": "unprivileged_userns", "necessary": true, "confidence": "medium", "reason": "…"}
    ]}
  ],
  "reasoning": "…",
  "recommended_status_if_reachable": "relevant"
}
```

`paths` are alternatives (any one suffices for an attack); `requires` are all
needed within a path. Checkable condition types are a fixed list the system can
evaluate against facts: `network_listener`, `package_in_use`, `service_active`,
`kernel_code` (source path), `unprivileged_userns`, `unprivileged_bpf`,
`local_user`, `physical_access`, `user_interaction`, `config_dependent`
(free text, never checkable).

A server is dismissed by the AI stage only if **every** path contains at least
one condition that is (a) `necessary`, (b) `confidence: high` and (c)
definitively false on that server according to known facts. Anything else stays
open. `determinable: false` keeps all servers open.

Because the analysis is per CVE and the check per server is deterministic:

- cost scales with the number of CVEs, not with servers × reports;
- a fact change re-checks without calling the model;
- the decision stores both the model's reasoning and which condition failed on
  which server, with the fact snapshot hash.

An analysis is reused until the CVE data, the prompt or the model changes
(`input_hash`, `prompt_hash`, `model`).

### 8.2 Cost controls

- Message Batches API (50 % price; the analysis is not urgent), switchable.
- Prompt caching of the system prompt and infrastructure context.
- Monthly budget in the Admin UI; the stage pauses when it is reached.
- Token usage and cost per stage are stored per call and shown in statistics.
- Before activation, both candidate models analyse the same sample of CVEs that
  humans have already assessed; the Admin UI shows agreement and cost per model.

Rough estimate, to be replaced by measurements: Sonnet with batching ≈ 1–3 ct
per CVE; Haiku 5.5 advisory a fraction of a cent.

## 9. Trust and security

- **Spoofed facts.** A compromised server could report false facts to get its
  findings dismissed. Guards (KEV, exploits) still apply, every dismissal is
  visible and revocable, and the fact snapshot is kept. Accepted residual risk,
  documented in the UI help.
- **Prompt injection** via CVE descriptions or process names: structured output
  with a closed vocabulary, facts never go into the prompt, the model cannot
  produce `relevant` or `accepted_risk` as an applied result.
- **Sensitive data.** Runtime facts are an attack-surface map. Only the current
  state per server plus referenced snapshots are stored; no command lines;
  access follows the existing auth model.

## 10. Control and visibility

**Admin → "Automated Assessment"**

- Global mode: off / shadow / active.
- Rule table: ID, version, description, mode per rule, number of decisions,
  agreement with human assessments in shadow mode.
- Guards: on/off for G-EXPLOIT and G-EPSS, EPSS threshold.
- AI: model and effort per stage, confidence threshold, batch on/off, monthly
  budget, current spend.
- "Check against existing assessments": runs rules and/or AI over CVEs humans
  have assessed and shows agreement, disagreements and cost.

**Triage, findings, CVE and server detail**

- Source badge (rule ID / AI / human) and a filter by source and mode.
- Decision detail: rule and version, or AI reasoning and the failed
  precondition; the fact snapshot; buttons *discard* and *override*; a timeline
  from `decision_events`.
- KEV badge (with ransomware flag and due date) and EPSS score/percentile;
  sort and filter by both.
- Server detail: runtime facts (listeners, loaded modules, packages in use,
  services, processes needing a restart).

**Statistics and metrics**

- Share of automatically decided (server, CVE) pairs over time, by rule and AI.
- Overrides by humans; shadow-mode agreement.
- AI cost per day and month, per stage.
- Triage queue size over time.
- Prometheus: decisions by source/rule, re-evaluations, evaluation duration, AI
  calls/tokens/cost, KEV/EPSS sync status.

**Reports (PDF)**

- New section "Automated assessments", **switchable per schedule and per manual
  report** (`include_auto_assessments`, off by default): counts by rule and AI in
  the period, human overrides, AI decisions with reasoning.
- KEV-listed CVEs with their affected servers (part of the existing CVE
  sections from Phase 1).

**MCP**

- Read access to decisions, reasons, KEV and EPSS, mirroring the UI settings
  (shared logic with the REST API).

## 11. Phases

Each phase is shippable on its own and leaves the system working.

| Phase | Content | Size |
|---|---|---|
| 1 | KEV and EPSS: syncers, storage, sync status in Admin, display in findings/triage/CVE detail, sort and filter, MCP fields, Prometheus | S |
| 2 | Decision model: tables, evaluation engine, guards, rules without agent data (R-VEX, R-HDR, R-KRN-IDLE), shadow mode, per-server override, binding flag, UI (Admin, badges, detail, timeline), statistics, PDF section with toggle, MCP | L |
| 3 | Runtime facts: API spec in AGENT_API.md, ingestion with fingerprints, storage, server detail UI; agent implementation in the agent repository | M (+ agent M) |
| 4 | Rules with host context: R-KMOD including the kernel CVE → source file → module mapping, R-NET, R-UNUSED (shadow) | L |
| 5 | AI precondition analysis: schema, checker, batching, budget, model comparison, gradual activation; advisory stage moved to Haiku 5.5 | L |

### Acceptance criteria

- **Phase 1:** KEV and EPSS sync daily and on demand; a sync failure is visible in
  Admin and Prometheus; KEV and EPSS appear in triage, findings, CVE detail and
  MCP; sorting and filtering work; no measurable slowdown of the findings and
  triage queries (EXPLAIN checked).
- **Phase 2:** shadow mode computes decisions without changing the triage queue;
  active mode removes decided servers from it; mode *off* restores today's
  behaviour exactly; every decision shows its rule and version; KEV listing
  reopens a dismissal in the next sync; an unchanged report writes no decision
  rows; benchmark within budget.
- **Phase 3:** old agents keep working unchanged; new agents against an old
  backend keep working; an unchanged report causes no snapshot write; facts
  visible on the server detail page.
- **Phase 4:** each rule has tests including negative cases; shadow-mode
  agreement with human assessments reviewed before activation.
- **Phase 5:** model comparison on the existing assessments documented; no
  `relevant` or `accepted_risk` ever applied automatically; budget stop works.

## 12. Rollback

- All schema changes are additive (new tables, new nullable or defaulted
  columns); an older VulTrack image runs against the newer schema.
- Global mode *off* disables evaluation and ignores `auto_decisions`; the
  triage queue is then computed exactly as before.
- The agent's `runtime` object is optional in both directions.

## 13. Open points

- Exact list of packages for R-HDR: to be checked against the production
  findings in shadow mode before the rule is activated.
- Verification of the kernel CVE → affected file data source (Phase 4).
- Default EPSS guard threshold (0.10 proposed) after looking at the distribution
  of our findings.

## 14. Implementation notes (phase 2)

- Decisions are stored per (server, CVE) in `auto_decisions` only when every
  active finding of the CVE on that server is dismissed by an enabled rule.
- Whether a decision takes effect is computed when it is read, from the global
  mode, the rule modes and the guards. Switching a rule between shadow and
  active therefore takes effect immediately, without re-evaluation.
- With no active rule, the triage queue does not join `auto_decisions` at all.
- One evaluation per server at a time (advisory lock); full re-evaluations are
  coalesced, so bursts of triggers cause at most one extra run.
- Hysteresis (§5, point 5) is not needed yet: the phase-2 rules read no runtime
  facts. It comes with phase 3.

## 15. Implementation notes (phase 3)

- `server_facts` holds the current state per (server, category) with
  `stable_since` (last content change) and `reported_at`; the content lives in
  `fact_snapshots`, keyed by the SHA-256 of the canonical JSON. `server_runtime`
  keeps the agent's collection errors and truncation flags.
- The kernel module index is stored once per kernel release in
  `kernel_module_index`; the kernel facts keep only its hash, so resending the
  index never looks like a change on the server.
- A category missing from a report, an unsupported `schemaVersion`, a report
  without `runtime` and an unparseable category all make the data unknown
  (the row is removed). Phase-4 rules must treat "no row" and `truncated` as
  "cannot conclude absence".
- Fact changes reach the decisions through the existing after-scan
  evaluation, since every report triggers a scan. Hysteresis (§5 point 5) is
  for phase 4: a dismissal that rests on a fact requires `stable_since` older
  than two report intervals.
- Snapshots no longer current and not cited by a decision or event
  (`evidence -> 'facts' -> <category> = <hash>`) are deleted daily after 30
  days; so are module indexes no server's kernel facts cite any more.


## 16. Implementation notes (phase 4: R-KMOD)

- **Affected code.** The Linux kernel CNA lists the affected source files in
  every CVE record it assigns (`containers.cna.affected[].programFiles`). The
  syncer (`internal/kernelintel`) fetches the record from the CVE Services API
  (`https://cveawg.mitre.org/api/cve/<id>`) for every kernel CVE with active
  findings, at about 5 requests per second, and stores it in
  `kernel_cve_files`. Records are refreshed after 30 days, failures after a
  day. CVEs of other CNAs have no file list (`no_files`) and are never
  dismissed by R-KMOD.
- **Build map.** For every kernel build a server with kernel facts runs
  (release from the facts, version of `linux-modules-<release>`, server
  architecture) the syncer downloads from Launchpad, which keeps every
  published build:
  the flavour headers package (`linux-headers-<release>`, for `.config`), the
  common headers package (`linux-headers-<abi>` or `<source>-headers-<abi>`,
  for the Kbuild makefiles) and the module packages (`linux-modules-*`,
  `linux-modules-extra-*`, file names only). Makefiles are parsed into a map
  source file → `builtin` / `module <path>` / `absent (<option> off)`, stored in
  `kernel_source_files`. Packages are streamed; nothing else is kept.
- **Conservative parsing.** Conditionals (`ifeq`, `ifdef`) are ignored, so
  both branches count. Tokens with variables are skipped and the files behind
  them stay unmapped. `tools/` (user-space programs) is skipped. Code under a
  different `arch/` is `absent`. A module target counts as real only when the
  module packages ship it (`Shipped`); on a 6.8 tree 6,458 of 6,474 real
  modules are recognised, and a few makefile-only modules that are not shipped
  are never trusted.
- **Rule.** R-KMOD dismisses a `kernel` finding only when the kernel facts are
  known, not truncated and describe the scanned kernel (`release` =
  `servers.kernel`), the module index and the build map are known, and every
  affected file is mapped with every target either `absent`, or a module that
  is not loaded (by name or path), not built in on the host, and cannot be
  loaded: `modulesDisabled`, an `install … /bin/false|/bin/true` line, or not
  installed (missing from the host's index while the packages ship it). A
  plain `blacklist` line is not enough. The evidence names each file and why
  it cannot run.
- **Rules get host context.** `Rule.Dismiss(f, h *Host)`; rules that read
  runtime facts implement `FactReader`, and their decisions record the fact
  snapshot hashes in `evidence.facts`, which keeps those snapshots from the
  daily cleanup.
- **Hysteresis.** A new decision based on runtime facts is created only when
  the facts have been unchanged for the settle time (setting
  `auto_assessment_fact_settle_minutes`, default 120; Admin → Assessment
  Automation → Runtime facts & kernel data). An existing decision is revoked
  at once when the facts no longer support it, e.g. when the module is loaded.
- **Network.** The backend needs outbound HTTPS to `cveawg.mitre.org` and
  `launchpad.net` (redirects to `launchpadlibrarian.net`). Nothing is fetched
  while automated assessment or R-KMOD is off.
- **Admin.** `GET /api/v1/admin/kernel-intel/status` and
  `POST /api/v1/admin/kernel-intel/sync`; the Admin card shows CVE record
  counts and every mapped build with its server count.
