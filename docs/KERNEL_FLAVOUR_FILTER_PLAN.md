# Suppressing architecture-blind kernel findings

**Status:** implemented on 2026-09-03. This document is kept as the design
record — it explains why the code looks the way it does, and how to re-verify it.
**Scope:** server-side only. No agent, API, schema or frontend change.

## Result

On a 24.04 host with 10,269 packages installed and kernel `6.8.0-124-generic`,
against the real noble feeds:

| | before | after |
|---|---|---|
| kernel findings | 5,779 | **2,109** |
| suppressed | — | 3,670 |
| findings that newly appeared | — | 0 |
| `CVE-2026-31718` reported | yes | **no** |

Cross-checked against the independent flavour attribution of §4 on three host
profiles (amd64 GA, riscv64 on the same release string, amd64 HWE 6.14):
**0 justified findings lost, 0 unjustified findings remaining** in every case.
The riscv64 host keeps all 5,779 kernel findings, identical to the unfiltered
baseline.

The numbers are marginally below the §4 predictions (2,109 vs 2,120 and so on)
because on a host with packages installed a handful of definitions produce
package findings instead of kernel findings, which take precedence.

---

## 1. The problem

Ubuntu's OVAL identifies the running kernel with `uname_test` against `uname -r`.
There is no architecture predicate in that test, and Ubuntu's riscv64 kernel
flavour is *also* called `generic`. So every `-generic` release string is matched
by two flavour criteria at once:

| `uname -r` | matching criteria |
|---|---|
| `6.8.0-124-generic` | `linux` **and `linux-riscv`** |
| `6.14.0-33-generic` | `linux-hwe-6.14` **and `linux-riscv-6.14`** |
| `6.17.0-20-generic` | `linux-hwe-6.17` **and `linux-riscv-6.17`** |
| `7.0.0-30-generic` | `linux-hwe-7.0` **and `linux-riscv-7.0`** |
| `6.11.0-19-generic` | only `linux-hwe-6.11` (no riscv twin exists) |

The kernel criteria sit in an `OR`, so one match is enough for the definition to
hold. On an amd64 host the riscv criterion therefore fires for every CVE that
affects the riscv kernel but not the one actually running.

### Worked example (the report that triggered this)

`CVE-2026-31718`, Ubuntu 24.04, kernel `6.8.0-124-generic`, amd64.

The only criterion that matches in
`oval:com.ubuntu.noble:def:2026317180000000` is:

```
oval:com.ubuntu.noble:tst:201245420000460
  comment:     "Is kernel 'linux-riscv' running?"
  uname_state: pattern match   6.8.0-\d+(-generic)
```

The definition contains **no criterion for the plain `linux` source at all** —
only the 6.11/6.14/6.17/7.0 flavours plus riscv, realtime and raspi-realtime.
Canonical's own package feed agrees: for this CVE `linux` is `not-vulnerable`.

This is Canonical's data, not a VulTrack evaluation bug. Any correct OVAL
evaluator produces the same result, and the pre-`5198871` code did too (an
anchored `^6.8.0-[0-9]+(-generic)$` matches just as well).

**Worth doing independently:** report the four unqualified riscv patterns to the
Ubuntu Security team, with `CVE-2026-31718` on `6.8.0-124-generic` as the
minimal example.

---

## 2. The fix

For findings filed against the synthetic `kernel` package, take Canonical's
package feed as authoritative: does the feed consider the source package of the
*running* kernel affected by that CVE?

The feed is already imported (`231481d`), so no new data is needed.

### 2.1 Resolving the running kernel's source package

`getServerPackages` ([scanner.go:343](../backend/internal/scanner/scanner.go#L343))
already selects `source_package`, and `ScanServer` already builds `packageMap`
keyed by package name ([scanner.go:122](../backend/internal/scanner/scanner.go#L122)).
Resolution is a map lookup — **no new query**.

Try in this order, accepting the first candidate that passes the validity check
in 2.2:

1. `packageMap["linux-modules-" + kernel.Release].SourcePackage`
2. `packageMap["linux-headers-" + kernel.Release].SourcePackage`
3. `PkgFeedService.KernelSourceForRelease(...)` — the feed's own binary map for
   `linux-image-<release>` / `linux-image-unsigned-<release>`, but only when it
   yields exactly one source package.

If none resolves: **do not filter**.

> **Do not use `linux-image-<release>`'s own `source_package`.** Verified on a
> live 26.04 host:
> ```
> linux-image-7.0.0-30-generic     -> linux-signed     ← NOT in the feed at all
> linux-modules-7.0.0-30-generic   -> linux            ← correct
> linux-headers-7.0.0-30-generic   -> linux            ← correct
> ```
> Ubuntu builds the signed image in a separate `linux-signed` source package.
> Conversely the feed lists *only* `linux-image-*` / `linux-image-unsigned-*`
> binaries for kernel sources, never `linux-modules-*` — which is why step 3 is
> a fallback rather than the primary path.

Step 3 alone already fixes the reported case (`linux-image-6.8.0-124-generic` is
unique to `linux`, because `linux-riscv`'s ABI range stops at 60 while `linux`
reaches 138). The HWE/riscv pairs are ambiguous in the feed and need step 1.

### 2.2 The safety net — do not skip this

A resolved name only counts if it exists in `pkg_source_packages` for that source
with `is_kernel = true`.

Without this check, `linux-signed` (or any other name absent from the feed) would
produce zero status rows, and the rule in 2.3 would then suppress **every** kernel
finding. This is the single most dangerous failure mode of the whole change.

### 2.3 The decision rule

For each CVE about to be filed against `kernel`, with `S` = resolved kernel
source package and `kevr` = `KernelEVR(server.Kernel)`:

```
row := pkg_cve_status for (S, CVE)

row exists, status = "vulnerable"                  -> keep
row exists, status = "fixed", kevr <  fixed version -> keep
row exists, status = "fixed", kevr >= fixed version -> suppress
no row, but the CVE is in pkg_cve_metadata          -> suppress   (Canonical triaged it)
CVE not in pkg_cve_metadata                         -> keep       (fail open)
```

The `pkg_cve_metadata` guard exists because the importer drops `not-vulnerable`
rows (56% of the feed), which makes "no row" ambiguous between *triaged as
unaffected* and *not tracked*. Presence of a metadata row resolves it.

Importing the `not-vulnerable` rows for kernel sources instead would cost
**441,767 extra rows per release** (~1.8M across four releases) and was measured
to produce identical results — the guard never had to fire in any of the 11 host
profiles. Do not do it.

---

## 3. Where the code changed

### `backend/internal/services/pkg_feed_service.go`

Three methods under the `KERNEL CROSS-CHECK` heading:

```go
// IsKernelSourcePackage reports whether name is a kernel source package the
// feed knows (pkg_source_packages, is_kernel = true). See §2.2.
func (s *PkgFeedService) IsKernelSourcePackage(ctx context.Context, sourceID int64, name string) (bool, error)

// KernelSourceForRelease resolves a kernel release string to its source package
// through the feed's binary map, returning "" when ambiguous or unknown.
func (s *PkgFeedService) KernelSourceForRelease(ctx context.Context, sourceID int64, release string) (string, error)

// KernelVerdicts returns what the feed says about every CVE it knows, for one
// kernel source package. One query per scan.
func (s *PkgFeedService) KernelVerdicts(ctx context.Context, sourceID int64, kernelSource string) (map[string]KernelVerdict, error)
```

`KernelVerdicts` query — one row per CVE the feed knows (39,992 for noble),
with the status for that kernel source or empty:

```sql
SELECT m.cve_id, COALESCE(st.status, ''), COALESCE(st.source_fixed_version, '')
FROM pkg_cve_metadata m
LEFT JOIN pkg_cve_status st
  ON st.source_id = m.source_id
 AND st.cve_id = m.cve_id
 AND st.source_package = $2
WHERE m.source_id = $1
```

A CVE absent from the returned map is unknown to the feed → keep (§2.3).

### `backend/internal/scanner/scanner.go`

`kernelFeedFilter` holds the resolved kernel source package and the feed's
verdicts; its `justifies(cveID)` method applies §2.3 and fails open at every
step, including on a nil receiver. `newKernelFeedFilter` builds it once per scan
and returns nil — an inert filter — whenever any input is missing;
`resolveKernelSource` implements §2.1 with the §2.2 guard.

`ScanServer` builds the filter before the source loop and consults it in the
`evaluation.KernelMatch` branch, counting suppressions for a single log line.

Nothing else. Package findings are untouched.

### Not changed

`models`, `schema.sql`, the parser, the agent API, the frontend.

---

## 4. Validation already done — reproduce before and after

Two **independent** verdicts were computed for every kernel finding and compared:

- **A) Flavour attribution** (validation only): parse the criterion comments
  (`Is kernel 'X' running?`), evaluate the criteria tree, and record which
  flavours contributed to a `true` result. A finding is justified iff the running
  kernel's own flavour is among them.
- **B) Package feed** (what the implementation uses): §2.3.

They agreed **exactly** — every finding fell into either (own flavour matched,
feed affected) or (foreign flavour only, feed not affected). No case in between.

| Host profile | kernel findings | suppressed | real hits lost | FP left |
|---|---|---|---|---|
| amd64, 24.04 GA `6.8.0-124-generic` | 5,794 | **3,674 (63%)** | **0** | 0 |
| amd64, 24.04 GA `6.8.0-79-generic` | 5,794 | 3,670 | 0 | 0 |
| riscv64, `6.8.0-124-generic` | 5,794 | 0 | 0 | 0 |
| amd64, HWE `6.14.0-33-generic` | 4,172 | 843 (20%) | 0 | 0 |
| riscv64, `6.14.0-33-generic` | 4,172 | 2 | 0 | 0 |
| amd64, HWE `6.17.0-20-generic` | 2,922 | 260 (9%) | 0 | 0 |
| amd64, HWE `7.0.0-30-generic` | 1,848 | 8 | 0 | 0 |
| amd64, HWE `6.11.0-19-generic` | 5,605 | 0 | 0 | 0 |
| AWS `6.8.0-1029-aws` | 2,119 | 0 | 0 | 0 |
| lowlatency `6.8.0-79-lowlatency` | 2,119 | 0 | 0 | 0 |
| raspi `6.8.0-1015-raspi` | 2,120 | 0 | 0 | 0 |

Measured against the 2026-08-27 noble feeds. Re-measure after implementing and
confirm the "real hits lost" column stays at 0.

### How to reproduce

```bash
BASE=https://security-metadata.canonical.com/oval
curl -sSLO $BASE/com.ubuntu.noble.usn.oval.xml.bz2   # ~1 MB   -> 29 MB
curl -sSLO $BASE/com.ubuntu.noble.cve.oval.xml.bz2   # ~9 MB   -> 177 MB
curl -sSLO $BASE/com.ubuntu.noble.pkg.json.xz        # ~8 MB   -> 170 MB
```

Method: evaluate the CVE OVAL's kernel criteria for a given `uname -r` (only
`uname_test` and `variable_test` matter; treat package tests as false to isolate
the kernel path), then compare verdict A against verdict B per CVE. The riscv
criteria are identifiable as the `uname_state` patterns ending in a bare
`(-generic)` — there are exactly four.

For an end-to-end check, use a throwaway PostgreSQL and the existing test
harness in `backend/internal/scanner/oval_pipeline_test.go` (`setupPipeline`).

---

## 5. Tests

`backend/internal/scanner/kernel_filter_test.go` carries its own OVAL and feed
fixtures — an OVAL definition whose only matching criterion is a foreign flavour
(the riscv collision, `tst:9000`) alongside the genuine one, plus a feed that
gives both kernel sources the same image binary name so its binary map is
ambiguous for that release. Separate fixtures keep the exact expectations of the
existing pipeline tests untouched. The cases:

1. amd64 host, `linux-modules-*` reporting source `linux` → finding suppressed.
2. riscv64 host, source `linux-riscv` → finding kept.
3. Host whose kernel source cannot be resolved (no `source_package`, ambiguous
   release) → finding kept.
4. Host where only `linux-image-*` is reported, resolving to `linux-signed` →
   finding kept (§2.2 — this is the test that guards the dangerous failure mode).
5. `pkg` source disabled → finding kept.
6. CVE absent from `pkg_cve_metadata` → finding kept.

Plus: a release that maps to exactly one kernel source resolves from the feed
alone without any agent metadata, the `fixed` branch drops the finding once the
running kernel is past the fixed version, and a finding the cross-check starts
rejecting is marked `resolved_at` by the following scan rather than silently
disappearing.

---

## 6. Deliberate non-goals

The filter does nothing — behaviour stays exactly as today — when:

- the agent does not report `source_package` and the release string is ambiguous;
- the server has no kernel packages at all (a container reporting the host's
  `uname -r`);
- the `pkg` source is disabled or has not synced yet;
- a CVE is newer in the OVAL feed than in the package feed.

All four fail open, which is the conservative direction.

Only the kernel path is affected. Package-level findings, the OVAL linking, the
source precedence (`usn` > `cve` > `pkg`) and the pocket handling stay as
committed in `231481d`.
