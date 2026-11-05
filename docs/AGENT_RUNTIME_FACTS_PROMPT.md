# VulTrack Agent — Runtime Facts Prompt

Use this prompt with a coding agent working in the **vultrack-agent** repository.
It adds optional runtime facts to the agent's report. The VulTrack backend uses
them to decide automatically whether a vulnerability can affect a server (see
[AUTO_ASSESSMENT_PLAN.md](AUTO_ASSESSMENT_PLAN.md), §6).

---

## Prompt

```
You are extending the VulTrack agent so that every report also carries runtime
facts about the system: loaded kernel modules, listening sockets, packages in
use by running processes, systemd services and a few kernel settings.

Read the existing codebase first. Understand how the report is built and sent
(API v2, POST /api/v2/agent/report), how configuration is loaded, how errors are
logged and how tests are written. Follow the existing style, structure and
dependency policy. Do not add third-party dependencies unless the repository
already uses an equivalent; everything below can be done with the standard
library by reading /proc, /sys and /lib/modules and by running systemctl.

---

## 1. Why these facts exist — read this before writing code

The backend uses the facts to dismiss vulnerability findings automatically,
for example "this kernel CVE is in a module that is not loaded and cannot be
loaded" or "this daemon only listens on 127.0.0.1". A wrong or incomplete fact
can therefore hide a real vulnerability. Two rules follow from that and override
everything else in this prompt:

1. **Unknown is not empty.** If a collector cannot collect a category (missing
   permission, unsupported system, error, timeout), OMIT that field entirely and
   record the reason in `runtime.errors`. Send an empty list ONLY when the
   collector ran successfully and found nothing. The backend treats a missing
   field as "unknown" and will never dismiss anything based on it; it treats an
   empty list as a fact.
2. **Never guess.** If a value cannot be determined exactly (for example the
   owning package of a file), leave that single field out instead of filling in
   a plausible value.

## 2. Backward compatibility

- All new data goes into ONE new optional top-level object `runtime` in the
  existing report body. No existing field changes name, type or meaning.
- The backend ignores unknown fields, so a new agent works against an older
  backend unchanged. Do not branch on the server version.
- Do not compress the request body; the backend does not accept
  `Content-Encoding: gzip`.
- The whole request body must stay below 3 MB (the backend limit is 4 MB and the
  package list already uses part of it). The `runtime` object must stay below
  1 MB; see §5 for limits and truncation.

## 3. Configuration

Add to the agent configuration, keeping the existing format:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `collect_runtime` | bool | `true` | Master switch. `false` omits `runtime` entirely. |
| `runtime_collectors` | list of strings | all | Which collectors run: `kernel`, `listeners`, `packages_in_use`, `services`, `virtualization`. A collector that is not listed is omitted (not an empty list). |
| `runtime_timeout_seconds` | int | `20` | Overall time budget for all collectors. A collector that exceeds its share is aborted and reported in `runtime.errors`. |
| `module_index_state_file` | string | `/var/lib/vultrack-agent/module-index.sha256` | Where the hash of the last sent module index is stored (see §4.1). |

Document the new keys wherever the existing configuration is documented.

## 4. The `runtime` object

```json
"runtime": {
  "schemaVersion": 1,
  "collectedAt": "2026-11-05T10:00:03Z",
  "kernel": { ... },
  "listeners": [ ... ],
  "packagesInUse": [ ... ],
  "services": [ ... ],
  "virtualization": "kvm",
  "errors": [ {"collector": "services", "error": "systemctl not found"} ],
  "truncated": ["packagesInUse"]
}
```

- `schemaVersion` is always `1` for this change.
- `collectedAt` is UTC, RFC 3339, the time the collection started.
- Lists are sorted deterministically (by the fields listed per section) so that
  identical system state produces byte-identical JSON. The backend hashes each
  category to detect changes; unstable ordering would make every report look
  changed.
- `errors` lists collectors that failed or were skipped because of an error.
  Omit `errors` when it is empty. `truncated` lists categories cut by the size
  limits in §5; omit it when nothing was cut.

### 4.1 `kernel`

```json
"kernel": {
  "release": "6.8.0-124-generic",
  "modulesDisabled": false,
  "loadedModules": [
    {"name": "ath9k", "path": "kernel/drivers/net/wireless/ath/ath9k/ath9k.ko.zst"}
  ],
  "blacklistedModules": [
    {"name": "cramfs", "installCommand": "/bin/false"},
    {"name": "pcspkr"}
  ],
  "moduleIndex": {
    "hash": "sha256:…",
    "available": ["kernel/arch/x86/crypto/aesni-intel.ko.zst", "…"],
    "builtin": ["kernel/fs/ext4/ext4.ko", "…"]
  },
  "sysctls": {
    "kernel.unprivileged_userns_clone": "1",
    "user.max_user_namespaces": "63408",
    "kernel.apparmor_restrict_unprivileged_userns": "1",
    "kernel.unprivileged_bpf_disabled": "2",
    "kernel.yama.ptrace_scope": "1",
    "kernel.kptr_restrict": "1",
    "kernel.dmesg_restrict": "1",
    "kernel.perf_event_paranoid": "4",
    "kernel.modules_disabled": "0"
  },
  "installedKernels": ["6.8.0-121-generic", "6.8.0-124-generic"],
  "rebootRequired": true,
  "rebootRequiredPackages": ["linux-image-6.8.0-124-generic"]
}
```

How to collect each field:

- `release`: `uname -r` equivalent (`syscall.Uname` or `/proc/sys/kernel/osrelease`).
- `modulesDisabled`: `/proc/sys/kernel/modules_disabled` equals `1`.
- `loadedModules`: names from `/proc/modules` (first column). `path` is the
  module's path relative to `/lib/modules/<release>/` as listed in
  `/lib/modules/<release>/modules.dep` (left of the colon); omit `path` for a
  module not found there. Sort by `name`.
- `blacklistedModules`: parse every `*.conf` in `/etc/modprobe.d`,
  `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/lib/modprobe.d` and
  `/usr/lib/modprobe.d`, honouring the modprobe.d override rule (a file in an
  earlier directory replaces a file of the same name in a later one). Collect
  `blacklist <name>` lines, and `install <name> <command>` lines whose command is
  exactly `/bin/false`, `/bin/true`, `/usr/bin/false` or `/usr/bin/true`
  (record it in `installCommand`). Ignore comments and other directives. Module
  names: treat `-` and `_` as equal and report them with `_`. Sort by `name`.
- `moduleIndex`: `available` is every module path from `modules.dep`;
  `builtin` every line of `/lib/modules/<release>/modules.builtin`; both sorted.
  `hash` is `sha256:` + hex SHA-256 over the release string, a newline, the
  sorted `available` lines joined by newlines, a newline, and the sorted
  `builtin` lines joined by newlines. The index is large (several thousand
  lines), so send it only when needed: include the full `moduleIndex` object
  when its hash differs from the hash in `module_index_state_file`, or when that
  file is missing or older than 24 hours; otherwise send only
  `"moduleIndex": {"hash": "sha256:…"}`. Write the state file only after the
  report was accepted with HTTP 2xx.
- `sysctls`: read exactly the keys above from `/proc/sys` (dots become slashes).
  Include a key only if its file exists and is readable; values are the trimmed
  file contents as strings.
- `installedKernels`: from the dpkg status database
  (`/var/lib/dpkg/status`), packages named `linux-image-*` in state
  `install ok installed`, reported as the release suffix
  (`linux-image-6.8.0-124-generic` → `6.8.0-124-generic`); skip meta packages
  such as `linux-image-generic`. Sort ascending by string.
- `rebootRequired`: `/var/run/reboot-required` exists.
  `rebootRequiredPackages`: lines of `/var/run/reboot-required.pkgs`, sorted and
  de-duplicated; omit when the file does not exist.

### 4.2 `listeners`

```json
"listeners": [
  {"protocol": "tcp", "address": "0.0.0.0", "port": 22,
   "process": "sshd", "exe": "/usr/sbin/sshd", "package": "openssh-server",
   "unit": "ssh.service", "hostNetns": true}
]
```

- Read `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`.
  TCP: only state `0A` (LISTEN). UDP: sockets in state `07` whose remote
  address is all zeros (bound, unconnected).
- `protocol`: `tcp`, `tcp6`, `udp` or `udp6` by source file.
- `address`: the local address in normal text form (IPv4 dotted, IPv6
  compressed, e.g. `::`, `::1`, `::ffff:127.0.0.1`). Decode the kernel's
  little-endian hex correctly and add a unit test for each form.
- `port`: integer.
- Map socket inode → process: scan `/proc/<pid>/fd/*` symlinks of the form
  `socket:[<inode>]`. When several processes share a socket, report the one with
  the lowest PID. `process` is `/proc/<pid>/comm`, `exe` the target of
  `/proc/<pid>/exe`. Leave both out when the socket's owner is not found.
- `package`: owner of `exe` from the dpkg file index (§4.6); omit when unknown.
- `unit`: the systemd unit from `/proc/<pid>/cgroup` (the last path element
  ending in `.service` or `.scope`); omit when none.
- Network namespaces: also read `/proc/<pid>/net/tcp*`/`udp*` for one process per
  distinct `/proc/<pid>/ns/net`, so sockets inside containers are found.
  `hostNetns` is `true` for the namespace of PID 1, `false` otherwise.
- De-duplicate identical entries; sort by protocol, address, port, process.

### 4.3 `packagesInUse`

```json
"packagesInUse": [
  {"package": "libssl3t64", "processes": ["nginx", "sshd"],
   "staleProcesses": ["nginx"]}
]
```

- For every process, read `/proc/<pid>/maps` and take the file paths of
  file-backed mappings, plus the target of `/proc/<pid>/exe`.
- A path ending in ` (deleted)` means the process still runs code from a file
  that has been replaced (typically by an upgrade). Strip the suffix, look up the
  package of the original path and add the process to `staleProcesses` of that
  package. This is how the backend knows that an upgraded library is still in
  use in its old version until the process restarts.
- Map paths to packages with the dpkg file index (§4.6). Paths without a
  package are ignored.
- `processes` and `staleProcesses` contain distinct `comm` names, sorted, at most
  20 each (set `truncated` if cut). Omit `staleProcesses` when empty.
- Skip kernel threads (empty `maps`). Processes that exit while being read are
  skipped silently, not reported as errors.
- Sort entries by `package`.

### 4.4 `services`

```json
"services": [
  {"unit": "nginx.service", "activeState": "active", "subState": "running",
   "unitFileState": "enabled", "package": "nginx"}
]
```

- List the units with `systemctl list-units --type=service --all --no-legend
  --plain` (first column), then read their properties with
  `systemctl show <units…> --property=Id,ActiveState,SubState,UnitFileState,FragmentPath`
  in batches of at most 100 units. Do not depend on `--output=json` (missing on
  Ubuntu 20.04). `systemctl show` without unit names describes the service
  manager itself, not the units; do not use it that way.
- `package`: owner of `FragmentPath` from the dpkg file index; omit when unknown.
- Include all service units, also inactive ones. Sort by `unit`.

### 4.5 `virtualization`

- Output of `systemd-detect-virt` (e.g. `none`, `kvm`, `vmware`, `lxc`,
  `docker`). Omit the field when the command is missing or fails with anything
  other than the documented "none" result.

### 4.6 dpkg file index (shared helper)

- Build a map path → package once per report from
  `/var/lib/dpkg/info/*.list` (the package name is the file name without
  `.list`, minus an `:arch` suffix).
- Handle merged `/usr`: on systems where `/bin`, `/sbin` and `/lib*` are
  symlinks into `/usr`, look a path up both as given and with the
  `/usr` prefix added or removed.
- Respect diversions in `/var/lib/dpkg/diversions` (the diverted-to path belongs
  to the package that made the diversion only if the file list says so; when
  unsure, leave the package out).
- Resolve symlinks of the looked-up path only one level; do not follow chains.
- The index must be built at most once per report and must not be held in memory
  between reports.

## 5. Limits and performance

- The whole collection must finish within `runtime_timeout_seconds` and should
  normally take well under 2 seconds of CPU on a server with 500 processes.
- Hard caps, applied after sorting: `listeners` 2,000 entries,
  `packagesInUse` 3,000 entries, `services` 2,000 entries. Add the category name
  to `truncated` when a cap is hit. If the serialized `runtime` object would
  still exceed 1 MB, drop `moduleIndex.available` and `moduleIndex.builtin`
  (keep the hash, so it is retried next time) and then, if still too large,
  omit `packagesInUse` and record that in `errors`.
- The agent must not write anything except the module index state file.
- The agent usually runs as root. If it does not, collectors that need other
  processes' `/proc` entries will see only part of the system: in that case
  OMIT `listeners` and `packagesInUse` and report
  `{"collector": "...", "error": "insufficient privileges"}` — partial data
  would look complete to the backend.

## 6. Privacy

Do not collect, log or send:

- command lines (`/proc/<pid>/cmdline`), environment variables
  (`/proc/<pid>/environ`), working directories or open regular files other than
  through `maps`;
- user names or UIDs of processes;
- contents of configuration files other than the modprobe directives above.

## 7. Tests

- Unit tests for every parser with fixture files checked into the repository
  (`/proc/net/tcp*` with IPv4, IPv6 and v4-mapped addresses; `/proc/modules`;
  `modules.dep`; `modules.builtin`; modprobe.d with overrides, comments,
  `blacklist` and `install`; `maps` with deleted files; dpkg `.list` files with
  merged-/usr cases; `systemctl show` output).
- Make the collectors read from a configurable root directory so the fixtures can
  be used without touching the real system.
- A golden-file test for the complete `runtime` JSON of a fixture system, which
  also proves the output is deterministic (run it twice, compare bytes).
- A test that a failing collector leads to an omitted field plus an `errors`
  entry, never to an empty list.
- A test for the module index state file: full index on first run, hash only on
  the second run, full index again after 24 hours or a hash change, and no state
  file update when the report fails.

## 8. Deliverables

1. The collectors, the `runtime` object in the report, and the configuration
   keys, with tests as above.
2. Updated agent documentation: configuration keys, what is collected, what is
   deliberately not collected, and how to disable it.
3. A short summary in the pull request description with an example `runtime`
   object from a real Ubuntu 24.04 server (anonymised: replace hostnames and
   addresses that are not loopback or wildcard).

Do not change the backend repository. The backend side (accepting, storing and
using these facts) is implemented separately against this specification.
```
