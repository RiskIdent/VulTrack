# VulTrack Agent — Package Info Prompt

Use this prompt with a coding agent working in the **vultrack-agent** repository,
after the runtime facts change ([AGENT_RUNTIME_FACTS_PROMPT.md](AGENT_RUNTIME_FACTS_PROMPT.md))
is in place. It adds one more category to the `runtime` object, `packageInfo`.
The backend uses it for the rule R-UNUSED (see
[AUTO_ASSESSMENT_PLAN.md](AUTO_ASSESSMENT_PLAN.md), §7).

---

## Prompt

```
You are extending the VulTrack agent's runtime facts with one new category,
`packageInfo`: for every installed Debian package, whether it ships entry points
(programs, services, plugins, hooks) and which packages it depends on.

Read the existing runtime facts code first (the `runtime` object, the
collectors, the dpkg file index helper, the configuration keys, the tests and
the golden file). Follow the same structure, style and rules. No new
third-party dependencies.

---

## 1. Why this exists — read this before writing code

The backend wants to dismiss vulnerability findings in libraries that nothing on
the server can use: installed, but not loaded by any process for weeks, without
programs or services of their own, and not needed by any package that has some.
Typical examples are old library versions left behind after upgrades.

The rule trusts the ABSENCE of entry points and dependencies. A package this
category wrongly reports as "no entry points", or a dependency that is missing,
can hide a real vulnerability. So:

1. **Over-report, never under-report.** When in doubt whether a file is an
   entry point, count it as one. A false "has entry points" only means a
   finding stays open for a human; a false "has none" can hide a real risk.
2. **All or nothing.** `packageInfo` must cover every installed package. If the
   collector cannot read the dpkg database, a package's file list, or runs out
   of time, OMIT `packageInfo` entirely and add an entry to `runtime.errors`.
   Never send a partial list.
3. The general rules of the runtime facts prompt still apply (unknown is not
   empty, never guess, deterministic output, privacy).

## 2. Configuration

Add `package_info` to the allowed values of `runtime_collectors` (enabled by
default, like the other collectors). Nothing else.

## 3. The `packageInfo` category

```json
"packageInfo": [
  {"package": "curl", "entryPoints": ["executable"],
   "depends": ["libc6", "libcurl4t64", "zlib1g"]},
  {"package": "libcurl4t64",
   "depends": ["libbrotli1", "libc6", "libgssapi-krb5-2", "libssl3t64", "zlib1g"]},
  {"package": "libpam-modules", "entryPoints": ["plugin"], "depends": ["libc6", "libpam0g"]},
  {"package": "nginx-core", "entryPoints": ["executable", "hook", "service"],
   "depends": ["libc6", "libpcre2-8-0", "libssl3t64", "nginx-common", "zlib1g"]}
]
```

One entry per installed package: every package in `/var/lib/dpkg/status`
whose files may be on disk, i.e. whose state (third word of `Status`) is
`installed`, `half-installed`, `half-configured`, `unpacked`,
`triggers-awaited` or `triggers-pending`, whatever the selection (`install`,
`hold`, …). The same set is used for the Provides map in §5.

- `package`: the package name without architecture qualifier. When the same
  package is installed for several architectures, emit ONE entry and merge
  `entryPoints` and `depends` of all of them.
- `entryPoints`: sorted, distinct values from §4. Omit the field when the
  package has none.
- `depends`: sorted, distinct names from §5. Omit the field when there are none.
- Sort entries by `package`.

## 4. Entry points

Take every path from the package's file list(s) in `/var/lib/dpkg/info/`
(`<package>.list` and `<package>:<arch>.list`). For each path, check the rules
below in order; a path may match several kinds. Apply the merged-/usr handling of
the dpkg file index helper: a path under `/bin`, `/sbin` or `/lib*` counts the
same as the `/usr/...` path, and vice versa.

`executable` — the package ships something that can be run:
- any path directly or indirectly under `/usr/bin`, `/usr/sbin`, `/usr/games`,
  `/usr/libexec`, `/usr/local/bin`, `/usr/local/sbin` (symlinks count too);
- any regular file anywhere with an execute bit for anyone (`mode & 0111 != 0`),
  checked with `lstat` on the real system. Shared libraries are not executable
  on Debian, so this mostly catches helper programs in `/usr/lib/<package>/`
  and scripts. Skip the stat for paths under `/usr/share/doc`, `/usr/share/man`,
  `/usr/share/info`, `/usr/share/locale` and `/usr/include` (never
  executable in practice) to save time;
- any file with the setuid or setgid bit.

`service` — the package starts something by itself or on demand:
- systemd units: any file under `/usr/lib/systemd/system`,
  `/usr/lib/systemd/user`, `/etc/systemd/system`, `/etc/systemd/user`,
  `/usr/lib/systemd/system-generators`, `/usr/lib/systemd/user-generators`;
- SysV init scripts under `/etc/init.d`;
- cron jobs under `/etc/cron.d`, `/etc/cron.hourly`, `/etc/cron.daily`,
  `/etc/cron.weekly`, `/etc/cron.monthly`;
- D-Bus activation files under `/usr/share/dbus-1/services`,
  `/usr/share/dbus-1/system-services`;
- desktop autostart files under `/etc/xdg/autostart`.

`plugin` — code that other programs load by name at run time:
- any shared object (`*.so` or `*.so.<digits…>`) whose directory is NOT one of
  the standard library directories `/usr/lib`, `/usr/lib64`, `/usr/lib32`,
  `/usr/lib/<multiarch-triplet>` (e.g. `/usr/lib/x86_64-linux-gnu`). This covers
  PAM modules (`…/security/`), SASL, GIO, gconv, OpenSSL providers, Python
  extensions and similar;
- NSS modules: any file named `libnss_*.so*`, also in a standard directory;
- interpreter modules: any file under `/usr/lib/python3*`, `/usr/lib/python2*`,
  `/usr/share/python3`, `/usr/lib/<triplet>/perl*`, `/usr/lib/<triplet>/perl5`,
  `/usr/share/perl5`, `/usr/lib/ruby`, `/usr/share/ruby`, `/usr/lib/nodejs`,
  `/usr/share/nodejs`, `/usr/lib/php`, `/usr/share/php`.

`hook` — files that make other software run the package's code:
- `/etc/profile.d`, `/etc/X11/Xsession.d`, `/etc/apt/apt.conf.d`,
  `/usr/lib/apt/methods`, `/etc/kernel/postinst.d`, `/etc/kernel/postrm.d`,
  `/etc/update-motd.d`, `/etc/network/if-*.d`, `/etc/NetworkManager/dispatcher.d`,
  `/usr/lib/udev/rules.d`, `/etc/udev/rules.d`, `/etc/pam.d`,
  `/etc/ld.so.conf.d`, `/etc/ld.so.preload`, `/usr/lib/systemd/system-sleep`,
  `/usr/lib/systemd/system-shutdown`.

A path that is a directory in the file list (dpkg lists directories too) does
not count by itself; only files and symlinks do. A path is a directory when
another path of the list lies below it or `lstat` reports a directory.

Compare paths with the rules always in their `/usr` form, also on systems
without merged `/usr` (`/lib/systemd/system/x.service` counts as
`/usr/lib/systemd/system/x.service`).

When `lstat` fails for a single file:
- the file does not exist (deleted by an administrator): apply only the
  path-based rules; the execute-bit check is skipped;
- any other error (e.g. permission denied): count the file as `executable`;
- diverted files (`/var/lib/dpkg/diversions`): check the file at the
  diversion target.

"All or nothing" (§1) applies to the dpkg database, the `.list` files and the
time budget, not to single files.

## 5. Dependencies

Read `Depends`, `Pre-Depends` and `Recommends` of the package from
`/var/lib/dpkg/status`.

- Split on `,` and `|` (alternatives all count), trim, drop version constraints
  (`(>= 1.2)`), architecture qualifiers (`:any`, `:amd64`) and architecture
  restrictions (`[amd64]`).
- Virtual packages: when a name is not an installed package but one or more
  installed packages declare it in `Provides`, emit the names of those
  installed providers instead. Build the Provides map from the same status file.
- Drop names that are neither installed nor provided by an installed package.
- Do not emit the package itself.

## 6. Limits and performance

- Cap: 6,000 entries; set `truncated` for `packageInfo` when hit (the backend then
  treats the category as unknown).
- Typical size is 150–250 KB for 1,500 packages. If the serialized `runtime`
  object would exceed 1 MB, extend the existing drop order: first
  `moduleIndex.available`/`builtin`, then `packageInfo`, then `packagesInUse`,
  each recorded in `errors`.
- Build the dpkg file index once per report and share it between
  `packagesInUse` and `packageInfo`.
- Building `packageInfo` stats up to a few hundred thousand files. It must take
  well under 2 seconds on a typical server. Build it without a cache first and
  measure on a real server; only if that is too slow, you MAY cache
  the result per package in a state file next to the module index state file,
  keyed by the size and modification time of the package's `.list` file(s) and
  of `/var/lib/dpkg/status`; anything changed is recomputed. Without such a
  cache, compute it on every report. Never send cached data for a package whose
  key changed.
- Count `packageInfo` against `runtime_timeout_seconds` like the other
  collectors; on timeout omit it and report the error.

## 7. Tests

- Fixture root with a small dpkg database (`status`, `info/*.list` including a
  multi-arch package) and fixture files with modes, covering: an executable in
  `/usr/bin`; a merged-/usr path given as `/bin/...`; a helper with an execute
  bit under `/usr/lib/<pkg>/`; a setuid file; a systemd unit; a cron job; a PAM
  module in `/usr/lib/x86_64-linux-gnu/security/`; an NSS module in the
  standard directory; a plain shared library in the standard directory (NO entry
  point); a Python module; a profile.d hook; a package that only ships
  directories and docs (no entry points).
- Dependencies: version constraints, alternatives, `:any`, `[arch]`
  restrictions, `Pre-Depends`, `Recommends`, a virtual package with two
  installed providers, a dependency that is not installed.
- A failing read of one `.list` file omits the whole category with an `errors`
  entry.
- Extend the golden-file and determinism tests to include `packageInfo`.
- If a cache is implemented: unchanged → served from cache; changed `.list`
  mtime or size → recomputed; cache file unreadable → recomputed.

## 8. Deliverables

1. The collector, the `packageInfo` category in `runtime`, the collector name
   in the configuration, with tests as above.
2. Updated agent documentation (what is collected and why).
3. In the pull request: the `packageInfo` entries of a real Ubuntu 24.04 server
   for `openssl`, `libssl3t64`, `libpam-modules`, `curl`, `libcurl4t64` and the
   total entry count and serialized size.

Do not change the backend repository. The backend accepts `packageInfo` as of
VulTrack v1.6.5; older backends ignore it.
```
