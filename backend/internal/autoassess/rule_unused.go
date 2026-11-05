package autoassess

import (
	"fmt"
	"time"
)

// R-UNUSED: a package nothing on the server can run or load.
//
// All of the following must hold, from the agent's packageInfo and the
// package usage observation:
//   - packageInfo is known and complete, and lists the package;
//   - the package has no entry points of its own (programs, services,
//     plugins, hooks);
//   - no installed package with entry points depends on it, directly or
//     transitively (Depends, Pre-Depends, Recommends);
//   - usage has been observed without a gap for the whole period, and the
//     package was not in use (mapped by a process) during it.
//
// Typical hits are libraries left behind by upgrades. Software outside dpkg
// linking a system library is only visible while it runs, which is why the
// rule runs in shadow mode until reviewed.
type unusedPackage struct{}

func (unusedPackage) ID() string   { return "R-UNUSED" }
func (unusedPackage) Version() int { return 1 }
func (unusedPackage) Description() string {
	return "The package has no programs, services, plugins or hooks of its own, no installed package with such entry points " +
		"depends on it (directly or transitively), and no process has used it during the whole observation period " +
		"(gap-free agent reports). Typically libraries left behind by upgrades."
}
func (unusedPackage) FactCategories() []string { return []string{"packageInfo"} }

func (unusedPackage) Dismiss(f Finding, h *Host) (bool, string) {
	if h == nil || h.Packages == nil {
		return false, ""
	}
	p := h.Packages
	if f.Package == "kernel" || p.Window <= 0 || p.ObservedFor < p.Window {
		return false, ""
	}
	info, listed := p.Info[f.Package]
	if !listed || len(info.EntryPoints) > 0 || p.Reachable[f.Package] {
		return false, ""
	}
	if ago, seen := p.LastInUse[f.Package]; seen && ago < p.Window {
		return false, ""
	}
	days := int(p.Window / (24 * time.Hour))
	return true, fmt.Sprintf("no entry points, not needed by any package with entry points, not in use for %d days", days)
}

// PackageHost is what the agent reported about the installed packages.
type PackageHost struct {
	Info map[string]PackageInfo
	// Reachable: packages a package with entry points depends on,
	// directly or transitively.
	Reachable map[string]bool
	// ObservedFor is the gap-free usage observation; LastInUse how long
	// ago each package was last in use (absent: never seen in use).
	ObservedFor time.Duration
	LastInUse   map[string]time.Duration
	// Window is the configured observation period.
	Window time.Duration
}

// PackageInfo is one packageInfo entry.
type PackageInfo struct {
	Package     string   `json:"package"`
	EntryPoints []string `json:"entryPoints"`
	Depends     []string `json:"depends"`
}

// NewPackageHost builds the reachability from packageInfo.
func NewPackageHost(entries []PackageInfo) *PackageHost {
	p := &PackageHost{Info: make(map[string]PackageInfo, len(entries)), Reachable: map[string]bool{}}
	for _, e := range entries {
		p.Info[e.Package] = e
	}
	var queue []string
	for _, e := range entries {
		if len(e.EntryPoints) > 0 {
			queue = append(queue, e.Depends...)
		}
	}
	for len(queue) > 0 {
		name := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if p.Reachable[name] {
			continue
		}
		p.Reachable[name] = true
		queue = append(queue, p.Info[name].Depends...)
	}
	return p
}
