package autoassess

import (
	"fmt"
	"strings"

	"github.com/vultrack/vultrack/internal/kernelintel"
)

// R-KMOD: a kernel CVE whose affected code exists on this server only in
// modules that are not loaded and cannot be loaded, or is not compiled at all.
//
// Every affected program file of the CVE record must be mapped for the
// running kernel build, and every place it is compiled into must be one of:
//   - absent: its config option is off (or it belongs to another architecture);
//   - a module that is not loaded and cannot be loaded: module loading is
//     disabled, or modprobe's install command for it is /bin/false or
//     /bin/true, or the module file is not installed (missing from the
//     server's module index while the kernel's module packages do ship it,
//     which confirms the mapping).
//
// A file compiled into the kernel image, a file the makefiles do not map, a
// module that is loaded or merely blacklisted (the "blacklist" directive does
// not stop explicit or dependency loads), or any unknown fact keeps the CVE
// open.
type kernelModules struct{}

func (kernelModules) ID() string   { return "R-KMOD" }
func (kernelModules) Version() int { return 1 }
func (kernelModules) Description() string {
	return "Kernel CVE whose affected source files (from the CVE record) are, in the running kernel build, " +
		"either not compiled or compiled only into modules that are not loaded and cannot be loaded: " +
		"module loading disabled, modprobe install command /bin/false or /bin/true, or the module not installed. " +
		"Code built into the kernel image, unmapped files and merely blacklisted modules are never dismissed."
}
func (kernelModules) FactCategories() []string { return []string{"kernel"} }

func (kernelModules) Dismiss(f Finding, h *Host) (bool, string) {
	if f.Package != "kernel" || h == nil || h.Kernel == nil {
		return false, ""
	}
	k := h.Kernel
	if k.Truncated || k.Release == "" || k.Release != k.ScanKernel || !k.IndexKnown || k.Build == nil {
		return false, ""
	}
	cve, ok := k.CVEs[f.CVEID]
	if !ok || len(cve.Files) == 0 {
		return false, ""
	}
	var parts []string
	for _, file := range cve.Files {
		targets := cve.Targets[file]
		if len(targets) == 0 {
			return false, "" // not mapped: unknown
		}
		var why []string
		for _, t := range targets {
			reason, ok := k.unreachable(t)
			if !ok {
				return false, ""
			}
			why = append(why, reason)
		}
		parts = append(parts, file+": "+strings.Join(why, ", "))
	}
	return true, fmt.Sprintf("kernel %s (build %s): %s", k.Release, k.Build.Version, strings.Join(parts, "; "))
}

// unreachable reports whether code compiled into target cannot run on the
// server, with the reason.
func (k *KernelHost) unreachable(t kernelintel.Target) (string, bool) {
	switch t.Kind {
	case kernelintel.KindAbsent:
		if t.Config == "ARCH" {
			return "other architecture", true
		}
		if t.Config != "" {
			return "not compiled (" + t.Config + " off)", true
		}
		return "not compiled", true
	case kernelintel.KindModule:
	default:
		return "", false // built in, or unknown kind
	}
	name := ModuleName(t.Module)
	if t.Module == "" || k.Loaded[name] || k.Loaded[t.Module] || k.Builtin[t.Module] {
		return "", false
	}
	switch {
	case k.ModulesDisabled:
		return "module " + name + " not loaded, module loading disabled", true
	case k.Available[t.Module]:
		if cmd, blocked := k.InstallBlocked[name]; blocked {
			return "module " + name + " not loaded, modprobe install " + cmd, true
		}
		return "", false // installed and loadable
	case k.Build.ModulesVerified && t.Shipped:
		return "module " + name + " not installed", true
	}
	// Not in the index, but the build's module packages were not checked or
	// do not contain it: the mapping itself is in doubt.
	return "", false
}
