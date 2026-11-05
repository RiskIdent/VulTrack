package autoassess

import (
	"path"
	"strings"
	"time"

	"github.com/vultrack/vultrack/internal/kernelintel"
)

// Host is what the rules know about the server itself. Every part may be
// missing; a rule that needs a missing part does not dismiss.
type Host struct {
	// Kernel is the running kernel as described by the agent's kernel facts
	// and the mapped kernel build. Nil when the facts are unknown.
	Kernel *KernelHost
	// Packages is the agent's packageInfo with the usage observation. Nil
	// when packageInfo is unknown or truncated.
	Packages *PackageHost
	// FactHashes holds the snapshot hash of each fact category the host
	// context was built from; recorded as evidence by rules that read them.
	FactHashes map[string]string
	// FactsAge is how long each fact category has been unchanged.
	FactsAge map[string]time.Duration
}

// KernelHost describes the running kernel.
type KernelHost struct {
	// Release is the kernel facts' release ("6.8.0-147-generic"); ScanKernel
	// is the kernel the vulnerability scan matched against. Kernel rules fire
	// only when both agree.
	Release    string
	ScanKernel string
	Truncated  bool

	ModulesDisabled bool
	// Loaded holds the names of loaded modules ("-" folded to "_") and the
	// paths of those with a known path (without compression suffix).
	Loaded map[string]bool
	// InstallBlocked holds modules whose modprobe install command is
	// /bin/false or /bin/true: modprobe never loads them.
	InstallBlocked map[string]string

	// IndexKnown: the module index (modules.dep, modules.builtin) for this
	// release is stored. Available and Builtin hold paths without suffix.
	IndexKnown bool
	Available  map[string]bool
	Builtin    map[string]bool

	// Build is the mapped kernel build, nil when there is none (yet).
	Build *KernelBuild
	// CVEs holds the affected program files of the kernel CVEs on this server
	// with their build targets.
	CVEs map[string]KernelCVE
}

// KernelBuild identifies the mapped build.
type KernelBuild struct {
	Version         string // linux-modules-<release> package version
	ModulesVerified bool
}

// KernelCVE is the code a kernel CVE affects, mapped to this build.
type KernelCVE struct {
	Files []string
	// Targets per program file; a file without entry is not mapped (unknown).
	Targets map[string][]kernelintel.Target
}

// ModulePath strips a compression suffix from a module path.
func ModulePath(p string) string {
	for _, ext := range []string{".zst", ".xz", ".gz"} {
		p = strings.TrimSuffix(p, ext)
	}
	return p
}

// ModuleName returns the kernel's name of a module path
// ("kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko" → "vmw_vsock_virtio_transport").
func ModuleName(p string) string {
	return strings.ReplaceAll(strings.TrimSuffix(path.Base(ModulePath(p)), ".ko"), "-", "_")
}
