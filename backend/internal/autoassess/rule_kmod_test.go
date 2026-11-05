package autoassess

import (
	"strings"
	"testing"

	"github.com/vultrack/vultrack/internal/kernelintel"
)

func sctpTarget(shipped bool) kernelintel.Target {
	return kernelintel.Target{Kind: kernelintel.KindModule, Module: "kernel/net/sctp/sctp.ko", Config: "CONFIG_IP_SCTP", Shipped: shipped}
}

// kmodHost: sctp.ko is installed, not loaded and blocked by "install /bin/true".
func kmodHost() *Host {
	return &Host{
		FactHashes: map[string]string{"kernel": "h1"},
		Kernel: &KernelHost{
			Release: "6.8.0-147-generic", ScanKernel: "6.8.0-147-generic",
			Loaded:         map[string]bool{"ext4": true, "kernel/fs/ext4/ext4.ko": true},
			InstallBlocked: map[string]string{"sctp": "/bin/true"},
			IndexKnown:     true,
			Available:      map[string]bool{"kernel/net/sctp/sctp.ko": true},
			Builtin:        map[string]bool{},
			Build:          &KernelBuild{Version: "6.8.0-147.147", ModulesVerified: true},
			CVEs: map[string]KernelCVE{
				"CVE-S": {
					Files: []string{"net/sctp/socket.c", "net/sctp/objcnt.c"},
					Targets: map[string][]kernelintel.Target{
						"net/sctp/socket.c": {sctpTarget(true)},
						"net/sctp/objcnt.c": {{Kind: kernelintel.KindAbsent, Config: "CONFIG_SCTP_DBG_OBJCNT"}},
					},
				},
			},
		},
	}
}

var kernelFinding = Finding{CVEID: "CVE-S", Package: "kernel"}

func TestKMODDismisses(t *testing.T) {
	ok, detail := kernelModules{}.Dismiss(kernelFinding, kmodHost())
	if !ok {
		t.Fatal("blocked, unloaded module must be dismissed")
	}
	for _, s := range []string{"6.8.0-147.147", "net/sctp/socket.c: module sctp not loaded, modprobe install /bin/true",
		"net/sctp/objcnt.c: not compiled (CONFIG_SCTP_DBG_OBJCNT off)"} {
		if !strings.Contains(detail, s) {
			t.Errorf("detail %q lacks %q", detail, s)
		}
	}

	// module loading disabled
	h := kmodHost()
	h.Kernel.InstallBlocked = map[string]string{}
	h.Kernel.ModulesDisabled = true
	if ok, d := (kernelModules{}).Dismiss(kernelFinding, h); !ok || !strings.Contains(d, "module loading disabled") {
		t.Errorf("modules_disabled: %v %q", ok, d)
	}

	// module not installed, and the packages confirm the mapping
	h = kmodHost()
	h.Kernel.InstallBlocked = map[string]string{}
	h.Kernel.Available = map[string]bool{}
	if ok, d := (kernelModules{}).Dismiss(kernelFinding, h); !ok || !strings.Contains(d, "not installed") {
		t.Errorf("not installed: %v %q", ok, d)
	}

	// the whole CVE in code of another architecture
	h = kmodHost()
	h.Kernel.CVEs["CVE-S"] = KernelCVE{Files: []string{"arch/arm64/x.c"},
		Targets: map[string][]kernelintel.Target{"arch/arm64/x.c": {{Kind: kernelintel.KindAbsent, Config: "ARCH"}}}}
	if ok, _ := (kernelModules{}).Dismiss(kernelFinding, h); !ok {
		t.Error("code of another architecture must be dismissed")
	}
}

func TestKMODKeepsOpen(t *testing.T) {
	cases := map[string]func(h *Host){
		"no host context":          func(h *Host) { h.Kernel = nil },
		"truncated facts":          func(h *Host) { h.Kernel.Truncated = true },
		"other running kernel":     func(h *Host) { h.Kernel.ScanKernel = "6.8.0-150-generic" },
		"module index unknown":     func(h *Host) { h.Kernel.IndexKnown = false },
		"build not mapped":         func(h *Host) { h.Kernel.Build = nil },
		"CVE record not fetched":   func(h *Host) { delete(h.Kernel.CVEs, "CVE-S") },
		"CVE record lists no file": func(h *Host) { h.Kernel.CVEs["CVE-S"] = KernelCVE{} },
		"module loaded (by name)":  func(h *Host) { h.Kernel.Loaded["sctp"] = true },
		"module loaded (by path)":  func(h *Host) { h.Kernel.Loaded["kernel/net/sctp/sctp.ko"] = true },
		"module built in on host":  func(h *Host) { h.Kernel.Builtin["kernel/net/sctp/sctp.ko"] = true },
		"plain blacklist only":     func(h *Host) { h.Kernel.InstallBlocked = map[string]string{} },
		"a file not mapped": func(h *Host) {
			c := h.Kernel.CVEs["CVE-S"]
			c.Files = append(c.Files, "net/sctp/unknown.c")
			h.Kernel.CVEs["CVE-S"] = c
		},
		"a file built in": func(h *Host) {
			c := h.Kernel.CVEs["CVE-S"]
			c.Targets["net/sctp/socket.c"] = append(c.Targets["net/sctp/socket.c"], kernelintel.Target{Kind: kernelintel.KindBuiltin})
		},
		"not installed, modules not verified": func(h *Host) {
			h.Kernel.InstallBlocked = map[string]string{}
			h.Kernel.Available = map[string]bool{}
			h.Kernel.Build.ModulesVerified = false
		},
		"not installed, not shipped (mapping in doubt)": func(h *Host) {
			h.Kernel.InstallBlocked = map[string]string{}
			h.Kernel.Available = map[string]bool{}
			h.Kernel.CVEs["CVE-S"].Targets["net/sctp/socket.c"][0] = sctpTarget(false)
		},
	}
	for name, mutate := range cases {
		h := kmodHost()
		mutate(h)
		if ok, d := (kernelModules{}).Dismiss(kernelFinding, h); ok {
			t.Errorf("%s: dismissed (%s)", name, d)
		}
	}
	if ok, _ := (kernelModules{}).Dismiss(Finding{CVEID: "CVE-S", Package: "openssl"}, kmodHost()); ok {
		t.Error("only findings of the running kernel")
	}
}

func TestKMODEvidenceFacts(t *testing.T) {
	ds := Decide([]Finding{kernelFinding}, kmodHost(), Rules, nil, GuardConfig{})
	d, ok := ds["CVE-S"]
	if !ok || d.RuleIDs[0] != "R-KMOD" {
		t.Fatalf("decision %+v", ds)
	}
	if d.Evidence.Facts["kernel"] != "h1" {
		t.Errorf("facts evidence %+v", d.Evidence.Facts)
	}
	// rules that read no facts record none
	ds = Decide([]Finding{{CVEID: "CVE-X", Package: "linux-libc-dev"}}, kmodHost(), Rules, nil, GuardConfig{})
	if ds["CVE-X"].Evidence.Facts != nil {
		t.Errorf("R-HDR must not record facts: %+v", ds["CVE-X"].Evidence.Facts)
	}
}
