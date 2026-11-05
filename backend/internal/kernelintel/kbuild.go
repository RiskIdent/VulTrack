// Package kernelintel maps Linux kernel CVEs to the kernel code they affect
// and that code to how a given kernel build contains it, so the R-KMOD rule can
// tell whether a server can run the vulnerable code at all.
//
//   - The affected source files of a CVE come from its CVE record
//     (containers.cna.affected[].programFiles), which the Linux kernel CNA fills
//     for every CVE it assigns.
//   - How each source file is built — into the kernel image, as a module, or
//     not at all — comes from the kernel's Kbuild makefiles together with the
//     build's .config, both shipped in Ubuntu's linux-headers packages for the
//     exact kernel build.
//
// Everything is conservative: a file the makefiles do not map is unknown, and
// a file that may be built in under any reading is never dismissed.
package kernelintel

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// Build kinds of a source file in one kernel build.
const (
	KindBuiltin = "builtin" // compiled into the kernel image: always present
	KindModule  = "module"  // compiled into a loadable module
	KindAbsent  = "absent"  // its config option is off: not compiled at all
)

// Target is one place a source file ends up in a kernel build.
type Target struct {
	Kind string `json:"kind"`
	// Module path as in modules.dep without the compression suffix, e.g.
	// "kernel/net/vmw_vsock/vsock.ko"; set for KindModule.
	Module string `json:"module,omitempty"`
	// Config is the option that decided it ("CONFIG_VSOCKETS"), if any;
	// "ARCH" for code of another architecture.
	Config string `json:"config,omitempty"`
	// Shipped: the module file is in this kernel's module packages
	// (linux-modules, linux-modules-extra). Set only when that was checked;
	// a module the makefiles suggest but the packages do not contain is not
	// trusted.
	Shipped bool `json:"shipped,omitempty"`
}

// SourceMap maps a source path relative to the kernel tree
// (e.g. "net/vmw_vsock/af_vsock.c") to every place it is compiled into.
type SourceMap map[string][]Target

func (m SourceMap) add(file string, t Target) {
	for _, have := range m[file] {
		if have == t {
			return
		}
	}
	m[file] = append(m[file], t)
}

var (
	// "lhs op rhs" where op is +=, :=, ?= or =.
	assignRe = regexp.MustCompile(`^\s*([A-Za-z0-9_\-.$()]+?)\s*(\+=|:=|\?=|=)\s*(.*)$`)
	// obj-y, obj-m, obj-$(CONFIG_FOO), lib-y, lib-$(CONFIG_FOO)
	listRe = regexp.MustCompile(`^(obj|lib)-(y|m|\$\(CONFIG_[A-Za-z0-9_]+\))$`)
	// foo-y, foo-objs, foo-$(CONFIG_BAR), foo-m: members of composite object foo
	compositeRe = regexp.MustCompile(`^([A-Za-z0-9_\-]+)-(y|m|objs|\$\(CONFIG_[A-Za-z0-9_]+\))$`)
)

// cond is "y", "m" or a config symbol such as "CONFIG_VSOCKETS".
type entry struct {
	name string
	cond string
	lib  bool
}

type member struct {
	obj  string // relative path with .o
	cond string // "y" for unconditional members
}

type dirRules struct {
	entries    []entry
	composites map[string][]member
}

func condOf(s string) string {
	switch s {
	case "y", "m", "objs":
		if s == "objs" {
			return "y"
		}
		return s
	}
	return strings.TrimSuffix(strings.TrimPrefix(s, "$("), ")")
}

// parseMakefile reads the target lists and composite objects of one Kbuild
// makefile. Conditionals (ifeq/ifdef …) are ignored, so both branches count —
// a union, which is the safe direction. Tokens with variables are skipped;
// files only reachable through them stay unmapped (unknown).
func parseMakefile(text string) dirRules {
	r := dirRules{composites: map[string][]member{}}
	text = strings.ReplaceAll(text, "\\\n", " ")
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		m := assignRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		lhs, rhs := m[1], m[3]
		if lm := listRe.FindStringSubmatch(lhs); lm != nil {
			for _, tok := range strings.Fields(rhs) {
				if strings.Contains(tok, "$") || !strings.HasSuffix(tok, ".o") {
					continue // subdirectories ("foo/") are found by walking the tree
				}
				r.entries = append(r.entries, entry{name: strings.TrimSuffix(tok, ".o"), cond: condOf(lm[2]), lib: lm[1] == "lib"})
			}
			continue
		}
		if cm := compositeRe.FindStringSubmatch(lhs); cm != nil {
			switch {
			case cm[1] == "obj", cm[1] == "lib", cm[1] == "subdir", cm[1] == "always",
				strings.HasPrefix(cm[1], "ccflags"), strings.HasPrefix(cm[1], "asflags"):
				continue
			}
			for _, tok := range strings.Fields(rhs) {
				if strings.Contains(tok, "$") || !strings.HasSuffix(tok, ".o") {
					continue
				}
				r.composites[cm[1]] = append(r.composites[cm[1]], member{obj: tok, cond: condOf(cm[2])})
			}
		}
	}
	return r
}

// Config is a kernel .config: option name → value ("y", "m", a string, …).
// Options that are not set are absent.
type Config map[string]string

// ParseConfig reads a kernel .config file.
func ParseConfig(text string) Config {
	c := Config{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "CONFIG_") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			c[k] = strings.Trim(v, `"`)
		}
	}
	return c
}

// eval turns a condition into "y", "m" or "n" for this build.
func (c Config) eval(cond string) string {
	switch cond {
	case "y", "m":
		return cond
	}
	switch c[cond] {
	case "y":
		return "y"
	case "m":
		return "m"
	}
	return "n"
}

// KernelArch maps a Debian architecture to the kernel's arch/ directory.
func KernelArch(debArch string) string {
	switch debArch {
	case "amd64", "i386":
		return "x86"
	case "arm64":
		return "arm64"
	case "armhf", "armel":
		return "arm"
	case "ppc64el":
		return "powerpc"
	case "s390x":
		return "s390"
	case "riscv64":
		return "riscv"
	}
	return debArch
}

// BuildSourceMap parses every Kbuild makefile of a kernel tree and resolves
// each object with the build's .config. files maps the makefile path relative
// to the tree root ("net/vmw_vsock/Makefile") to its content; a directory's
// Kbuild file takes precedence over its Makefile, as in the kernel's own build.
// arch is the kernel architecture ("x86"): code under another arch/ directory
// is not compiled. tools/ is skipped entirely — it holds user-space programs
// (perf, bpftool …) shipped in other packages, so its files stay unknown.
func BuildSourceMap(files map[string]string, cfg Config, arch string) SourceMap {
	byDir := map[string]string{}
	for p, content := range files {
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		if dir == "tools" || strings.HasPrefix(dir, "tools/") {
			continue
		}
		switch base {
		case "Kbuild":
			byDir[dir] = content
		case "Makefile":
			if _, ok := byDir[dir]; !ok {
				byDir[dir] = content
			}
		}
	}
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	out := SourceMap{}
	for _, dir := range dirs {
		r := parseMakefile(byDir[dir])
		otherArch := strings.HasPrefix(dir, "arch/") && !(dir == "arch/"+arch || strings.HasPrefix(dir, "arch/"+arch+"/"))
		for _, e := range r.entries {
			config := ""
			if strings.HasPrefix(e.cond, "CONFIG_") {
				config = e.cond
			}
			var t Target
			switch v := cfg.eval(e.cond); {
			case otherArch:
				t = Target{Kind: KindAbsent, Config: "ARCH"}
			case v == "n":
				t = Target{Kind: KindAbsent, Config: config}
			case v == "y" || e.lib:
				t = Target{Kind: KindBuiltin, Config: config}
			default:
				t = Target{Kind: KindModule, Module: "kernel/" + path.Join(dir, e.name) + ".ko", Config: config}
			}
			members, composite := r.composites[e.name]
			if !composite {
				members = []member{{obj: e.name + ".o", cond: "y"}}
			}
			for _, mem := range members {
				mt := t
				// A conditional member whose option is off is not compiled,
				// whatever its composite object is.
				if mt.Kind != KindAbsent && cfg.eval(mem.cond) == "n" {
					mt = Target{Kind: KindAbsent, Config: mem.cond}
				}
				base := strings.TrimSuffix(mem.obj, ".o")
				for _, ext := range []string{".c", ".S"} {
					out.add(path.Join(dir, base+ext), mt)
				}
			}
		}
	}
	return out
}

// MarkShipped records which module targets exist in the kernel's module
// packages. modules holds module paths as in modules.dep without the
// compression suffix ("kernel/net/sctp/sctp.ko").
func (m SourceMap) MarkShipped(modules map[string]bool) {
	for file, ts := range m {
		for i := range ts {
			if ts[i].Kind == KindModule && modules[ts[i].Module] {
				ts[i].Shipped = true
			}
		}
		m[file] = ts
	}
}
