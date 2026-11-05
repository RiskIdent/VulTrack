package kernelintel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const testConfig = `
# CONFIG_FOO is not set
CONFIG_VSOCKETS=m
CONFIG_VIRTIO_VSOCKETS=m
CONFIG_INET=y
CONFIG_IP_SCTP=m
CONFIG_SCTP_COOKIE_HMAC_MD5=y
CONFIG_SCTP_DBG_OBJCNT=n
CONFIG_EXT4_FS=y
CONFIG_LOCALVERSION="-generic"
`

var testTree = map[string]string{
	// composite module with conditional members and a continuation line
	"net/sctp/Makefile": `
obj-$(CONFIG_IP_SCTP) += sctp.o
sctp-y := sm_statetable.o socket.o \
	  ulpqueue.o
sctp-$(CONFIG_SCTP_DBG_OBJCNT) += objcnt.o
sctp-$(CONFIG_SCTP_COOKIE_HMAC_MD5) += auth.o
ifeq ($(CONFIG_FOO),y)
sctp-y += foo_only.o
endif
`,
	// the Kbuild file wins over the Makefile of the same directory
	"net/vmw_vsock/Kbuild": `
obj-$(CONFIG_VSOCKETS) += vsock.o
obj-$(CONFIG_VIRTIO_VSOCKETS) += vmw_vsock_virtio_transport.o
vsock-y += af_vsock.o vsock_addr.o
vmw_vsock_virtio_transport-y += virtio_transport.o
`,
	"net/vmw_vsock/Makefile": `obj-y += wrong.o`,
	"net/ipv4/Makefile": `
obj-y := tcp.o tcp_input.o
obj-$(CONFIG_FOO) += fou.o
obj-$(CONFIG_INET) += $(VAR)/x.o  # variable tokens are skipped
`,
	"fs/ext4/Makefile": `
obj-$(CONFIG_EXT4_FS) += ext4.o
ext4-y := inode.o super.o
`,
	"lib/Makefile":         `lib-y += string.o`,
	"arch/arm64/Makefile":  `obj-y += arm_only.o`,
	"arch/x86/Makefile":    `obj-y += x86_only.o`,
	"tools/perf/Makefile":  `obj-y += perf_tool.o`,
	"drivers/foo/Makefile": `obj-m += always_mod.o`,
}

func TestBuildSourceMap(t *testing.T) {
	m := BuildSourceMap(testTree, ParseConfig(testConfig), KernelArch("amd64"))
	want := map[string][]Target{
		"net/sctp/socket.c":        {{Kind: KindModule, Module: "kernel/net/sctp/sctp.ko", Config: "CONFIG_IP_SCTP"}},
		"net/sctp/ulpqueue.c":      {{Kind: KindModule, Module: "kernel/net/sctp/sctp.ko", Config: "CONFIG_IP_SCTP"}},
		"net/sctp/objcnt.c":        {{Kind: KindAbsent, Config: "CONFIG_SCTP_DBG_OBJCNT"}},
		"net/sctp/auth.c":          {{Kind: KindModule, Module: "kernel/net/sctp/sctp.ko", Config: "CONFIG_IP_SCTP"}},
		"net/sctp/foo_only.c":      {{Kind: KindModule, Module: "kernel/net/sctp/sctp.ko", Config: "CONFIG_IP_SCTP"}}, // conditionals are a union
		"net/vmw_vsock/af_vsock.c": {{Kind: KindModule, Module: "kernel/net/vmw_vsock/vsock.ko", Config: "CONFIG_VSOCKETS"}},
		"net/vmw_vsock/virtio_transport.c": {{Kind: KindModule,
			Module: "kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko", Config: "CONFIG_VIRTIO_VSOCKETS"}},
		"net/ipv4/tcp.c":           {{Kind: KindBuiltin}},
		"net/ipv4/fou.c":           {{Kind: KindAbsent, Config: "CONFIG_FOO"}},
		"fs/ext4/inode.c":          {{Kind: KindBuiltin, Config: "CONFIG_EXT4_FS"}},
		"lib/string.c":             {{Kind: KindBuiltin}},
		"arch/arm64/arm_only.c":    {{Kind: KindAbsent, Config: "ARCH"}},
		"arch/x86/x86_only.c":      {{Kind: KindBuiltin}},
		"drivers/foo/always_mod.c": {{Kind: KindModule, Module: "kernel/drivers/foo/always_mod.ko"}},
	}
	for file, ts := range want {
		if got := m[file]; !reflect.DeepEqual(got, ts) {
			t.Errorf("%s: got %+v, want %+v", file, got, ts)
		}
	}
	for _, unmapped := range []string{"net/vmw_vsock/wrong.c", "tools/perf/perf_tool.c", "net/ipv4/x.c", "mm/memory.c"} {
		if ts, ok := m[unmapped]; ok {
			t.Errorf("%s must stay unmapped, got %+v", unmapped, ts)
		}
	}

	m.MarkShipped(map[string]bool{"kernel/net/sctp/sctp.ko": true})
	if !m["net/sctp/socket.c"][0].Shipped {
		t.Error("sctp.ko is shipped")
	}
	if m["net/vmw_vsock/af_vsock.c"][0].Shipped {
		t.Error("vsock.ko is not in the shipped list")
	}
}

func TestParseCVERecord(t *testing.T) {
	rec := `{
	  "cveMetadata": {"assignerShortName": "Linux"},
	  "containers": {"cna": {"affected": [
	    {"vendor": "Linux", "product": "Linux", "programFiles": ["net/sctp/socket.c", "./net/sctp/sm_statefuns.c"]},
	    {"vendor": "Linux", "product": "Linux", "programFiles": ["net/sctp/socket.c"]},
	    {"vendor": "Other", "product": "tool", "programFiles": ["x.c"]}
	  ]}}
	}`
	got, err := ParseCVERecord(strings.NewReader(rec))
	if err != nil {
		t.Fatal(err)
	}
	if got.Assigner != "Linux" || !reflect.DeepEqual(got.ProgramFiles, []string{"net/sctp/sm_statefuns.c", "net/sctp/socket.c"}) {
		t.Errorf("got %+v", got)
	}
}

func TestHeadersPackage(t *testing.T) {
	for _, c := range []struct{ release, source, want string }{
		{"6.8.0-147-generic", "linux", "linux-headers-6.8.0-147"},
		{"6.8.0-147-generic", "", "linux-headers-6.8.0-147"},
		{"6.11.0-29-generic", "linux-hwe-6.11", "linux-hwe-6.11-headers-6.11.0-29"},
	} {
		got, err := BuildInput{Release: c.release, Source: c.source}.HeadersPackage()
		if err != nil || got != c.want {
			t.Errorf("%s/%s: %q %v, want %q", c.release, c.source, got, err, c.want)
		}
	}
	if _, err := (BuildInput{Release: "weird"}).HeadersPackage(); err == nil {
		t.Error("a release without ABI must fail")
	}
}

// makeDeb builds a minimal Debian package (ar archive with a gzip data member).
func makeDeb(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()

	var deb bytes.Buffer
	deb.WriteString("!<arch>\n")
	member := func(name string, body []byte) {
		fmt.Fprintf(&deb, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", name, "0", "0", "0", "100644", len(body))
		deb.Write(body)
		if len(body)%2 == 1 {
			deb.WriteByte('\n')
		}
	}
	member("debian-binary", []byte("2.0\n"))
	member("control.tar.gz", []byte("x")) // odd size: tests the padding
	member("data.tar.gz", data.Bytes())
	return deb.Bytes()
}

func TestFetchBuild(t *testing.T) {
	tree := map[string]string{}
	for p, c := range testTree {
		tree["./usr/src/linux-headers-6.8.0-147/"+p] = c
	}
	tree["./usr/src/linux-headers-6.8.0-147/net/sctp/socket.c"] = "not a makefile"
	pkgs := map[string][]byte{
		"linux-headers-6.8.0-147-generic_6.8.0-147.147_amd64.deb": makeDeb(t, map[string]string{
			"./usr/src/linux-headers-6.8.0-147-generic/.config":           testConfig,
			"./usr/src/linux-headers-6.8.0-147-generic/net/ipv4/Makefile": "obj-y += overridden.o",
		}),
		"linux-headers-6.8.0-147_6.8.0-147.147_all.deb": makeDeb(t, tree),
		"linux-modules-6.8.0-147-generic_6.8.0-147.147_amd64.deb": makeDeb(t, map[string]string{
			"./lib/modules/6.8.0-147-generic/kernel/net/sctp/sctp.ko.zst": "",
			"./lib/modules/6.8.0-147-generic/modules.dep":                 "",
		}),
		// no linux-modules-extra: 404 is fine
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := pkgs[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()

	f := &Fetcher{HTTP: srv.Client(), PackageURL: func(file string) string { return srv.URL + "/" + file }}
	res, err := f.FetchBuild(context.Background(), BuildInput{Release: "6.8.0-147-generic", Version: "6.8.0-147.147", Source: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ModulesVerified || res.ShippedModules != 1 || res.HeadersPackage != "linux-headers-6.8.0-147" {
		t.Errorf("result %+v", res)
	}
	if got := res.Map["net/sctp/socket.c"]; len(got) != 1 || !got[0].Shipped {
		t.Errorf("socket.c: %+v", got)
	}
	if _, ok := res.Map["net/ipv4/overridden.c"]; ok {
		t.Error("the tree's makefile must win over the flavour package's")
	}

	delete(pkgs, "linux-modules-6.8.0-147-generic_6.8.0-147.147_amd64.deb")
	res, err = f.FetchBuild(context.Background(), BuildInput{Release: "6.8.0-147-generic", Version: "6.8.0-147.147", Source: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ModulesVerified || res.Map["net/sctp/socket.c"][0].Shipped {
		t.Error("without the modules package nothing is verified")
	}
}
