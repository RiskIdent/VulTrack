package kernelintel

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// maxMakefileBytes bounds a single makefile read from a package.
const maxMakefileBytes = 1 << 20

// ExtractMakefiles reads a Debian package (ar archive) and returns the Kbuild
// makefiles of the kernel tree it ships, keyed by their path relative to the
// tree root (the "/usr/src/<name>/" prefix removed), and the kernel .config if
// the package has one (flavour headers packages do).
func ExtractMakefiles(deb io.Reader) (map[string]string, error) {
	return readDataMember(deb, func(h *tar.Header) bool {
		base := path.Base(h.Name)
		return base == "Makefile" || base == "Kbuild" || base == ".config"
	})
}

// ListModules returns the module paths a linux-modules package ships, relative
// to /lib/modules/<release>/ and without compression suffix
// ("kernel/net/sctp/sctp.ko").
func ListModules(deb io.Reader) (map[string]bool, error) {
	out := map[string]bool{}
	_, err := readDataMember(deb, func(h *tar.Header) bool {
		name := strings.TrimPrefix(h.Name, "./")
		if !strings.HasPrefix(name, "lib/modules/") && !strings.HasPrefix(name, "usr/lib/modules/") {
			return false
		}
		name = strings.TrimPrefix(strings.TrimPrefix(name, "usr/"), "lib/modules/")
		i := strings.IndexByte(name, '/')
		if i < 0 {
			return false
		}
		rel := name[i+1:]
		for _, ext := range []string{".zst", ".xz", ".gz"} {
			rel = strings.TrimSuffix(rel, ext)
		}
		if strings.HasSuffix(rel, ".ko") {
			out[rel] = true
		}
		return false // names only; contents are never read
	})
	if err != nil && err != errNoFiles {
		return nil, err
	}
	return out, nil
}

var errNoFiles = errors.New("package contains no matching files")

// readDataMember walks the data member of a Debian package and returns the
// content of the regular files want accepts, keyed by tree-relative path
// (or by package path when the file is not under /usr/src/<name>/).
func readDataMember(deb io.Reader, want func(*tar.Header) bool) (map[string]string, error) {
	br := bufio.NewReader(deb)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, fmt.Errorf("read ar magic: %w", err)
	}
	if string(magic) != "!<arch>\n" {
		return nil, errors.New("not a Debian package (ar archive)")
	}
	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("package has no data member")
			}
			return nil, fmt.Errorf("read ar header: %w", err)
		}
		name := strings.TrimRight(strings.TrimSpace(string(hdr[0:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("bad ar member size for %q", name)
		}
		body := io.LimitReader(br, size)
		if strings.HasPrefix(name, "data.tar") {
			return readTar(name, body, want)
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			return nil, err
		}
		if size%2 == 1 { // ar members are 2-byte aligned
			if _, err := br.Discard(1); err != nil {
				return nil, err
			}
		}
	}
}

func readTar(member string, r io.Reader, want func(*tar.Header) bool) (map[string]string, error) {
	var tr *tar.Reader
	switch path.Ext(member) {
	case ".zst":
		d, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer d.Close()
		tr = tar.NewReader(d)
	case ".xz":
		d, err := xz.NewReader(r)
		if err != nil {
			return nil, err
		}
		tr = tar.NewReader(d)
	case ".gz":
		d, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer d.Close()
		tr = tar.NewReader(d)
	case ".tar":
		tr = tar.NewReader(r)
	default:
		return nil, fmt.Errorf("unsupported data member %q", member)
	}

	out := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read package contents: %w", err)
		}
		if h.Typeflag != tar.TypeReg || !want(h) {
			continue
		}
		rel, ok := treeRelative(h.Name)
		if !ok {
			rel = strings.TrimPrefix(h.Name, "./")
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, io.LimitReader(tr, maxMakefileBytes)); err != nil {
			return nil, err
		}
		out[rel] = buf.String()
	}
	if len(out) == 0 {
		return nil, errNoFiles
	}
	return out, nil
}

// treeRelative turns "./usr/src/linux-headers-6.8.0-147/net/Makefile" into
// "net/Makefile".
func treeRelative(name string) (string, bool) {
	name = strings.TrimPrefix(name, "./")
	if !strings.HasPrefix(name, "usr/src/") {
		return "", false
	}
	rest := strings.TrimPrefix(name, "usr/src/")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "", false
	}
	return rest[i+1:], true
}
