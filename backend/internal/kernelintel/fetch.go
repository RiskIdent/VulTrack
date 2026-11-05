package kernelintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Fetcher downloads CVE records and Ubuntu kernel packages.
type Fetcher struct {
	HTTP *http.Client
	// CVEAPI is the CVE Services record endpoint; the CVE ID is appended.
	CVEAPI string
	// PackageURL returns the download URL of a Debian package file name.
	PackageURL func(file string) string
}

// NewFetcher returns a Fetcher for the public CVE Services API and the Ubuntu
// archive as kept by Launchpad (which, unlike the archive mirrors, keeps every
// published kernel build).
func NewFetcher() *Fetcher {
	return &Fetcher{
		HTTP:   &http.Client{Timeout: 15 * time.Minute},
		CVEAPI: "https://cveawg.mitre.org/api/cve/",
		PackageURL: func(file string) string {
			return "https://launchpad.net/ubuntu/+archive/primary/+files/" + file
		},
	}
}

// ErrNotFound is returned for a CVE record or package that does not exist.
var ErrNotFound = errors.New("not found")

// CVEFiles is what a CVE record says about the affected kernel code.
type CVEFiles struct {
	Assigner     string
	ProgramFiles []string
}

// FetchCVEFiles reads the affected program files of a CVE record.
func (f *Fetcher) FetchCVEFiles(ctx context.Context, cveID string) (CVEFiles, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.CVEAPI+cveID, nil)
	if err != nil {
		return CVEFiles{}, err
	}
	req.Header.Set("User-Agent", "VulTrack")
	req.Header.Set("Accept", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return CVEFiles{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return CVEFiles{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return CVEFiles{}, fmt.Errorf("CVE API: HTTP %d", resp.StatusCode)
	}
	return ParseCVERecord(io.LimitReader(resp.Body, 4<<20))
}

// ParseCVERecord extracts the program files of the Linux entries of a CVE
// record (CVE JSON 5).
func ParseCVERecord(r io.Reader) (CVEFiles, error) {
	var rec struct {
		CVEMetadata struct {
			AssignerShortName string `json:"assignerShortName"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA struct {
				Affected []struct {
					Vendor       string   `json:"vendor"`
					Product      string   `json:"product"`
					ProgramFiles []string `json:"programFiles"`
				} `json:"affected"`
			} `json:"cna"`
		} `json:"containers"`
	}
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return CVEFiles{}, fmt.Errorf("decode CVE record: %w", err)
	}
	set := map[string]bool{}
	for _, a := range rec.Containers.CNA.Affected {
		if !strings.EqualFold(a.Product, "linux") {
			continue
		}
		for _, p := range a.ProgramFiles {
			p = strings.TrimPrefix(strings.TrimSpace(p), "./")
			if p != "" {
				set[p] = true
			}
		}
	}
	files := make([]string, 0, len(set))
	for p := range set {
		files = append(files, p)
	}
	sort.Strings(files)
	return CVEFiles{Assigner: rec.CVEMetadata.AssignerShortName, ProgramFiles: files}, nil
}

// abiRe takes the ABI ("6.8.0-147") from a kernel release ("6.8.0-147-generic").
var abiRe = regexp.MustCompile(`^(\d+\.\d+\.\d+-\d+)`)

// BuildInput identifies a kernel build as running on a server.
type BuildInput struct {
	Release string // uname -r, e.g. 6.8.0-147-generic
	Version string // version of linux-modules-<release>, e.g. 6.8.0-147.147
	Source  string // source package of linux-modules-<release>, e.g. linux, linux-hwe-6.11
	Arch    string // Debian architecture, e.g. amd64
}

// HeadersPackage is the name of the architecture-independent headers package
// holding the kernel tree's makefiles.
func (in BuildInput) HeadersPackage() (string, error) {
	m := abiRe.FindStringSubmatch(in.Release)
	if m == nil {
		return "", fmt.Errorf("cannot read the ABI from kernel release %q", in.Release)
	}
	if in.Source == "linux" || in.Source == "" {
		return "linux-headers-" + m[1], nil
	}
	return in.Source + "-headers-" + m[1], nil
}

// BuildResult is the outcome of reading one kernel build.
type BuildResult struct {
	HeadersPackage  string
	Map             SourceMap
	ModulesVerified bool
	ShippedModules  int
}

// FetchBuild downloads the headers packages of a kernel build, maps its source
// files and, when the module packages are available, marks which modules they
// ship. Packages are streamed; only makefiles, .config and file names are kept.
func (f *Fetcher) FetchBuild(ctx context.Context, in BuildInput) (*BuildResult, error) {
	headersPkg, err := in.HeadersPackage()
	if err != nil {
		return nil, err
	}
	flavour, err := f.packageFiles(ctx, fmt.Sprintf("linux-headers-%s_%s_%s.deb", in.Release, in.Version, in.Arch), ExtractMakefiles)
	if err != nil {
		return nil, fmt.Errorf("flavour headers: %w", err)
	}
	cfgText, ok := flavour[".config"]
	if !ok {
		return nil, errors.New("flavour headers package has no .config")
	}
	tree, err := f.packageFiles(ctx, fmt.Sprintf("%s_%s_all.deb", headersPkg, in.Version), ExtractMakefiles)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", headersPkg, err)
	}
	// The flavour package carries a few makefiles of its own; the tree wins.
	for p, c := range flavour {
		if _, exists := tree[p]; !exists && p != ".config" {
			tree[p] = c
		}
	}

	res := &BuildResult{HeadersPackage: headersPkg}
	res.Map = BuildSourceMap(tree, ParseConfig(cfgText), KernelArch(in.Arch))

	modules := map[string]bool{}
	mainOK := true
	for _, name := range []string{"linux-modules-", "linux-modules-extra-"} {
		file := fmt.Sprintf("%s%s_%s_%s.deb", name, in.Release, in.Version, in.Arch)
		mods, err := f.packageModules(ctx, file)
		switch {
		case errors.Is(err, ErrNotFound) && name == "linux-modules-extra-":
			// Not every kernel has an extra package.
		case err != nil:
			mainOK = false
		default:
			for m := range mods {
				modules[m] = true
			}
		}
	}
	if mainOK && len(modules) > 0 {
		res.Map.MarkShipped(modules)
		res.ModulesVerified = true
		res.ShippedModules = len(modules)
	}
	return res, nil
}

func (f *Fetcher) open(ctx context.Context, file string) (io.ReadCloser, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*10) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.PackageURL(file), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "VulTrack")
		resp, err := f.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, fmt.Errorf("%s: %w", file, ErrNotFound)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: HTTP %d", file, resp.StatusCode)
			continue
		}
		return resp.Body, nil
	}
	return nil, lastErr
}

func (f *Fetcher) packageFiles(ctx context.Context, file string, read func(io.Reader) (map[string]string, error)) (map[string]string, error) {
	body, err := f.open(ctx, file)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return read(body)
}

func (f *Fetcher) packageModules(ctx context.Context, file string) (map[string]bool, error) {
	body, err := f.open(ctx, file)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return ListModules(body)
}
