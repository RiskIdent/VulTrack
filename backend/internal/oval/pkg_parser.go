package oval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/services"
)

// PkgParser imports Canonical's package vulnerability feed
// (com.ubuntu.<series>.pkg.json.xz), the dataset `pro cves` evaluates.
//
// The feed is a single JSON object of ~170 MB uncompressed, so it is streamed
// entry by entry rather than unmarshalled as a whole.
type PkgParser struct {
	pkgService *services.PkgFeedService
}

// NewPkgParser creates a new PkgParser
func NewPkgParser(pkgService *services.PkgFeedService) *PkgParser {
	return &PkgParser{pkgService: pkgService}
}

// ============================================================================
// FEED STRUCTURES
// ============================================================================

// pkgSourceVersion is one published version of a source package.
type pkgSourceVersion struct {
	// BinaryPackages maps binary package name -> its version in this source
	// version. It can legitimately be empty for a few source packages.
	BinaryPackages map[string]string `json:"binary_packages"`
	Pocket         string            `json:"pocket"`
}

// pkgFeedPackage is one source package entry of the feed.
type pkgFeedPackage struct {
	SourceVersions map[string]pkgSourceVersion `json:"source_versions"`
	CVEs           map[string]struct {
		SourceFixedVersion *string `json:"source_fixed_version"`
		Status             string  `json:"status"`
	} `json:"cves"`
}

// pkgFeedCVE is one entry of security_issues.cves.
type pkgFeedCVE struct {
	Description    string   `json:"description"`
	PublishedAt    string   `json:"published_at"`
	Notes          []string `json:"notes"`
	CVSSSeverity   *string  `json:"cvss_severity"`
	CVSSScore      *float64 `json:"cvss_score"`
	UbuntuPriority *string  `json:"ubuntu_priority"`
	Mitigation     *string  `json:"mitigation"`
}

// ============================================================================
// PARSING
// ============================================================================

// ParseAndStore streams the feed from r and stores it for the given source.
func (p *PkgParser) ParseAndStore(ctx context.Context, sourceID int64, r io.Reader) (*services.PkgImportStats, error) {
	dec := json.NewDecoder(r)

	// Enter the top-level object.
	if tok, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("failed to read feed: %w", err)
	} else if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("unexpected feed root: %v", tok)
	}

	imp, err := p.pkgService.BeginImport(ctx, sourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to begin feed import: %w", err)
	}
	defer imp.Rollback(ctx)

	var format, release, publishedAt string
	sawPackages, sawIssues := false, false

	for dec.More() {
		key, err := decodeObjectKey(dec)
		if err != nil {
			return nil, err
		}

		switch key {
		case "format":
			if err := dec.Decode(&format); err != nil {
				return nil, fmt.Errorf("failed to read format: %w", err)
			}
		case "release":
			if err := dec.Decode(&release); err != nil {
				return nil, fmt.Errorf("failed to read release: %w", err)
			}
		case "published_at":
			if err := dec.Decode(&publishedAt); err != nil {
				return nil, fmt.Errorf("failed to read published_at: %w", err)
			}
		case "packages":
			if err := p.streamPackages(ctx, dec, imp); err != nil {
				return nil, err
			}
			sawPackages = true
		case "security_issues":
			if err := p.streamSecurityIssues(ctx, dec, imp); err != nil {
				return nil, err
			}
			sawIssues = true
		default:
			// Unknown top-level member: skip its value so the stream stays aligned.
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("failed to skip %q: %w", key, err)
			}
		}
	}

	if !sawPackages {
		return nil, fmt.Errorf("feed has no packages section")
	}
	if !sawIssues {
		return nil, fmt.Errorf("feed has no security_issues section")
	}

	log.Debug().
		Str("format", format).
		Str("release", release).
		Str("publishedAt", publishedAt).
		Msg("Parsed package vulnerability feed")

	stats, err := imp.Commit(ctx)
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// streamPackages consumes the "packages" object one source package at a time.
func (p *PkgParser) streamPackages(ctx context.Context, dec *json.Decoder, imp *services.PkgImport) error {
	if err := expectDelim(dec, '{', "packages"); err != nil {
		return err
	}

	for dec.More() {
		sourcePackage, err := decodeObjectKey(dec)
		if err != nil {
			return err
		}

		var pkg pkgFeedPackage
		if err := dec.Decode(&pkg); err != nil {
			return fmt.Errorf("failed to read package %q: %w", sourcePackage, err)
		}

		isKernel := false
		for _, sv := range pkg.SourceVersions {
			for binaryPackage := range sv.BinaryPackages {
				if isKernelBinary(binaryPackage) {
					isKernel = true
					break
				}
			}
			if isKernel {
				break
			}
		}

		if err := imp.AddSourcePackage(ctx, services.PkgSourcePackage{
			Name:     sourcePackage,
			IsKernel: isKernel,
		}); err != nil {
			return err
		}

		for sourceVersion, sv := range pkg.SourceVersions {
			for binaryPackage, binaryVersion := range sv.BinaryPackages {
				if err := imp.AddBinaryVersion(ctx, services.PkgBinaryVersion{
					SourcePackage: sourcePackage,
					SourceVersion: sourceVersion,
					BinaryPackage: binaryPackage,
					BinaryVersion: binaryVersion,
					Pocket:        sv.Pocket,
				}); err != nil {
					return err
				}
			}
		}

		for cveID, cve := range pkg.CVEs {
			status := services.PkgCVEStatus{
				SourcePackage: sourcePackage,
				CVEID:         cveID,
				Status:        cve.Status,
			}
			if cve.SourceFixedVersion != nil {
				status.SourceFixedVersion = *cve.SourceFixedVersion
			}
			if err := imp.AddCVEStatus(ctx, status); err != nil {
				return err
			}
		}
	}

	return expectDelim(dec, '}', "packages")
}

// streamSecurityIssues consumes "security_issues", of which only the "cves"
// member is stored; USN details are already covered by the USN OVAL source.
func (p *PkgParser) streamSecurityIssues(ctx context.Context, dec *json.Decoder, imp *services.PkgImport) error {
	if err := expectDelim(dec, '{', "security_issues"); err != nil {
		return err
	}

	for dec.More() {
		key, err := decodeObjectKey(dec)
		if err != nil {
			return err
		}

		if key != "cves" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return fmt.Errorf("failed to skip security_issues.%s: %w", key, err)
			}
			continue
		}

		if err := expectDelim(dec, '{', "security_issues.cves"); err != nil {
			return err
		}
		for dec.More() {
			cveID, err := decodeObjectKey(dec)
			if err != nil {
				return err
			}
			var cve pkgFeedCVE
			if err := dec.Decode(&cve); err != nil {
				return fmt.Errorf("failed to read CVE %q: %w", cveID, err)
			}
			if err := imp.AddCVEMetadata(ctx, services.PkgCVEMetadata{
				CVEID:          cveID,
				UbuntuPriority: derefString(cve.UbuntuPriority),
				CVSSScore:      cve.CVSSScore,
				CVSSSeverity:   derefString(cve.CVSSSeverity),
				Description:    strings.TrimSpace(cve.Description),
				Notes:          cve.Notes,
				Mitigation:     strings.TrimSpace(derefString(cve.Mitigation)),
				PublishedAt:    parseFeedTime(cve.PublishedAt),
			}); err != nil {
				return err
			}
		}
		if err := expectDelim(dec, '}', "security_issues.cves"); err != nil {
			return err
		}
	}

	return expectDelim(dec, '}', "security_issues")
}

// isKernelBinary reports whether a binary package name belongs to a Linux kernel
// source package.
//
// This is what separates the kernel source packages (which ship
// linux-image-*/linux-modules-*) from unrelated packages that merely start with
// "linux", such as linux-firmware and linuxptp.
func isKernelBinary(name string) bool {
	return strings.HasPrefix(name, "linux-image-") ||
		strings.HasPrefix(name, "linux-modules-")
}

// ============================================================================
// STREAMING HELPERS
// ============================================================================

// decodeObjectKey reads the next token and returns it as an object key.
func decodeObjectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("failed to read object key: %w", err)
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected an object key, got %v", tok)
	}
	return key, nil
}

// expectDelim consumes one delimiter token and fails if it is not the expected one.
func expectDelim(dec *json.Decoder, want json.Delim, what string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", what, err)
	}
	got, ok := tok.(json.Delim)
	if !ok || got != want {
		return fmt.Errorf("expected %q in %s, got %v", want, what, tok)
	}
	return nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// parseFeedTime parses the feed's timestamps, which are RFC 3339 but appear both
// with and without an offset.
func parseFeedTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, value); err == nil {
			return &t
		}
	}
	log.Debug().Str("value", value).Msg("Unparsable timestamp in package vulnerability feed")
	return nil
}
