package scanner

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// CompareEVR compares two EVR (Epoch:Version-Release) strings
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func CompareEVR(a, b string, packageManager string) int {
	switch packageManager {
	case "rpm":
		return CompareRPM(a, b)
	case "dpkg":
		return CompareDpkg(a, b)
	default:
		// Default to dpkg-style comparison
		return CompareDpkg(a, b)
	}
}

// ============================================================================
// DPKG VERSION COMPARISON (Debian/Ubuntu)
// ============================================================================

// CompareDpkg compares two Debian package versions
// Format: [epoch:]upstream-version[-debian-revision]
func CompareDpkg(a, b string) int {
	epochA, upstreamA, revisionA := parseDpkgVersion(a)
	epochB, upstreamB, revisionB := parseDpkgVersion(b)

	// Compare epochs
	if epochA != epochB {
		if epochA < epochB {
			return -1
		}
		return 1
	}

	// Compare upstream versions
	if cmp := compareDpkgPart(upstreamA, upstreamB); cmp != 0 {
		return cmp
	}

	// Compare debian revisions
	return compareDpkgPart(revisionA, revisionB)
}

// parseDpkgVersion parses a Debian version string into epoch, upstream, and revision
func parseDpkgVersion(version string) (epoch int, upstream, revision string) {
	// Handle empty version
	if version == "" {
		return 0, "", ""
	}

	// Extract epoch
	if idx := strings.Index(version, ":"); idx != -1 {
		e, err := strconv.Atoi(version[:idx])
		if err == nil {
			epoch = e
		}
		version = version[idx+1:]
	}

	// Extract debian revision (last hyphen)
	if idx := strings.LastIndex(version, "-"); idx != -1 {
		upstream = version[:idx]
		revision = version[idx+1:]
	} else {
		upstream = version
		revision = ""
	}

	return epoch, upstream, revision
}

// compareDpkgPart compares two version parts using Debian comparison rules
func compareDpkgPart(a, b string) int {
	i, j := 0, 0

	for i < len(a) || j < len(b) {
		// Compare non-digit parts lexically
		for i < len(a) && !unicode.IsDigit(rune(a[i])) {
			if j >= len(b) {
				// a has more non-digits, a > b (unless it's ~)
				if a[i] == '~' {
					return -1
				}
				return 1
			}
			if !unicode.IsDigit(rune(b[j])) {
				cmp := compareDpkgChar(a[i], b[j])
				if cmp != 0 {
					return cmp
				}
				i++
				j++
			} else {
				// a has non-digit, b has digit
				if a[i] == '~' {
					return -1
				}
				return 1
			}
		}

		for j < len(b) && !unicode.IsDigit(rune(b[j])) {
			if b[j] == '~' {
				return 1
			}
			return -1
		}

		// Compare digit parts numerically
		numA := 0
		for i < len(a) && unicode.IsDigit(rune(a[i])) {
			numA = numA*10 + int(a[i]-'0')
			i++
		}

		numB := 0
		for j < len(b) && unicode.IsDigit(rune(b[j])) {
			numB = numB*10 + int(b[j]-'0')
			j++
		}

		if numA != numB {
			if numA < numB {
				return -1
			}
			return 1
		}
	}

	return 0
}

// compareDpkgChar compares two characters using Debian ordering rules
// Order: ~ < empty < alphanumeric < everything else
func compareDpkgChar(a, b byte) int {
	orderA := dpkgCharOrder(a)
	orderB := dpkgCharOrder(b)
	if orderA < orderB {
		return -1
	}
	if orderA > orderB {
		return 1
	}
	return 0
}

// dpkgCharOrder returns the sort order for a character
func dpkgCharOrder(c byte) int {
	if c == '~' {
		return -1
	}
	if c == 0 {
		return 0
	}
	if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) {
		return int(c)
	}
	return int(c) + 256
}

// ============================================================================
// RPM VERSION COMPARISON (RHEL/CentOS/Oracle/SUSE)
// ============================================================================

// CompareRPM compares two RPM package versions
// Format: [epoch:]version[-release]
func CompareRPM(a, b string) int {
	epochA, versionA, releaseA := parseRPMVersion(a)
	epochB, versionB, releaseB := parseRPMVersion(b)

	// Compare epochs
	if epochA != epochB {
		if epochA < epochB {
			return -1
		}
		return 1
	}

	// Compare versions
	if cmp := compareRPMPart(versionA, versionB); cmp != 0 {
		return cmp
	}

	// Compare releases
	return compareRPMPart(releaseA, releaseB)
}

// parseRPMVersion parses an RPM version string
func parseRPMVersion(version string) (epoch int, ver, release string) {
	if version == "" {
		return 0, "", ""
	}

	// Extract epoch
	if idx := strings.Index(version, ":"); idx != -1 {
		e, err := strconv.Atoi(version[:idx])
		if err == nil {
			epoch = e
		}
		version = version[idx+1:]
	}

	// Extract release
	if idx := strings.LastIndex(version, "-"); idx != -1 {
		ver = version[:idx]
		release = version[idx+1:]
	} else {
		ver = version
		release = ""
	}

	return epoch, ver, release
}

// compareRPMPart compares two RPM version parts
func compareRPMPart(a, b string) int {
	// Split into segments
	segmentsA := splitRPMVersion(a)
	segmentsB := splitRPMVersion(b)

	for i := 0; i < len(segmentsA) || i < len(segmentsB); i++ {
		var segA, segB string
		if i < len(segmentsA) {
			segA = segmentsA[i]
		}
		if i < len(segmentsB) {
			segB = segmentsB[i]
		}

		// Empty segment is less than non-empty
		if segA == "" && segB != "" {
			return -1
		}
		if segA != "" && segB == "" {
			return 1
		}

		// Both numeric?
		numA, errA := strconv.Atoi(segA)
		numB, errB := strconv.Atoi(segB)

		if errA == nil && errB == nil {
			// Both numeric - compare numerically
			if numA < numB {
				return -1
			}
			if numA > numB {
				return 1
			}
		} else if errA == nil {
			// A is numeric, B is not - numeric comes first
			return -1
		} else if errB == nil {
			// B is numeric, A is not
			return 1
		} else {
			// Both alphabetic - compare lexically
			if segA < segB {
				return -1
			}
			if segA > segB {
				return 1
			}
		}
	}

	return 0
}

// splitRPMVersion splits an RPM version into alphanumeric segments
var rpmSegmentRegex = regexp.MustCompile(`[a-zA-Z]+|[0-9]+`)

func splitRPMVersion(version string) []string {
	return rpmSegmentRegex.FindAllString(version, -1)
}

// ============================================================================
// OVAL OPERATION HELPERS
// ============================================================================

// EvaluateVersionOperation evaluates an OVAL version comparison operation
func EvaluateVersionOperation(installedVersion, fixedVersion, operation, packageManager string) bool {
	if installedVersion == "" || fixedVersion == "" {
		return false
	}

	cmp := CompareEVR(installedVersion, fixedVersion, packageManager)

	switch operation {
	case "less than":
		return cmp < 0
	case "less than or equal":
		return cmp <= 0
	case "equals":
		return cmp == 0
	case "not equal":
		return cmp != 0
	case "greater than":
		return cmp > 0
	case "greater than or equal":
		return cmp >= 0
	default:
		// Unknown operation - assume vulnerable to be safe
		return true
	}
}

// kernelReleaseEVR splits a kernel release into the "<version>-<abi>" part and
// the flavour suffix, mirroring the regex Canonical uses in the OVAL variable
// "kernel version in evr format". The flavour must start with a letter so that
// the ABI number is captured in full ("6.8.0-79-generic" must not yield
// "6.8.0-7" with "9" treated as part of the flavour).
var kernelReleaseEVR = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*-[0-9]+)-[a-zA-Z][\w.-]*$`)

// KernelEVR converts a kernel release as reported by `uname -r` into the EVR
// string that OVAL variable_test states are compared against.
//
//	"6.8.0-79-generic" -> "0:6.8.0-79"
//
// Ubuntu's OVAL derives this value from the running kernel and compares it with
// the fixed kernel package version (e.g. "6.8.0-84.84"). Comparing the raw
// `uname -r` string instead would put the flavour ("generic") into the Debian
// revision field and compare it against a number, which silently produces both
// wrong "affected" and wrong "not affected" verdicts.
//
// Returns "" when the release does not have the expected shape; callers must
// then treat kernel version tests as not matching rather than guessing.
func KernelEVR(release string) string {
	match := kernelReleaseEVR.FindStringSubmatch(strings.TrimSpace(release))
	if match == nil {
		return ""
	}
	return "0:" + match[1]
}
