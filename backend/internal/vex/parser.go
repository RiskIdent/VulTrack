package vex

import (
	"encoding/json"
	"strings"
)

// ParseFile parses a single OpenVEX JSON file and returns deduplicated Rows.
// sourceType is "cve" or "usn".
func ParseFile(data []byte, sourceType string) ([]Row, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	// key: "cve_id|pkg_name|distro" → best Row so far
	best := make(map[string]Row)

	for _, stmt := range doc.Statements {
		mappedStatus := mapStatus(stmt)
		if mappedStatus == "" {
			continue // skip 'fixed' — already covered by OVAL
		}

		justification := stmt.ActionStatement
		if justification == "" {
			justification = stmt.StatusNotes
		}

		cveIDs := extractCVEIDs(stmt.Vulnerability)
		if len(cveIDs) == 0 {
			continue
		}

		for _, product := range stmt.Products {
			pkgName, distro := parsePurl(product.ID)
			if pkgName == "" || distro == "" {
				continue
			}

			for _, cveID := range cveIDs {
				k := cveID + "|" + pkgName + "|" + distro
				row := Row{
					CVEID:         cveID,
					PackageName:   pkgName,
					Distro:        distro,
					Status:        mappedStatus,
					Justification: justification,
					SourceType:    sourceType,
					SourceID:      sourceIDFromDoc(doc, sourceType),
				}
				if existing, ok := best[k]; !ok || statusPriority[row.Status] < statusPriority[existing.Status] {
					best[k] = row
				}
			}
		}
	}

	rows := make([]Row, 0, len(best))
	for _, r := range best {
		rows = append(rows, r)
	}
	return rows, nil
}

// mapStatus translates OpenVEX status to our internal storage value.
// Returns "" for statuses we don't store (fixed).
func mapStatus(stmt Statement) string {
	switch stmt.Status {
	case "not_affected":
		return StatusNotAffected
	case "under_investigation":
		return StatusUnderInvestigation
	case "affected":
		// Ubuntu uses action_statement to signal "will not fix"
		action := strings.ToLower(stmt.ActionStatement)
		if strings.Contains(action, "decided to not fix") ||
			strings.Contains(action, "will not fix") ||
			strings.Contains(action, "no longer supported") ||
			strings.Contains(action, "marking as ignored") {
			return StatusWillNotFix
		}
		return StatusWillNotFix // all 'affected' CVE VEX statements mean Canonical won't fix
	case "fixed":
		return "" // skip — already tracked via OVAL fix_state
	}
	return ""
}

// extractCVEIDs returns all CVE-XXXX-XXXX identifiers from a vulnerability.
func extractCVEIDs(v Vulnerability) []string {
	seen := make(map[string]bool)
	var ids []string

	addIfCVE := func(s string) {
		upper := strings.ToUpper(strings.TrimSpace(s))
		upper = trimCVEID(upper)
		if strings.HasPrefix(upper, "CVE-") && !seen[upper] {
			seen[upper] = true
			ids = append(ids, upper)
		}
	}

	addIfCVE(v.Name)
	for _, alias := range v.Aliases {
		// Aliases may be full URLs like https://www.cve.org/CVERecord?id=CVE-2024-0046
		if idx := strings.LastIndex(alias, "CVE-"); idx >= 0 {
			addIfCVE(alias[idx:])
		} else {
			addIfCVE(alias)
		}
	}
	return ids
}

// parsePurl extracts package name and distro codename from a purl string.
// e.g. "pkg:deb/ubuntu/openssl@3.0.2?arch=amd64&distro=jammy" → ("openssl", "jammy")
func parsePurl(purl string) (pkgName, distro string) {
	// Strip scheme prefix
	s := strings.TrimPrefix(purl, "pkg:deb/ubuntu/")
	if s == purl {
		return "", "" // not a Ubuntu deb purl
	}

	// Package name is before '@' or '?'
	nameEnd := strings.IndexAny(s, "@?")
	if nameEnd < 0 {
		pkgName = s
	} else {
		pkgName = s[:nameEnd]
	}
	pkgName = strings.TrimSpace(pkgName)

	// Distro is in the query string: ?...&distro=focal&...
	if q := strings.Index(purl, "distro="); q >= 0 {
		distroStr := purl[q+len("distro="):]
		if end := strings.IndexAny(distroStr, "&# "); end >= 0 {
			distroStr = distroStr[:end]
		}
		distro = strings.TrimSpace(distroStr)
	}

	return pkgName, distro
}

// trimCVEID truncates s at the first character that is not a digit, uppercase
// letter, or hyphen — isolating the bare CVE-YYYY-NNNN token from a URL or
// other surrounding text.
func trimCVEID(s string) string {
	for i, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return s[:i]
		}
	}
	return s
}

// sourceIDFromDoc derives the source identifier (CVE-XXXX or USN-XXXX) from the document.
func sourceIDFromDoc(doc Document, sourceType string) string {
	if len(doc.Statements) == 0 {
		return ""
	}
	name := doc.Statements[0].Vulnerability.Name
	if name != "" {
		return name
	}
	// Fall back to the document @id basename
	id := doc.Metadata.ID
	if idx := strings.LastIndex(id, "/"); idx >= 0 {
		return id[idx+1:]
	}
	return id
}
