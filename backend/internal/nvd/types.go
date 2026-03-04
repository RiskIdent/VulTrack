package nvd

// NVDResponse represents the response from the NVD API
type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability wraps a CVE entry
type Vulnerability struct {
	CVE CVE `json:"cve"`
}

// CVE represents a CVE entry from NVD
type CVE struct {
	ID           string        `json:"id"`
	SourceID     string        `json:"sourceIdentifier"`
	Published    string        `json:"published"`
	LastModified string        `json:"lastModified"`
	VulnStatus   string        `json:"vulnStatus"`
	Descriptions []Description `json:"descriptions"`
	Metrics      Metrics       `json:"metrics"`
	Weaknesses   []Weakness    `json:"weaknesses"`
	References   []Reference   `json:"references"`
}

// Description represents a CVE description
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics contains CVSS scores
type Metrics struct {
	CVSSV2  []CVSSMetricV2  `json:"cvssMetricV2,omitempty"`
	CVSSV30 []CVSSMetricV3  `json:"cvssMetricV30,omitempty"`
	CVSSV31 []CVSSMetricV3  `json:"cvssMetricV31,omitempty"`
}

// CVSSMetricV2 represents a CVSS v2 metric
type CVSSMetricV2 struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CVSSData CVSSV2Data `json:"cvssData"`
}

// CVSSV2Data contains CVSS v2 score data
type CVSSV2Data struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

// CVSSMetricV3 represents a CVSS v3.x metric
type CVSSMetricV3 struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CVSSData CVSSV3Data `json:"cvssData"`
}

// CVSSV3Data contains CVSS v3 score data
type CVSSV3Data struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// Weakness represents a CWE weakness
type Weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []Description `json:"description"`
}

// Reference represents a CVE reference URL
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}
