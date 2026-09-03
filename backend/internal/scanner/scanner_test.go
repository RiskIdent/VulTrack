package scanner

import (
	"regexp"
	"sort"
	"testing"

	"github.com/vultrack/vultrack/internal/models"
)

func unameTest(id int64, pattern string) *OVALTestData {
	return &OVALTestData{
		TestID:         id,
		TestType:       "uname_test",
		EVROperation:   "pattern match",
		EVRValue:       pattern,
		ReleasePattern: regexp.MustCompile(pattern),
	}
}

func variableTest(id int64, operation, value string) *OVALTestData {
	return &OVALTestData{
		TestID:       id,
		TestType:     "variable_test",
		EVROperation: operation,
		EVRValue:     value,
	}
}

func packageTest(id int64, operation, value string, names ...string) *OVALTestData {
	return &OVALTestData{
		TestID:       id,
		TestType:     "dpkginfo_test",
		PackageNames: names,
		EVROperation: operation,
		EVRValue:     value,
	}
}

func installed(nameVersion map[string]string) map[string]*models.ServerPackage {
	packages := make(map[string]*models.ServerPackage, len(nameVersion))
	for name, version := range nameVersion {
		packages[name] = &models.ServerPackage{Name: name, Version: version}
	}
	return packages
}

func matchedPackageNames(r criteriaResult) []string {
	names := make([]string, 0, len(r.Packages))
	for _, p := range r.Packages {
		names = append(names, p.Package.Name)
	}
	sort.Strings(names)
	return names
}

func TestMatchOSRelease(t *testing.T) {
	generic := unameTest(1, `6.8.0-\d+(-generic|-generic-64k)`)
	hwe70 := unameTest(2, `7.0.0-\d+(-generic|-generic-64k)`)
	aws := unameTest(3, `6.8.0-\d+(-aws|-aws-64k)`)

	tests := []struct {
		release string
		test    *OVALTestData
		want    bool
	}{
		{"6.8.0-79-generic", generic, true},
		// OVAL "pattern match" is an unanchored search, so a longer flavour that
		// starts with a listed alternative still matches.
		{"6.8.0-79-generic-64k", generic, true},
		{"6.8.0-79-generic", hwe70, false},
		{"7.0.0-30-generic", hwe70, true},
		// A 26.04-era HWE kernel criterion must not apply to a 24.04 kernel.
		{"6.8.0-79-generic", aws, false},
		{"6.8.0-1029-aws", aws, true},
		{"6.8.0-1029-aws", generic, false},
		// Digits are required where the pattern says so.
		{"6.8.0-x-generic", generic, false},
		{"", generic, false},
	}

	for _, tc := range tests {
		if got := matchOSRelease(tc.release, tc.test); got != tc.want {
			t.Errorf("matchOSRelease(%q, %q) = %v, want %v",
				tc.release, tc.test.EVRValue, got, tc.want)
		}
	}
}

func TestMatchOSReleaseEquality(t *testing.T) {
	exact := &OVALTestData{TestType: "uname_test", EVROperation: "equals", EVRValue: "6.8.0-79-generic"}
	if !matchOSRelease("6.8.0-79-generic", exact) {
		t.Error("expected equals operation to match an identical release")
	}
	if matchOSRelease("6.8.0-80-generic", exact) {
		t.Error("expected equals operation not to match a different release")
	}

	notEqual := &OVALTestData{TestType: "uname_test", EVROperation: "not equal", EVRValue: "6.8.0-79-generic"}
	if notEqual.EVRValue != "" && matchOSRelease("6.8.0-79-generic", notEqual) {
		t.Error("expected not equal operation not to match an identical release")
	}
}

// TestEvaluateCriterionMissingTestIsFalse covers the AND-weakening bug: a
// criterion whose test was not loaded (its object matches no installed package,
// or the test type is unsupported) used to be dropped from the surrounding
// operator instead of evaluating to false.
func TestEvaluateCriterionMissingTestIsFalse(t *testing.T) {
	tests := map[int64]*OVALTestData{}
	kernel := kernelInfo{Release: "6.8.0-79-generic", EVR: "0:6.8.0-79"}

	got := evaluateCriterion(criterionRef{TestID: 99}, nil, tests, "dpkg", kernel)
	if got.Matched {
		t.Error("a criterion whose test is not loaded must not match")
	}
	if len(got.Packages) != 0 || got.KernelMatch {
		t.Error("a criterion whose test is not loaded must not report evidence")
	}

	negated := evaluateCriterion(criterionRef{TestID: 99, Negate: true}, nil, tests, "dpkg", kernel)
	if !negated.Matched {
		t.Error("negating an unmatched criterion must yield a match")
	}
}

func TestEvaluateCriterionPackageVersion(t *testing.T) {
	tests := map[int64]*OVALTestData{
		1: packageTest(1, "less than", "3.0.13-0ubuntu3.2", "openssl", "libssl3t64"),
	}
	kernel := kernelInfo{Release: "6.8.0-79-generic", EVR: "0:6.8.0-79"}
	criterion := criterionRef{TestID: 1, Comment: "openssl source package in noble was vulnerable but has been fixed (note: '3.0.13-0ubuntu3.2')."}

	// Outdated: reported with the fixed version.
	packages := installed(map[string]string{"openssl": "3.0.13-0ubuntu3.1", "libssl3t64": "3.0.13-0ubuntu3.2"})
	got := evaluateCriterion(criterion, packages, tests, "dpkg", kernel)
	if !got.Matched {
		t.Fatal("expected an outdated package to match")
	}
	if names := matchedPackageNames(got); len(names) != 1 || names[0] != "openssl" {
		t.Errorf("expected only openssl to be affected, got %v", names)
	}
	if got.Packages[0].FixState != "fix_available" || got.Packages[0].FixedIn != "3.0.13-0ubuntu3.2" {
		t.Errorf("expected fix_available with a fixed version, got %+v", got.Packages[0])
	}

	// Fully patched: no finding at all.
	packages = installed(map[string]string{"openssl": "3.0.13-0ubuntu3.2", "libssl3t64": "3.0.13-0ubuntu3.2"})
	if got := evaluateCriterion(criterion, packages, tests, "dpkg", kernel); got.Matched {
		t.Errorf("expected a patched package not to match, got %v", matchedPackageNames(got))
	}

	// Not installed: no finding.
	if got := evaluateCriterion(criterion, installed(map[string]string{"bash": "5.2-2"}), tests, "dpkg", kernel); got.Matched {
		t.Error("expected an uninstalled package not to match")
	}
}

func TestEvaluateCriterionExistenceOnly(t *testing.T) {
	tests := map[int64]*OVALTestData{
		1: packageTest(1, "", "", "amd64-microcode"),
	}
	kernel := kernelInfo{Release: "6.8.0-79-generic", EVR: "0:6.8.0-79"}
	packages := installed(map[string]string{"amd64-microcode": "3.20240710.3ubuntu1"})

	cases := []struct {
		comment  string
		fixState string
	}{
		{"amd64-microcode source package in noble, is affected and needs fixing.", "affected"},
		{"foo package in noble, a decision has been made to ignore this issue.", "will_not_fix"},
		{"foo package in noble, a decision has been made to defer this issue.", "deferred"},
		{"", "affected"},
	}

	for _, tc := range cases {
		got := evaluateCriterion(criterionRef{TestID: 1, Comment: tc.comment}, packages, tests, "dpkg", kernel)
		if !got.Matched {
			t.Fatalf("expected an existence-only test to match for comment %q", tc.comment)
		}
		if len(got.Packages) != 1 || got.Packages[0].FixState != tc.fixState {
			t.Errorf("comment %q: got fix_state %q, want %q", tc.comment, got.Packages[0].FixState, tc.fixState)
		}
		if got.Packages[0].FixedIn != "" {
			t.Errorf("comment %q: an existence-only test has no fixed version, got %q", tc.comment, got.Packages[0].FixedIn)
		}
	}
}

func TestCombineCriteriaResultsAND(t *testing.T) {
	affected := criteriaResult{Matched: true, Packages: []AffectedPackageInfo{
		{Package: &models.ServerPackage{Name: "openssl"}},
	}}
	kernelHit := criteriaResult{Matched: true, KernelMatch: true}

	// An AND that does not hold must not leak the evidence of its matching parts.
	got := combineCriteriaResults("AND", []criteriaResult{affected, kernelHit, {Matched: false}})
	if got.Matched {
		t.Error("AND with a failing branch must not match")
	}
	if len(got.Packages) != 0 || got.KernelMatch {
		t.Errorf("AND with a failing branch must not report evidence, got %+v", got)
	}

	got = combineCriteriaResults("AND", []criteriaResult{affected, kernelHit})
	if !got.Matched || !got.KernelMatch || len(got.Packages) != 1 {
		t.Errorf("AND over matching branches must combine their evidence, got %+v", got)
	}

	// An empty node cannot hold; per the OVAL spec a missing operator is AND.
	if combineCriteriaResults("", nil).Matched {
		t.Error("a criteria node without criteria must not match")
	}
	if !combineCriteriaResults("", []criteriaResult{{Matched: true}}).Matched {
		t.Error("a missing operator must behave like AND")
	}
}

func TestCombineCriteriaResultsOR(t *testing.T) {
	openssl := criteriaResult{Matched: true, Packages: []AffectedPackageInfo{
		{Package: &models.ServerPackage{Name: "openssl"}},
	}}
	curlNotAffected := criteriaResult{Matched: false, Packages: []AffectedPackageInfo{
		{Package: &models.ServerPackage{Name: "curl"}},
	}}

	got := combineCriteriaResults("OR", []criteriaResult{openssl, curlNotAffected})
	if !got.Matched {
		t.Fatal("OR with a matching branch must match")
	}
	if names := matchedPackageNames(got); len(names) != 1 || names[0] != "openssl" {
		t.Errorf("OR must only report packages from branches that matched, got %v", names)
	}

	if combineCriteriaResults("OR", []criteriaResult{{Matched: false}, {Matched: false}}).Matched {
		t.Error("OR without a matching branch must not match")
	}
}

func TestNegateDropsEvidence(t *testing.T) {
	got := negate(criteriaResult{Matched: true, KernelMatch: true, Packages: []AffectedPackageInfo{
		{Package: &models.ServerPackage{Name: "openssl"}},
	}})
	if got.Matched {
		t.Error("negate must invert the match")
	}
	if len(got.Packages) != 0 || got.KernelMatch {
		t.Errorf("negate must drop the evidence of the inverted subtree, got %+v", got)
	}
}

func TestBuildCriteriaTree(t *testing.T) {
	rootID := int64(1)
	criteria := []*criteriaNode{
		{ID: 2, ParentID: &rootID, Operator: "OR"},
		{ID: 1, Operator: "AND"},
		{ID: 3, ParentID: &rootID, Operator: "OR"},
	}

	root := buildCriteriaTree(criteria)
	if root == nil || root.ID != 1 {
		t.Fatalf("expected the parentless node as root, got %+v", root)
	}
	if len(root.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(root.Children))
	}

	// Re-building the same nodes must not accumulate duplicate children; the
	// bulk loader hands out shared pointers across definitions.
	root = buildCriteriaTree(criteria)
	if len(root.Children) != 2 {
		t.Errorf("rebuilding the tree duplicated children: got %d, want 2", len(root.Children))
	}

	if buildCriteriaTree(nil) != nil {
		t.Error("a definition without criteria has no root")
	}
}

// TestEvaluateCriteriaNodeKernelOnly models Canonical's kernel CVE shape:
// AND(applicability, OR(is kernel X running?, ...)) with no package test.
func TestEvaluateCriteriaNodeKernelOnly(t *testing.T) {
	tests := map[int64]*OVALTestData{
		1: unameTest(1, `6.8.0-\d+(-generic|-generic-64k)`),
		2: unameTest(2, `7.0.0-\d+(-generic|-generic-64k)`),
	}

	newTree := func() *criteriaNode {
		rootID := int64(10)
		return buildCriteriaTree([]*criteriaNode{
			{ID: 10, Operator: "", ExtendDefinitions: []extendDefinitionRef{
				{DefinitionOvalID: "oval:com.ubuntu.noble:def:100", ApplicabilityCheck: true},
			}},
			{ID: 11, ParentID: &rootID, Operator: "OR", Tests: []criterionRef{
				{TestID: 1, Comment: "Is kernel 'linux' running?"},
				{TestID: 2, Comment: "Is kernel 'linux-hwe-7.0' running?"},
			}},
		})
	}

	s := &Scanner{}

	got := s.evaluateCriteriaNode(nil, 1, newTree(), nil, tests, "dpkg",
		kernelInfo{Release: "6.8.0-79-generic", EVR: "0:6.8.0-79"})
	if !got.Matched || !got.KernelMatch {
		t.Errorf("the running 6.8.0 kernel must match the 'linux' criterion, got %+v", got)
	}

	// Only the 26.04-era HWE kernel criterion is left: a 24.04 kernel is not affected.
	delete(tests, 1)
	got = s.evaluateCriteriaNode(nil, 1, newTree(), nil, tests, "dpkg",
		kernelInfo{Release: "6.8.0-79-generic", EVR: "0:6.8.0-79"})
	if got.Matched {
		t.Error("a definition gated on linux-hwe-7.0 must not apply to a 6.8.0 kernel")
	}
}

// TestEvaluateCriteriaNodeKernelAndVersion models the USN kernel shape:
// AND(is kernel X running?, kernel version < fixed).
func TestEvaluateCriteriaNodeKernelAndVersion(t *testing.T) {
	tests := map[int64]*OVALTestData{
		1: unameTest(1, `6.8.0-\d+(-generic|-generic-64k)`),
		2: variableTest(2, "less than", "6.8.0-84.84"),
		3: unameTest(3, `6.8.0-\d+(-ibm)`),
		4: variableTest(4, "less than", "6.8.0-1006.6"),
	}

	rootID := int64(20)
	tree := func() *criteriaNode {
		return buildCriteriaTree([]*criteriaNode{
			{ID: 20, Operator: "OR"},
			{ID: 21, ParentID: &rootID, Operator: "AND", Tests: []criterionRef{
				{TestID: 1, Comment: "Is kernel 'linux' running?"},
				{TestID: 2, Comment: "'linux' kernel in noble was vulnerable but has been fixed (note: '6.8.0-84.84')."},
			}},
			{ID: 22, ParentID: &rootID, Operator: "AND", Tests: []criterionRef{
				{TestID: 3, Comment: "Is kernel 'linux-ibm' running?"},
				{TestID: 4, Comment: "'linux-ibm' kernel in noble was vulnerable but has been fixed (note: '6.8.0-1006.6')."},
			}},
		})
	}

	s := &Scanner{}

	// Running an outdated generic kernel: affected.
	got := s.evaluateCriteriaNode(nil, 1, tree(), nil, tests, "dpkg",
		kernelInfo{Release: "6.8.0-79-generic", EVR: "0:6.8.0-79"})
	if !got.Matched || !got.KernelMatch {
		t.Errorf("an outdated generic kernel must be reported, got %+v", got)
	}

	// Running a patched generic kernel. Note the linux-ibm branch compares as
	// "older" on version alone (1006 > 84) — only its uname test keeps it from
	// applying, which is exactly why a dropped criterion is dangerous.
	got = s.evaluateCriteriaNode(nil, 1, tree(), nil, tests, "dpkg",
		kernelInfo{Release: "6.8.0-90-generic", EVR: "0:6.8.0-90"})
	if got.Matched {
		t.Error("a patched generic kernel must not be reported as affected")
	}
}

// TestEvaluateCriteriaNodeMicrocodeNotKernel covers the mis-attribution seen in
// the real 24.04 feed: OR(microcode package installed?, is kernel X running?)
// must be filed against the microcode package, not against "kernel".
func TestEvaluateCriteriaNodeMicrocodeNotKernel(t *testing.T) {
	tests := map[int64]*OVALTestData{
		1: packageTest(1, "", "", "amd64-microcode"),
		2: unameTest(2, `6.8.0-\d+(-generic|-generic-64k)`),
	}

	rootID := int64(30)
	tree := buildCriteriaTree([]*criteriaNode{
		{ID: 30, Operator: ""},
		{ID: 31, ParentID: &rootID, Operator: "OR", Tests: []criterionRef{
			{TestID: 1, Comment: "amd64-microcode source package in noble, might be affected and may need fixing."},
			{TestID: 2, Comment: "Is kernel 'linux' running?"},
		}},
	})

	s := &Scanner{}
	got := s.evaluateCriteriaNode(nil, 1, tree, installed(map[string]string{
		"amd64-microcode": "3.20240710.3ubuntu1",
	}), tests, "dpkg", kernelInfo{Release: "6.8.0-79-generic", EVR: "0:6.8.0-79"})

	if !got.Matched {
		t.Fatal("expected the definition to apply")
	}
	if names := matchedPackageNames(got); len(names) != 1 || names[0] != "amd64-microcode" {
		t.Errorf("expected the finding to name amd64-microcode, got %v", names)
	}
}

func TestClassifyCriterionComment(t *testing.T) {
	tests := map[string]string{
		"openssl source package in noble was vulnerable but has been fixed (note: '3.0.13-0ubuntu3.2').": "fix_available",
		"foo package in noble, a decision has been made to ignore this issue.":                           "will_not_fix",
		"foo package in noble, a decision has been made to defer this issue.":                            "deferred",
		"foo package in noble, is affected and needs fixing.":                                            "affected",
		"foo package in noble, might be affected and may need fixing.":                                   "affected",
		"":                                "affected",
		"something completely unexpected": "affected",
	}

	for comment, want := range tests {
		if got := classifyCriterionComment(comment); got != want {
			t.Errorf("classifyCriterionComment(%q) = %q, want %q", comment, got, want)
		}
	}
}
