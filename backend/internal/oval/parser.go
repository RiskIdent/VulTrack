package oval

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/services"
)

// ParseStats contains statistics about parsed OVAL data
type ParseStats struct {
	TotalDefinitions int
	TotalTests       int
	TotalObjects     int
	TotalStates      int
}

// Parser handles OVAL XML parsing
type Parser struct {
	ovalService *services.OVALService
}

// NewParser creates a new OVAL Parser
func NewParser(ovalService *services.OVALService) *Parser {
	return &Parser{ovalService: ovalService}
}

// ============================================================================
// OVAL XML Structures
// ============================================================================

// OvalDefinitions is the root element of an OVAL file
type OvalDefinitions struct {
	XMLName     xml.Name    `xml:"oval_definitions"`
	Generator   Generator   `xml:"generator"`
	Definitions Definitions `xml:"definitions"`
	Tests       Tests       `xml:"tests"`
	Objects     Objects     `xml:"objects"`
	States      States      `xml:"states"`
	Variables   Variables   `xml:"variables"`
}

// Variables container
type Variables struct {
	ConstantVariable   []ConstantVariable `xml:"constant_variable"`
	ConstantVariableNS []ConstantVariable `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 constant_variable"`
}

type ConstantVariable struct {
	ID      string   `xml:"id,attr"`
	Values  []string `xml:"value"`
}

type Generator struct {
	ProductName   string `xml:"product_name"`
	SchemaVersion string `xml:"schema_version"`
	Timestamp     string `xml:"timestamp"`
}

type Definitions struct {
	Definition []Definition `xml:"definition"`
}

type Definition struct {
	ID       string   `xml:"id,attr"`
	Class    string   `xml:"class,attr"`
	Metadata Metadata `xml:"metadata"`
	Criteria *Criteria `xml:"criteria"`
}

type Metadata struct {
	Title       string      `xml:"title"`
	Description string      `xml:"description"`
	Advisory    *Advisory   `xml:"advisory"`
	Reference   []Reference `xml:"reference"`
}

type Advisory struct {
	Severity string   `xml:"severity"`
	Rights   string   `xml:"rights"`
	CVE      []CVERef `xml:"cve"`
}

type CVERef struct {
	ID   string `xml:",chardata"`
	Href string `xml:"href,attr"`
}

type Reference struct {
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
	Source string `xml:"source,attr"`
}

type Criteria struct {
	Operator         string             `xml:"operator,attr"`
	Negate           bool               `xml:"negate,attr"`
	Comment          string             `xml:"comment,attr"`
	Criterion        []Criterion        `xml:"criterion"`
	Criteria         []Criteria         `xml:"criteria"`          // Nested criteria
	ExtendDefinition []ExtendDefinition `xml:"extend_definition"` // References to other definitions
}

type Criterion struct {
	TestRef string `xml:"test_ref,attr"`
	Negate  bool   `xml:"negate,attr"`
	Comment string `xml:"comment,attr"`
}

type ExtendDefinition struct {
	DefinitionRef      string `xml:"definition_ref,attr"`
	Comment            string `xml:"comment,attr"`
	ApplicabilityCheck bool   `xml:"applicability_check,attr"`
	Negate             bool   `xml:"negate,attr"`
}

// Tests container
type Tests struct {
	// Support both with and without namespace prefix
	DpkgInfoTest    []DpkgInfoTest `xml:"dpkginfo_test"`
	DpkgInfoTestNS  []DpkgInfoTest `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux dpkginfo_test"`
	RpmInfoTest     []RpmInfoTest  `xml:"rpminfo_test"`
	RpmInfoTestNS   []RpmInfoTest  `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_test"`
	UnameTest       []UnameTest    `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix uname_test"`
	VariableTest    []VariableTest `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent variable_test"`
}

type DpkgInfoTest struct {
	ID      string    `xml:"id,attr"`
	Check   string    `xml:"check,attr"`
	Comment string    `xml:"comment,attr"`
	Object  ObjectRef `xml:"object"`
	State   *StateRef `xml:"state"`
}

type RpmInfoTest struct {
	ID      string    `xml:"id,attr"`
	Check   string    `xml:"check,attr"`
	Comment string    `xml:"comment,attr"`
	Object  ObjectRef `xml:"object"`
	State   *StateRef `xml:"state"`
}

type UnameTest struct {
	ID      string    `xml:"id,attr"`
	Check   string    `xml:"check,attr"`
	Comment string    `xml:"comment,attr"`
	Object  ObjectRef `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix object"`
	State   *StateRef `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix state"`
}

type VariableTest struct {
	ID      string    `xml:"id,attr"`
	Check   string    `xml:"check,attr"`
	Comment string    `xml:"comment,attr"`
	Object  ObjectRef `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent object"`
	State   *StateRef `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent state"`
}

type ObjectRef struct {
	ObjectRef string `xml:"object_ref,attr"`
}

type StateRef struct {
	StateRef string `xml:"state_ref,attr"`
}

// Objects container
type Objects struct {
	DpkgInfoObject   []DpkgInfoObject `xml:"dpkginfo_object"`
	DpkgInfoObjectNS []DpkgInfoObject `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux dpkginfo_object"`
	RpmInfoObject    []RpmInfoObject  `xml:"rpminfo_object"`
	RpmInfoObjectNS  []RpmInfoObject  `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_object"`
	UnameObject      []UnameObject    `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix uname_object"`
	VariableObject   []VariableObject `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent variable_object"`
}

type NameElement struct {
	VarRef string `xml:"var_ref,attr"`
	Value  string `xml:",chardata"`
}

type DpkgInfoObject struct {
	ID     string      `xml:"id,attr"`
	Name   NameElement `xml:"name"`
	NameNS NameElement `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux name"`
}

func (o DpkgInfoObject) GetName() string {
	if o.Name.Value != "" {
		return o.Name.Value
	}
	if o.NameNS.Value != "" {
		return o.NameNS.Value
	}
	return ""
}

func (o DpkgInfoObject) GetVarRef() string {
	if o.Name.VarRef != "" {
		return o.Name.VarRef
	}
	return o.NameNS.VarRef
}

type RpmInfoObject struct {
	ID     string      `xml:"id,attr"`
	Name   NameElement `xml:"name"`
	NameNS NameElement `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux name"`
}

func (o RpmInfoObject) GetName() string {
	if o.Name.Value != "" {
		return o.Name.Value
	}
	if o.NameNS.Value != "" {
		return o.NameNS.Value
	}
	return ""
}

func (o RpmInfoObject) GetVarRef() string {
	if o.Name.VarRef != "" {
		return o.Name.VarRef
	}
	return o.NameNS.VarRef
}

type UnameObject struct {
	ID string `xml:"id,attr"`
	// Uname objects don't have name/var_ref - they reference system uname directly
}

type VariableObject struct {
	ID     string `xml:"id,attr"`
	VarRef string `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent var_ref"`
}

// States container
type States struct {
	DpkgInfoState   []DpkgInfoState `xml:"dpkginfo_state"`
	DpkgInfoStateNS []DpkgInfoState `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux dpkginfo_state"`
	RpmInfoState    []RpmInfoState  `xml:"rpminfo_state"`
	RpmInfoStateNS  []RpmInfoState  `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_state"`
	UnameState      []UnameState     `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix uname_state"`
	VariableState   []VariableState  `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent variable_state"`
}

type DpkgInfoState struct {
	ID    string `xml:"id,attr"`
	EVR   *EVR   `xml:"evr"`
	EVRNS *EVR   `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux evr"`
}

func (s DpkgInfoState) GetEVR() *EVR {
	if s.EVR != nil {
		return s.EVR
	}
	return s.EVRNS
}

type RpmInfoState struct {
	ID    string `xml:"id,attr"`
	EVR   *EVR   `xml:"evr"`
	EVRNS *EVR   `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux evr"`
}

func (s RpmInfoState) GetEVR() *EVR {
	if s.EVR != nil {
		return s.EVR
	}
	return s.EVRNS
}

type EVR struct {
	Operation string `xml:"operation,attr"`
	Datatype  string `xml:"datatype,attr"`
	Value     string `xml:",chardata"`
}

type UnameState struct {
	ID        string `xml:"id,attr"`
	OSRelease *OSRelease `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix os_release"`
}

type OSRelease struct {
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

type VariableState struct {
	ID    string `xml:"id,attr"`
	Value *EVR   `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent value"`
}

// ============================================================================
// PARSING
// ============================================================================

// ParseAndStore parses OVAL XML and stores it in the database
func (p *Parser) ParseAndStore(ctx context.Context, sourceID int64, xmlData []byte) (*ParseStats, error) {
	// Parse XML
	var oval OvalDefinitions
	if err := xml.Unmarshal(xmlData, &oval); err != nil {
		return nil, fmt.Errorf("failed to parse OVAL XML: %w", err)
	}

	log.Debug().
		Int("definitions", len(oval.Definitions.Definition)).
		Int("dpkgTests", len(oval.Tests.DpkgInfoTest)+len(oval.Tests.DpkgInfoTestNS)).
		Int("rpmTests", len(oval.Tests.RpmInfoTest)+len(oval.Tests.RpmInfoTestNS)).
		Int("unameTests", len(oval.Tests.UnameTest)).
		Int("variableTests", len(oval.Tests.VariableTest)).
		Int("dpkgObjects", len(oval.Objects.DpkgInfoObject)+len(oval.Objects.DpkgInfoObjectNS)).
		Int("rpmObjects", len(oval.Objects.RpmInfoObject)+len(oval.Objects.RpmInfoObjectNS)).
		Int("unameObjects", len(oval.Objects.UnameObject)).
		Int("variableObjects", len(oval.Objects.VariableObject)).
		Msg("Parsed OVAL XML")

	stats := &ParseStats{}

	// Start transaction
	tx, err := p.ovalService.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Maps to store OVAL ID -> DB ID mappings
	testIDMap := make(map[string]int64)
	objectIDMap := make(map[string]int64)
	stateIDMap := make(map[string]int64)

	// Build variable map (var_id -> list of package names)
	variableMap := make(map[string][]string)
	allVariables := append(oval.Variables.ConstantVariable, oval.Variables.ConstantVariableNS...)
	for _, v := range allVariables {
		variableMap[v.ID] = v.Values
	}

	log.Debug().Int("variables", len(variableMap)).Msg("Loaded OVAL variables")

	// 1. Insert objects (combine regular and namespaced variants)
	// For objects with var_ref, resolve to actual package names
	allDpkgObjects := append(oval.Objects.DpkgInfoObject, oval.Objects.DpkgInfoObjectNS...)
	for _, obj := range allDpkgObjects {
		name := obj.GetName()
		varRef := obj.GetVarRef()
		
		// If there's a var_ref, resolve it to package names
		if varRef != "" {
			if names, ok := variableMap[varRef]; ok && len(names) > 0 {
				// Insert one object per package name
				for _, pkgName := range names {
					// Use a composite ID to make it unique
					compositeID := obj.ID + ":" + pkgName
					id, err := p.ovalService.InsertObject(ctx, tx, sourceID, compositeID, "dpkginfo_object", pkgName)
					if err != nil {
						return nil, fmt.Errorf("failed to insert dpkg object %s: %w", compositeID, err)
					}
					// Map original object ID to the first inserted ID (for test references)
					if _, exists := objectIDMap[obj.ID]; !exists {
						objectIDMap[obj.ID] = id
					}
					stats.TotalObjects++
				}
				continue
			}
		}
		
		// Direct name or fallback
		id, err := p.ovalService.InsertObject(ctx, tx, sourceID, obj.ID, "dpkginfo_object", name)
		if err != nil {
			return nil, fmt.Errorf("failed to insert dpkg object %s: %w", obj.ID, err)
		}
		objectIDMap[obj.ID] = id
		stats.TotalObjects++
	}
	
	allRpmObjects := append(oval.Objects.RpmInfoObject, oval.Objects.RpmInfoObjectNS...)
	for _, obj := range allRpmObjects {
		name := obj.GetName()
		varRef := obj.GetVarRef()
		
		if varRef != "" {
			if names, ok := variableMap[varRef]; ok && len(names) > 0 {
				for _, pkgName := range names {
					compositeID := obj.ID + ":" + pkgName
					id, err := p.ovalService.InsertObject(ctx, tx, sourceID, compositeID, "rpminfo_object", pkgName)
					if err != nil {
						return nil, fmt.Errorf("failed to insert rpm object %s: %w", compositeID, err)
					}
					if _, exists := objectIDMap[obj.ID]; !exists {
						objectIDMap[obj.ID] = id
					}
					stats.TotalObjects++
				}
				continue
			}
		}
		
		id, err := p.ovalService.InsertObject(ctx, tx, sourceID, obj.ID, "rpminfo_object", name)
		if err != nil {
			return nil, fmt.Errorf("failed to insert rpm object %s: %w", obj.ID, err)
		}
		objectIDMap[obj.ID] = id
		stats.TotalObjects++
	}

	// Insert uname objects (no name needed - they reference system uname)
	for _, obj := range oval.Objects.UnameObject {
		// Store empty name - uname objects don't have package names
		id, err := p.ovalService.InsertObject(ctx, tx, sourceID, obj.ID, "uname_object", "")
		if err != nil {
			return nil, fmt.Errorf("failed to insert uname object %s: %w", obj.ID, err)
		}
		objectIDMap[obj.ID] = id
		stats.TotalObjects++
	}

	// Insert variable objects (reference variables)
	for _, obj := range oval.Objects.VariableObject {
		// Store var_ref as name for reference
		id, err := p.ovalService.InsertObject(ctx, tx, sourceID, obj.ID, "variable_object", obj.VarRef)
		if err != nil {
			return nil, fmt.Errorf("failed to insert variable object %s: %w", obj.ID, err)
		}
		objectIDMap[obj.ID] = id
		stats.TotalObjects++
	}

	// 2. Insert states (combine regular and namespaced variants)
	allDpkgStates := append(oval.States.DpkgInfoState, oval.States.DpkgInfoStateNS...)
	for _, state := range allDpkgStates {
		var op, val string
		if evr := state.GetEVR(); evr != nil {
			op = evr.Operation
			val = strings.TrimSpace(evr.Value)
		}
		id, err := p.ovalService.InsertState(ctx, tx, sourceID, state.ID, "dpkginfo_state", op, val)
		if err != nil {
			return nil, fmt.Errorf("failed to insert dpkg state %s: %w", state.ID, err)
		}
		stateIDMap[state.ID] = id
		stats.TotalStates++
	}
	allRpmStates := append(oval.States.RpmInfoState, oval.States.RpmInfoStateNS...)
	for _, state := range allRpmStates {
		var op, val string
		if evr := state.GetEVR(); evr != nil {
			op = evr.Operation
			val = strings.TrimSpace(evr.Value)
		}
		id, err := p.ovalService.InsertState(ctx, tx, sourceID, state.ID, "rpminfo_state", op, val)
		if err != nil {
			return nil, fmt.Errorf("failed to insert rpm state %s: %w", state.ID, err)
		}
		stateIDMap[state.ID] = id
		stats.TotalStates++
	}

	// Insert uname states (pattern matching for kernel version)
	for _, state := range oval.States.UnameState {
		var op, val string
		if state.OSRelease != nil {
			op = state.OSRelease.Operation
			val = strings.TrimSpace(state.OSRelease.Value)
		}
		id, err := p.ovalService.InsertState(ctx, tx, sourceID, state.ID, "uname_state", op, val)
		if err != nil {
			return nil, fmt.Errorf("failed to insert uname state %s: %w", state.ID, err)
		}
		stateIDMap[state.ID] = id
		stats.TotalStates++
	}

	// Insert variable states (version comparison)
	for _, state := range oval.States.VariableState {
		var op, val string
		if state.Value != nil {
			op = state.Value.Operation
			val = strings.TrimSpace(state.Value.Value)
		}
		id, err := p.ovalService.InsertState(ctx, tx, sourceID, state.ID, "variable_state", op, val)
		if err != nil {
			return nil, fmt.Errorf("failed to insert variable state %s: %w", state.ID, err)
		}
		stateIDMap[state.ID] = id
		stats.TotalStates++
	}

	// 3. Insert tests (combine regular and namespaced variants)
	allDpkgTests := append(oval.Tests.DpkgInfoTest, oval.Tests.DpkgInfoTestNS...)
	for _, test := range allDpkgTests {
		stateRef := ""
		if test.State != nil {
			stateRef = test.State.StateRef
		}
		id, err := p.ovalService.InsertTest(ctx, tx, sourceID, test.ID, "dpkginfo_test", test.Object.ObjectRef, stateRef, test.Comment)
		if err != nil {
			return nil, fmt.Errorf("failed to insert dpkg test %s: %w", test.ID, err)
		}
		testIDMap[test.ID] = id
		stats.TotalTests++
	}
	allRpmTests := append(oval.Tests.RpmInfoTest, oval.Tests.RpmInfoTestNS...)
	for _, test := range allRpmTests {
		stateRef := ""
		if test.State != nil {
			stateRef = test.State.StateRef
		}
		id, err := p.ovalService.InsertTest(ctx, tx, sourceID, test.ID, "rpminfo_test", test.Object.ObjectRef, stateRef, test.Comment)
		if err != nil {
			return nil, fmt.Errorf("failed to insert rpm test %s: %w", test.ID, err)
		}
		testIDMap[test.ID] = id
		stats.TotalTests++
	}

	// Insert uname tests (kernel version pattern matching)
	for _, test := range oval.Tests.UnameTest {
		stateRef := ""
		if test.State != nil {
			stateRef = test.State.StateRef
		}
		id, err := p.ovalService.InsertTest(ctx, tx, sourceID, test.ID, "uname_test", test.Object.ObjectRef, stateRef, test.Comment)
		if err != nil {
			return nil, fmt.Errorf("failed to insert uname test %s: %w", test.ID, err)
		}
		testIDMap[test.ID] = id
		stats.TotalTests++
	}

	// Insert variable tests (kernel version comparison)
	for _, test := range oval.Tests.VariableTest {
		stateRef := ""
		if test.State != nil {
			stateRef = test.State.StateRef
		}
		id, err := p.ovalService.InsertTest(ctx, tx, sourceID, test.ID, "variable_test", test.Object.ObjectRef, stateRef, test.Comment)
		if err != nil {
			return nil, fmt.Errorf("failed to insert variable test %s: %w", test.ID, err)
		}
		testIDMap[test.ID] = id
		stats.TotalTests++
	}

	// 4. Insert definitions with criteria
	for _, def := range oval.Definitions.Definition {
		// Extract CVE IDs
		var cveIDs []string
		if def.Metadata.Advisory != nil {
			for _, cve := range def.Metadata.Advisory.CVE {
				if cve.ID != "" {
					cveIDs = append(cveIDs, strings.TrimSpace(cve.ID))
				}
			}
		}
		// Also check references
		for _, ref := range def.Metadata.Reference {
			if ref.Source == "CVE" && ref.RefID != "" {
				// Avoid duplicates
				found := false
				for _, existing := range cveIDs {
					if existing == ref.RefID {
						found = true
						break
					}
				}
				if !found {
					cveIDs = append(cveIDs, ref.RefID)
				}
			}
		}

		// Get severity
		severity := ""
		if def.Metadata.Advisory != nil {
			severity = def.Metadata.Advisory.Severity
		}

		// Insert definition
		defID, err := p.ovalService.InsertDefinition(
			ctx, tx, sourceID, def.ID, def.Class,
			def.Metadata.Title, def.Metadata.Description,
			severity, cveIDs,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert definition %s: %w", def.ID, err)
		}
		stats.TotalDefinitions++

		// Insert criteria tree
		if def.Criteria != nil {
			if err := p.insertCriteriaTree(ctx, tx, defID, nil, def.Criteria, testIDMap); err != nil {
				return nil, fmt.Errorf("failed to insert criteria for %s: %w", def.ID, err)
			}
		}
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return stats, nil
}

// insertCriteriaTree recursively inserts criteria and their children
func (p *Parser) insertCriteriaTree(ctx context.Context, tx pgx.Tx, definitionID int64, parentID *int64, criteria *Criteria, testIDMap map[string]int64) error {
	// Insert this criteria node
	var criteriaID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO oval_criteria (definition_id, parent_id, operator, negate, comment)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, definitionID, parentID, criteria.Operator, criteria.Negate, criteria.Comment).Scan(&criteriaID)
	if err != nil {
		return err
	}

	// Link criterion (test references) to this criteria, including the criterion comment
	// The comment carries semantic meaning (e.g. "affected and needs fixing", "decision to ignore", etc.)
	for _, crit := range criteria.Criterion {
		testID, ok := testIDMap[crit.TestRef]
		if ok {
			_, err := tx.Exec(ctx, `
				INSERT INTO oval_criteria_tests (criteria_id, test_id, negate, comment)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT DO NOTHING
			`, criteriaID, testID, crit.Negate, crit.Comment)
			if err != nil {
				log.Warn().Err(err).Str("testRef", crit.TestRef).Msg("Failed to link criteria to test")
			}
		}
	}

	// Link extend_definition references to this criteria
	for _, extDef := range criteria.ExtendDefinition {
		_, err := tx.Exec(ctx, `
			INSERT INTO oval_criteria_extend_definitions (criteria_id, definition_oval_id, applicability_check, negate, comment)
			VALUES ($1, $2, $3, $4, $5)
		`, criteriaID, extDef.DefinitionRef, extDef.ApplicabilityCheck, extDef.Negate, extDef.Comment)
		if err != nil {
			log.Warn().Err(err).Str("definitionRef", extDef.DefinitionRef).Msg("Failed to link criteria to extend_definition")
		}
	}

	// Recursively insert nested criteria
	for i := range criteria.Criteria {
		if err := p.insertCriteriaTree(ctx, tx, definitionID, &criteriaID, &criteria.Criteria[i], testIDMap); err != nil {
			return err
		}
	}

	return nil
}
