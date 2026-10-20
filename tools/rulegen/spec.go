package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// specFile is the top-level shape of one internal/rules/specs/*.json file.
type specFile struct {
	Rules []specRule `json:"rules"`
}

// specRule is one declarative rule definition. See internal/rules/specs for
// examples and package doc comment (below) for the full field contract.
type specRule struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Triggers      []specTrigger  `json:"triggers"`
	Validator     string         `json:"validator"`
	MinProfile    string         `json:"minProfile"`
	Confidence    string         `json:"confidence"`
	MaxLookbehind int            `json:"maxLookbehind"`
	MaxLookahead  int            `json:"maxLookahead"`
	Block         *specBlock     `json:"block,omitempty"`
	Provenance    specProvenance `json:"provenance"`
	Fixtures      specFixtures   `json:"fixtures"`

	// sourceFile is the base name of the spec file this rule was loaded
	// from, populated by loadSpecs. It is not part of the JSON schema; it
	// exists purely to make validation error messages actionable.
	sourceFile string
}

// specBlock names the block functions of a block rule (rules.Block): Begin
// and Extend, both Go identifiers in internal/rules/validators.
type specBlock struct {
	Begin  string `json:"begin"`
	Extend string `json:"extend"`
}

type specTrigger struct {
	Literal  string `json:"literal"`
	CaseFold bool   `json:"caseFold"`
}

type specProvenance struct {
	Source  string `json:"source"`
	License string `json:"license"`
}

type specFixtures struct {
	Match   []string `json:"match"`
	NoMatch []string `json:"nomatch"`
}

// loadSpecs reads every *.json file directly under dir, sorted by file
// name, and returns the concatenation of their rules (in file order, then
// declaration order within each file — codegen re-sorts by ID afterward).
// Malformed JSON is reported as a single problem per file, not a fatal
// error, so it can be listed alongside every other problem in one pass.
func loadSpecs(dir string) ([]specRule, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{fmt.Sprintf("reading specs directory %q: %v", dir, err)}
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var (
		rules    []specRule
		problems []string
	)
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		var sf specFile
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&sf); err != nil {
			problems = append(problems, fmt.Sprintf("%s: invalid JSON: %v", name, err))
			continue
		}
		for i := range sf.Rules {
			sf.Rules[i].sourceFile = name
			rules = append(rules, sf.Rules[i])
		}
	}
	return rules, problems
}

var (
	idPattern        = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	goIdentPattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	validMinProfiles = map[string]bool{"fast": true, "balanced": true, "deep": true}
	validConfidences = map[string]bool{"low": true, "medium": true, "high": true}
)
