package rules

import (
	"sort"
	"testing"
)

// TestBuiltinsSortedAndNonEmpty guards the ordering contract rulegen
// promises: built-in rules are registered in ID-sorted order, so
// adding an unrelated rule to the specs cannot reorder existing entries in
// Builtins() or in a compiled Set. This test exercises the real generated
// table (zz_generated_rules.go), produced by `go generate ./internal/rules`.
func TestBuiltinsSortedAndNonEmpty(t *testing.T) {
	rs := Builtins()
	if len(rs) == 0 {
		t.Fatal("Builtins() is empty; run `go generate ./internal/rules`")
	}

	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = r.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("Builtins() not sorted by ID: %v", ids)
	}

	seen := make(map[string]bool, len(ids))
	for i, r := range rs {
		if r.ID == "" {
			t.Errorf("builtin rule at index %d has an empty ID", i)
		}
		if seen[r.ID] {
			t.Errorf("duplicate builtin rule ID: %q", r.ID)
		}
		seen[r.ID] = true
		if r.Validate == nil {
			t.Errorf("builtin rule %q has a nil Validate func", r.ID)
		}
		if len(r.Triggers) == 0 {
			t.Errorf("builtin rule %q has no triggers", r.ID)
		}
	}

	if Version == "" {
		t.Error("Version is empty")
	}
}

// TestLineStartRulesSeeTheBytesBeforeTheirTrigger keeps the assumption
// behind the validators' startsLine check valid: a rule that reads the
// diff marker before its trigger, and asks whether that marker starts a
// line, needs a lookbehind of two bytes, so the start of its window is the
// start of a line only at the start of input.
func TestLineStartRulesSeeTheBytesBeforeTheirTrigger(t *testing.T) {
	needs := map[string]bool{
		"pem-private-key":            true, // the BEGIN line's diff marker
		"putty-private-key":          true, // the trigger line's diff marker
		"openai-legacy-key":          true, // a removal marker before "sk-"
		"deepseek-api-key":           true, // a removal marker before "sk-"
		"command-line-password-flag": true, // a removal marker before "--password"
	}
	for _, r := range Builtins() {
		if needs[r.ID] {
			delete(needs, r.ID)
			if r.MaxLookbehind < 2 {
				t.Errorf("rule %q checks for a diff marker opening its trigger's line, so needs maxLookbehind >= 2, has %d", r.ID, r.MaxLookbehind)
			}
		}
	}
	for id := range needs {
		t.Errorf("rule %q is not a built-in any more; update this test", id)
	}
}
