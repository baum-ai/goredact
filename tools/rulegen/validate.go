package main

import "fmt"

// validateRules checks every rule in rules against the spec schema and
// returns every problem found (empty when the specs are all valid). It
// never stops at the first problem: the whole point of collecting them is
// to report every violation in one generator run instead of a
// fix-one-rerun-repeat loop.
func validateRules(rules []specRule) []string {
	var problems []string

	report := func(r specRule, format string, args ...any) {
		var loc string
		if r.ID != "" {
			loc = fmt.Sprintf("%s: rule %q", r.sourceFile, r.ID)
		} else {
			loc = fmt.Sprintf("%s: rule with empty id", r.sourceFile)
		}
		problems = append(problems, loc+": "+fmt.Sprintf(format, args...))
	}

	seenIDs := make(map[string]string, len(rules)) // id -> first source file seen in
	for _, r := range rules {
		if r.ID == "" {
			report(r, "id is required")
		} else if !idPattern.MatchString(r.ID) {
			report(r, "id %q is not stable kebab-case (expected lowercase letters, digits, and hyphens)", r.ID)
		} else if first, ok := seenIDs[r.ID]; ok {
			report(r, "duplicate id: also defined in %s", first)
		} else {
			seenIDs[r.ID] = r.sourceFile
		}

		if r.Name == "" {
			report(r, "name is required")
		}

		if len(r.Triggers) == 0 {
			report(r, "must have at least one trigger")
		}
		for i, trig := range r.Triggers {
			if trig.Literal == "" {
				report(r, "trigger[%d] has an empty literal", i)
			}
		}

		if r.Validator == "" {
			report(r, "validator is required")
		} else if !goIdentPattern.MatchString(r.Validator) {
			report(r, "validator %q is not a valid Go identifier", r.Validator)
		}

		if r.Block != nil {
			for _, fn := range []struct{ field, name string }{{"block.begin", r.Block.Begin}, {"block.extend", r.Block.Extend}} {
				if fn.name == "" {
					report(r, "%s is required for a block rule", fn.field)
				} else if !goIdentPattern.MatchString(fn.name) {
					report(r, "%s %q is not a valid Go identifier", fn.field, fn.name)
				}
			}
		}

		if !validMinProfiles[r.MinProfile] {
			report(r, "minProfile %q is invalid (want one of fast, balanced, deep)", r.MinProfile)
		}
		if !validConfidences[r.Confidence] {
			report(r, "confidence %q is invalid (want one of low, medium, high)", r.Confidence)
		}

		if r.MaxLookbehind < 0 {
			report(r, "maxLookbehind must be non-negative, got %d", r.MaxLookbehind)
		}
		if r.MaxLookahead < 0 {
			report(r, "maxLookahead must be non-negative, got %d", r.MaxLookahead)
		}

		if r.Provenance.Source == "" {
			report(r, "provenance.source is required")
		}
		if r.Provenance.License == "" {
			report(r, "provenance.license is required")
		}

		if len(r.Fixtures.Match) == 0 {
			report(r, "must have at least one match fixture")
		}
	}

	// Note: duplicate trigger literals across (or within) different rules
	// are intentionally NOT a validation error. Multiple rules commonly
	// share a trigger literal (e.g. two providers both keying off a
	// generic "Bearer " prefix); the runtime automaton dedupes triggers at
	// compile time (internal/ahocorasick), and rule dispatch fans out to
	// every rule registered against a given trigger. Rejecting shared
	// triggers here would make that pattern impossible to express.

	return problems
}
