package goredact

import (
	"sort"

	"github.com/baum-ai/goredact/internal/rules"
)

// RuleInfo describes one built-in or custom detection rule for
// introspection and diagnostics. It never contains matched input bytes or
// any secret material — only stable identifiers and metadata.
type RuleInfo struct {
	// ID is the stable rule identifier, e.g. "aws-access-key-id".
	ID string

	// Name is the human-readable rule name.
	Name string

	// Confidence is the confidence level reported by findings this rule
	// confirms.
	Confidence Confidence

	// MinProfile is the least detailed profile that includes this rule.
	// For custom rules (Custom == true) this is always the zero Profile
	// value: custom rules are not tiered by profile — they are active
	// whenever they are part of an Engine's configuration, regardless of
	// Config.Profile — so MinProfile carries no meaning for them.
	MinProfile Profile

	// Custom reports whether this is a caller-supplied rule (added via
	// Config.CustomRules) rather than a built-in.
	Custom bool
}

// ActiveRules returns the rules compiled into e — the effective result of
// applying Config.Profile, EnableRules, DisableRules, and CustomRules —
// sorted by ID. The returned slice is a copy owned by the caller; mutating
// it does not affect e, and no internal engine state is exposed.
func (e *Engine) ActiveRules() []RuleInfo {
	out := make([]RuleInfo, len(e.rules.Rules))
	for i, r := range e.rules.Rules {
		out[i] = ruleInfoFrom(r)
	}
	sortRuleInfo(out)
	return out
}

// BuiltinRules returns every built-in rule this version of goredact ships,
// regardless of profile, sorted by ID. Use (*Engine).ActiveRules to see
// the rules compiled into a specific Engine.
func BuiltinRules() []RuleInfo {
	builtins := rules.Builtins()
	out := make([]RuleInfo, len(builtins))
	for i, r := range builtins {
		out[i] = ruleInfoFrom(r)
	}
	sortRuleInfo(out)
	return out
}

func ruleInfoFrom(r rules.Rule) RuleInfo {
	return RuleInfo{
		ID:         r.ID,
		Name:       r.Name,
		Confidence: Confidence(r.Confidence),
		MinProfile: Profile(r.MinProfile),
		Custom:     r.Custom,
	}
}

func sortRuleInfo(rs []RuleInfo) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
}
