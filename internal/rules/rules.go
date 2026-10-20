// Package rules defines the internal rule model shared by the matcher,
// the streaming engine, and the generated built-in rule tables.
package rules

import (
	"fmt"
	"sort"
)

// Version identifies the built-in rule-set revision. It is defined in the
// generated zz_generated_rules.go: it is derived from the
// canonical serialization of the generated rule table, so it changes
// exactly when generated rules change.

// Profile is a bitmask of the profiles a rule belongs to.
type Profile uint8

// Numbering starts at 1, matching the public goredact.Profile (whose zero
// value is reserved to mean "unspecified" so New(Config{}) can default to
// ProfileBalanced): goredact.New passes Profile(cfg.Profile) straight
// through as this type, so the two enums must stay numerically aligned.
const (
	profileUnspecified Profile = iota
	ProfileFast
	ProfileBalanced
	ProfileDeep
)

// Confidence mirrors the public confidence levels.
type Confidence uint8

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

// ValidateFunc inspects window, in which the trigger occupies
// window[trigStart:trigEnd], and reports the half-open range [start, end)
// within window to redact. Implementations must be pure functions of the
// window: no I/O, no logging, no retention of the window slice.
type ValidateFunc func(window []byte, trigStart, trigEnd int) (start, end int, ok bool)

// BlockBeginFunc confirms a block rule's candidate exactly like a
// ValidateFunc and also reports whether the block runs on past window.
//
// final reports that window ends at the end of input. When it is false and
// the block's end lies beyond the window, the function may return
// open == true: the confirmed span is then [start, end), where end is a
// token boundary at which scanning resumes in the bytes that follow, and
// state is the scanner state to resume with (see BlockExtendFunc). An open
// result has trigEnd < end <= len(window). With final set the result is
// never open and equals the rule's ValidateFunc result.
type BlockBeginFunc func(window []byte, trigStart, trigEnd int, final bool) (start, end int, state uint64, open, ok bool)

// BlockExtendFunc continues an open block. window starts at the resume
// point (the end of the span so far) and holds up to the rule's
// MaxLookahead bytes; final reports that it ends at the end of input. It
// returns the block's end within window, so [0, end) extends the span
// (end == 0 adds nothing). When the block still runs past the window it
// returns open == true, with end the next resume point
// (0 < end <= len(window)) and next the state to resume with.
type BlockExtendFunc func(window []byte, state uint64, final bool) (end int, next uint64, open bool)

// Block lets a rule mask a delimited block of unbounded length, such as a
// private key, to its end marker rather than to the end of a fixed window.
// Begin confirms the block within the trigger's bounded window; while the
// block stays open, the engine calls Extend on each following
// MaxLookahead-byte window and merges the adjacent spans into one. Only
// the masked extent is unbounded: detection is decided in the trigger
// window, and the engine retains no more input than for any other rule.
type Block struct {
	Begin  BlockBeginFunc
	Extend BlockExtendFunc
}

// Trigger is a literal byte string that activates a rule.
type Trigger struct {
	Literal  string
	CaseFold bool
}

// Rule is one detection rule: triggers locate candidates cheaply, Validate
// confirms them within a bounded window.
type Rule struct {
	// ID is the stable rule identifier, e.g. "aws-access-key-id".
	ID string

	// Name is the human-readable rule name.
	Name string

	// Triggers are the literals that activate this rule.
	Triggers []Trigger

	// Validate confirms candidates. Required.
	Validate ValidateFunc

	// MinProfile is the least detailed profile that includes this rule:
	// a rule with MinProfile == ProfileFast runs in every profile, one
	// with MinProfile == ProfileDeep runs only in the deep profile.
	MinProfile Profile

	// Confidence is reported for findings confirmed by this rule.
	Confidence Confidence

	// MaxLookbehind and MaxLookahead bound the validation window in bytes
	// before the trigger start and after the trigger end.
	MaxLookbehind int
	MaxLookahead  int

	// Block, when non-nil, makes this a block rule: the streaming engine
	// confirms candidates with Block.Begin instead of Validate and keeps
	// extending an open block past the validation window. Validate stays
	// required and is the window-bounded equivalent (Block.Begin with
	// final set). Built-in rules only.
	Block *Block

	// Custom marks caller-supplied rules.
	Custom bool
}

// Set is the compiled, immutable active rule set for one Engine.
type Set struct {
	// Rules is the active rules in deterministic order (built-ins in
	// generation order, then custom rules in caller order).
	Rules []Rule

	// maxWindow is the largest MaxLookbehind + trigger length +
	// MaxLookahead over all active rules.
	maxWindow int
}

// BuildOptions selects and extends the built-in rule set.
type BuildOptions struct {
	Profile      Profile
	EnableRules  []string
	DisableRules []string
	CustomRules  []Rule
}

// builtins is populated by the generated rule tables. Kept as a
// function variable so the generated file lives in this package without an
// import cycle.
var builtins []Rule

// RegisterBuiltins installs the generated built-in rule table. It is called
// from generated code's init and must not be called twice.
func RegisterBuiltins(rs []Rule) {
	if builtins != nil {
		panic("rules: builtins registered twice")
	}
	builtins = rs
}

// Builtins returns the registered built-in rules.
func Builtins() []Rule { return builtins }

// Build compiles the active rule set for the given options.
func Build(opts BuildOptions) (*Set, error) {
	var enable map[string]bool
	if len(opts.EnableRules) > 0 {
		enable = make(map[string]bool, len(opts.EnableRules))
		for _, id := range opts.EnableRules {
			enable[id] = true
		}
	}
	disable := make(map[string]bool, len(opts.DisableRules))
	for _, id := range opts.DisableRules {
		disable[id] = true
	}

	known := make(map[string]bool, len(builtins))
	var active []Rule
	for _, r := range builtins {
		known[r.ID] = true
		if enable != nil {
			// Explicit enablement is an allowlist: a named rule runs
			// regardless of the requested profile, rather than being
			// silently dropped when it sits above the profile's
			// MinProfile gate.
			if !enable[r.ID] {
				continue
			}
		} else if r.MinProfile > opts.Profile {
			continue
		}
		if disable[r.ID] {
			continue
		}
		active = append(active, r)
	}
	for _, id := range opts.EnableRules {
		if !known[id] {
			return nil, fmt.Errorf("unknown rule ID in EnableRules: %q", id)
		}
	}
	for _, id := range opts.DisableRules {
		if !known[id] {
			return nil, fmt.Errorf("unknown rule ID in DisableRules: %q", id)
		}
	}

	seen := make(map[string]bool, len(active)+len(opts.CustomRules))
	for _, r := range active {
		seen[r.ID] = true
	}
	for _, r := range opts.CustomRules {
		if err := validateRule(r); err != nil {
			return nil, err
		}
		if known[r.ID] || seen[r.ID] {
			return nil, fmt.Errorf("custom rule ID collides with existing rule: %q", r.ID)
		}
		seen[r.ID] = true
		active = append(active, r)
	}
	if len(active) == 0 {
		return nil, fmt.Errorf("rule set is empty: no rules matched the given Profile, EnableRules, and DisableRules")
	}

	s := &Set{Rules: active}
	for _, r := range s.Rules {
		for _, t := range r.Triggers {
			if w := r.MaxLookbehind + len(t.Literal) + r.MaxLookahead; w > s.maxWindow {
				s.maxWindow = w
			}
		}
	}
	return s, nil
}

// maxValidationWindow is the largest validation window (MaxLookbehind +
// longest trigger + MaxLookahead) a rule may declare. The streaming engine
// retains up to Set.MaxWindow() bytes of overlap across chunk boundaries
// and requires ChunkSize >= 2*window, so lookaround beyond a few tens of
// MiB is useless for a bounded streaming scanner and merely forces absurd
// allocations. 16 MiB is ~1000x the largest built-in window (16 KiB) while
// keeping 2*window, the maxWindow sums in Build, and the engine's int64
// offset arithmetic (trigEnd + MaxLookahead) far from overflow.
const maxValidationWindow = 16 << 20 // 16 MiB

func validateRule(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("rule with empty ID")
	}
	if len(r.Triggers) == 0 {
		return fmt.Errorf("rule %q has no triggers", r.ID)
	}
	for _, t := range r.Triggers {
		if t.Literal == "" {
			return fmt.Errorf("rule %q has an empty trigger", r.ID)
		}
	}
	if r.Validate == nil {
		return fmt.Errorf("rule %q has no validator", r.ID)
	}
	if r.MaxLookbehind < 0 || r.MaxLookahead < 0 {
		return fmt.Errorf("rule %q has negative window bounds", r.ID)
	}
	// The engine retains MaxLookbehind + trigger length + MaxLookahead
	// bytes across chunk boundaries (Set.MaxWindow), so the total window
	// is what must stay bounded. Check it by subtraction: summing
	// MaxInt-sized bounds first would wrap around to a tiny value and let
	// an over-limit rule silently through to an engine slice panic.
	longestTrigger := 0
	for _, t := range r.Triggers {
		if n := len(t.Literal); n > longestTrigger {
			longestTrigger = n
		}
	}
	if remain := maxValidationWindow - r.MaxLookbehind - longestTrigger; r.MaxLookahead > remain {
		return fmt.Errorf("rule %q validation window (%d + %d + %d bytes) exceeds maximum %d bytes",
			r.ID, r.MaxLookbehind, longestTrigger, r.MaxLookahead, maxValidationWindow)
	}
	if r.Confidence > ConfidenceHigh {
		// Confidence is a uint8 the collector compares numerically when
		// choosing a merged span's attribution; an out-of-range value
		// (e.g. a public Confidence(-1) wrapped through the conversion)
		// would silently outrank ConfidenceHigh and stringify to
		// "unknown" in findings.
		return fmt.Errorf("rule %q has invalid confidence %d", r.ID, r.Confidence)
	}
	return nil
}

// MaxWindow returns the largest lookbehind + trigger + lookahead over all
// active rules, i.e. the overlap the streaming engine must retain across
// chunk boundaries.
func (s *Set) MaxWindow() int { return s.maxWindow }

// MinChunkSize returns the smallest chunk size the streaming engine can
// operate with for this rule set.
func (s *Set) MinChunkSize() int {
	const floor = 4096
	if w := 2 * s.maxWindow; w > floor {
		return w
	}
	return floor
}

// SortedIDs returns the active rule IDs sorted, for diagnostics and tests.
func (s *Set) SortedIDs() []string {
	ids := make([]string, len(s.Rules))
	for i, r := range s.Rules {
		ids[i] = r.ID
	}
	sort.Strings(ids)
	return ids
}
