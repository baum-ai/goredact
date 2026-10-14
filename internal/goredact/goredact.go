package goredact

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/baum-ai/goredact/internal/ahocorasick"
	"github.com/baum-ai/goredact/internal/rules"
)

// DefaultChunkSize is the input buffer size used when Config.ChunkSize is
// zero.
const DefaultChunkSize = 256 * 1024

// DefaultMarker is the replacement text used when Config.Marker is empty.
const DefaultMarker = "[REDACTED]"

// Config configures an Engine. The zero value is a valid configuration
// using ProfileBalanced, DefaultChunkSize, and DefaultMarker.
type Config struct {
	// Profile selects the detection profile. Defaults to ProfileBalanced.
	Profile Profile

	// ChunkSize is the size in bytes of the fixed input buffer. Values
	// below the minimum required by the compiled rule set are rejected by
	// New. Defaults to DefaultChunkSize.
	ChunkSize int

	// Marker is the fixed replacement text written in place of each
	// redacted span under MaskFixedMarker. Defaults to DefaultMarker.
	// The other mask strategies ignore it.
	Marker string

	// MaskStrategy selects how confirmed spans are replaced in the
	// output. The zero value, MaskFixedMarker, writes Marker once per
	// span; MaskLengthPreserving and MaskFormatPreserving instead
	// replace each redacted byte one-for-one, so output length equals
	// input length. See the MaskStrategy constants for the disclosure
	// trade-offs. Masking never changes what is detected or what
	// Findings/Stats report, and every strategy stays
	// allocation-bounded on the streaming path.
	MaskStrategy MaskStrategy

	// EnableRules, when non-empty, restricts detection to exactly the
	// listed rule IDs (an allowlist), overriding Profile: a named rule
	// runs even if its MinProfile is more detailed than Profile requests.
	// Unknown IDs are rejected by New, as is a resulting empty rule set
	// (e.g. every enabled ID also appearing in DisableRules).
	EnableRules []string

	// DisableRules removes the listed rule IDs from the active set (a
	// denylist, applied after EnableRules). Unknown IDs are rejected by
	// New, as is a resulting empty rule set.
	DisableRules []string

	// CustomRules adds caller-defined rules to the active set. Custom rule
	// IDs must not collide with built-in rule IDs.
	CustomRules []CustomRule

	// OnFinding, when non-nil, is invoked synchronously for each confirmed
	// finding during Redact, in input order. The Finding never contains
	// matched input bytes. The callback must not retain references past
	// its return and must be fast; it runs on the scanning path. When one
	// Engine serves concurrent Redact calls, OnFinding is invoked
	// concurrently from each call's own goroutine — it must be safe for
	// concurrent use if the Engine is shared.
	OnFinding func(Finding)

	// RecordAligned, when true, makes the engine prefer emitting output
	// aligned to newline record boundaries when it is safe to do so: a
	// mid-stream emission is held back to the last buffered '\n' rather
	// than the raw safe limit, so downstream consumers of structured,
	// newline-delimited formats (e.g. JSONL session logs) observe whole
	// records instead of a line split across two writes. It never
	// changes what is redacted, only where emission boundaries fall
	// while streaming, and it never relaxes any streaming guarantee
	// (bounded memory, no temporary files, determinism): alignment is a
	// best-effort output-shaping preference that falls back to the raw
	// limit whenever no newline is buffered, so the stream still makes
	// progress. Defaults to false.
	RecordAligned bool
}

// CustomRule is a caller-supplied detection rule.
//
// A CustomRule is located by literal trigger strings. When a trigger is
// found, Validate is invoked with a bounded window of surrounding bytes and
// decides whether a secret is present and which bytes to redact.
type CustomRule struct {
	// ID is the stable rule identifier. Required, must be unique.
	ID string

	// Triggers are the literal byte strings that activate the rule.
	// Required, each must be non-empty.
	Triggers []string

	// CaseFold, when true, matches triggers with ASCII case folding.
	CaseFold bool

	// Confidence reported for findings confirmed by this rule.
	Confidence Confidence

	// MaxLookbehind and MaxLookahead bound the validation window in bytes
	// before the trigger start and after the trigger end.
	MaxLookbehind int
	MaxLookahead  int

	// Validate inspects window, in which the trigger occupies
	// window[trigStart:trigEnd], and reports the half-open byte range
	// [start, end) within window to redact. Implementations must not
	// retain window, log it, or include its contents in any output.
	Validate func(window []byte, trigStart, trigEnd int) (start, end int, ok bool)
}

// Engine detects and redacts secrets from byte streams.
//
// An Engine is immutable after construction and safe for concurrent use by
// multiple goroutines; each Redact call maintains independent scan state.
type Engine struct {
	cfg    Config
	rules  *rules.Set
	marker []byte

	// matcher is the trigger automaton compiled from the unique
	// (Literal, CaseFold) trigger pairs of the active rule set. It is nil
	// when the active rule set is empty, in which case Redact degenerates
	// to a plain (stats-counting) copy.
	matcher *ahocorasick.Automaton

	// dispatch maps a matcher pattern index to the indexes (into
	// rules.Rules) of every rule sharing that trigger; patLen holds each
	// pattern's literal length in bytes.
	dispatch [][]int
	patLen   []int

	// window is rules.Set.MaxWindow(): the number of trailing bytes the
	// streaming engine must retain across reads so that every trigger's
	// full validation window (lookbehind + trigger + lookahead) stays
	// addressable.
	window int

	// recordAligned makes the engine prefer aligning emission boundaries
	// down to the last '\n' at or before the safe emission limit, so
	// downstream consumers observe whole records. It never violates
	// safety limits and falls back to the raw limit when no newline is
	// buffered. Set from the public Config.RecordAligned;
	// escaped-JSON record detection builds on this hook. See
	// (*scanRun).alignToRecord.
	recordAligned bool

	// states pools per-Redact scan buffers so a reused Engine does not
	// reallocate its chunk buffer on every call. It never holds input
	// bytes beyond a call's lifetime semantics: pooled buffers are reused
	// memory, reset (length zero) before each use.
	states sync.Pool
}

// New compiles the active rule set for the configuration and returns a
// reusable Engine.
func New(cfg Config) (*Engine, error) {
	if cfg.Profile == profileUnspecified {
		cfg.Profile = ProfileBalanced
	}
	if !cfg.Profile.valid() {
		return nil, fmt.Errorf("%w: unknown profile %d", ErrInvalidConfig, int(cfg.Profile))
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.ChunkSize < 0 {
		return nil, fmt.Errorf("%w: negative chunk size", ErrInvalidConfig)
	}
	if cfg.Marker == "" {
		cfg.Marker = DefaultMarker
	}
	if !cfg.MaskStrategy.valid() {
		return nil, fmt.Errorf("%w: unknown mask strategy %d", ErrInvalidConfig, int(cfg.MaskStrategy))
	}
	set, err := rules.Build(rules.BuildOptions{
		Profile:      rules.Profile(cfg.Profile),
		EnableRules:  cfg.EnableRules,
		DisableRules: cfg.DisableRules,
		CustomRules:  customToInternal(cfg.CustomRules),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if min := set.MinChunkSize(); cfg.ChunkSize < min {
		return nil, fmt.Errorf("%w: chunk size %d below minimum %d required by rule set", ErrInvalidConfig, cfg.ChunkSize, min)
	}
	e := &Engine{cfg: cfg, rules: set, marker: []byte(cfg.Marker), window: set.MaxWindow(), recordAligned: cfg.RecordAligned}
	if err := e.compileTriggers(); err != nil {
		return nil, err
	}
	chunkSize := cfg.ChunkSize
	e.states.New = func() any {
		return &scanState{buf: make([]byte, 0, chunkSize)}
	}
	return e, nil
}

// Redact copies src to dst, replacing every confirmed secret according to
// the configured MaskStrategy (by default, one copy of the marker per
// secret), and returns statistics about the scan.
//
// Redact streams: it never buffers more than a bounded window of input and
// never writes unredacted data to temporary storage. It returns the first
// error encountered: ctx.Err() on cancellation, a *ReadError on source
// failure, or a *WriteError on destination failure. On error, output
// already written remains valid redacted output; no unredacted confirmed
// secret has been emitted.
//
// ctx is polled once per read iteration: cancellation cannot interrupt a
// call already blocked inside src.Read.
func (e *Engine) Redact(ctx context.Context, dst io.Writer, src io.Reader) (Stats, error) {
	return e.redact(ctx, dst, src)
}

// RuleSetVersion reports the version identifier of the compiled built-in
// rule set, for inclusion in caller diagnostics.
func (e *Engine) RuleSetVersion() string {
	return rules.Version
}

func customToInternal(in []CustomRule) []rules.Rule {
	out := make([]rules.Rule, 0, len(in))
	for _, c := range in {
		r := rules.Rule{
			ID:            c.ID,
			Triggers:      make([]rules.Trigger, 0, len(c.Triggers)),
			Confidence:    rules.Confidence(c.Confidence),
			MaxLookbehind: c.MaxLookbehind,
			MaxLookahead:  c.MaxLookahead,
			Validate:      c.Validate,
			Custom:        true,
		}
		for _, t := range c.Triggers {
			r.Triggers = append(r.Triggers, rules.Trigger{Literal: t, CaseFold: c.CaseFold})
		}
		out = append(out, r)
	}
	return out
}
