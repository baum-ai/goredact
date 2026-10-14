package goredact

import (
	"context"
	"errors"
	"io"

	core "github.com/baum-ai/goredact/internal/goredact"
)

// DefaultChunkSize is the input buffer size used when Config.ChunkSize is
// zero.
const DefaultChunkSize = core.DefaultChunkSize

// DefaultMarker is the replacement text used when Config.Marker is empty.
const DefaultMarker = core.DefaultMarker

// Profile selects a predefined trade-off between scanning throughput and
// detection depth.
type Profile core.Profile

const (
	// ProfileFast enables only deterministic, high-confidence detectors:
	// provider token prefixes, authentication headers, credential-bearing
	// URLs, and private-key markers.
	ProfileFast = Profile(core.ProfileFast)

	// ProfileBalanced is the default. It extends ProfileFast with
	// contextual assignment detection, entropy validation, cookies, and
	// common generic credential patterns.
	ProfileBalanced = Profile(core.ProfileBalanced)

	// ProfileDeep extends ProfileBalanced with more expensive or
	// lower-confidence detectors and selected decoding. In v0.1 the only
	// deep-only built-in rule is a broad, low-confidence generic secret
	// assignment heuristic (keyed on words like "key", "secret", "auth",
	// "access", "credential", "creds"); every other rule that runs in
	// ProfileDeep also runs in ProfileBalanced. See docs/PROFILES.md.
	ProfileDeep = Profile(core.ProfileDeep)
)

// String returns the profile name.
func (p Profile) String() string { return core.Profile(p).String() }

// Confidence expresses how certain a rule is that a match is a real secret.
type Confidence core.Confidence

const (
	// ConfidenceLow marks heuristic detections (e.g. the deep profile's
	// broad generic-assignment rule) that are expected to over-match.
	ConfidenceLow = Confidence(core.ConfidenceLow)

	// ConfidenceMedium marks contextual detections confirmed by
	// surrounding structure and entropy rather than an exact token shape.
	ConfidenceMedium = Confidence(core.ConfidenceMedium)

	// ConfidenceHigh marks detections confirmed by an exact, well-known
	// token shape or structure.
	ConfidenceHigh = Confidence(core.ConfidenceHigh)
)

// String returns the confidence name.
func (c Confidence) String() string { return core.Confidence(c).String() }

// MaskStrategy selects how each confirmed secret span is replaced in the
// output. The zero value is MaskFixedMarker, so the zero Config keeps the
// documented fixed-marker behavior.
type MaskStrategy core.MaskStrategy

const (
	// MaskFixedMarker replaces each confirmed span with exactly one copy
	// of Config.Marker, regardless of the span's length. This is the
	// default and discloses nothing about the redacted value, not even
	// its length.
	MaskFixedMarker = MaskStrategy(core.MaskFixedMarker)

	// MaskLengthPreserving replaces each redacted byte with '*'. Output
	// length equals input length, so fixed-width records and offsets in
	// surrounding text survive redaction. The length of each secret is
	// disclosed; its contents are not.
	MaskLengthPreserving = MaskStrategy(core.MaskLengthPreserving)

	// MaskFormatPreserving replaces each redacted byte with a stand-in
	// of the same coarse character class: uppercase letters become 'X',
	// lowercase letters 'x', digits '9'; the separator bytes
	// - _ . : / + = @ pass through verbatim; every other byte becomes
	// '*'. Output length equals input length and token shapes (JWT dots,
	// UUID dashes, base64 padding) survive, which keeps
	// structured/fixed-format consumers parsing. The preserved shape and
	// separators are information about the original secret — choose this
	// only when downstream consumers need format fidelity.
	MaskFormatPreserving = MaskStrategy(core.MaskFormatPreserving)
)

// String returns the strategy name.
func (m MaskStrategy) String() string { return core.MaskStrategy(m).String() }

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
	//
	// A panic inside Validate does not propagate out of Redact: it is
	// caught and returned as an error naming this rule, so a faulty
	// validator cannot crash a process that redacts untrusted input.
	// The panic value never appears in the error (errors never contain
	// input bytes), the reported span is defensively clamped to window,
	// and output already written before the panic remains valid redacted
	// output.
	//
	// When one Engine serves concurrent Redact calls, Validate is
	// invoked concurrently from each call's own goroutine — like
	// Config.OnFinding, it must be safe for concurrent use if the
	// Engine is shared. Pure functions of the window are naturally safe.
	Validate func(window []byte, trigStart, trigEnd int) (start, end int, ok bool)
}

// Finding describes one confirmed and redacted secret occurrence.
//
// A Finding never contains the matched secret value, only its location and
// the rule that confirmed it. Offsets refer to byte positions in the
// original (unredacted) input stream.
type Finding struct {
	// RuleID is the stable identifier of the rule that confirmed the
	// secret, e.g. "aws-access-key-id".
	RuleID string

	// Confidence is the confidence level of the confirming rule.
	Confidence Confidence

	// Start is the byte offset of the first redacted byte in the input.
	Start int64

	// End is the byte offset one past the last redacted byte in the input.
	End int64
}

// Stats summarises one Redact call. It never contains matched input bytes.
// The JSON field names use snake_case, matching the CLI's directory-report
// schema.
type Stats struct {
	// BytesRead is the total number of input bytes consumed.
	BytesRead int64 `json:"bytes_read"`

	// BytesWritten is the total number of output bytes produced.
	BytesWritten int64 `json:"bytes_written"`

	// Candidates is the number of trigger/rule pairs submitted to a
	// validator. It is useful for operational and benchmark telemetry and
	// never exposes input contents.
	Candidates int64 `json:"candidates"`

	// Findings is the number of confirmed, redacted secret spans.
	Findings int64 `json:"findings"`

	// RedactedBytes is the total number of input bytes replaced by
	// redaction markers.
	RedactedBytes int64 `json:"redacted_bytes"`

	// ByRule maps rule IDs to the number of confirmed findings attributed
	// to that rule. It is nil when there are no findings.
	ByRule map[string]int64 `json:"by_rule,omitempty"`
}

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

// ErrInvalidConfig is returned (wrapped, with detail that never includes
// input data) by New when the configuration is invalid.
var ErrInvalidConfig = core.ErrInvalidConfig

// ReadError wraps an error returned by the source io.Reader, so callers
// can distinguish source I/O failures from configuration or destination
// failures (see the package documentation's Errors section). The wrapped
// error is produced by the caller's own reader and is preserved unmodified
// for errors.Is/As; goredact itself never puts scanned input bytes in an
// error.
type ReadError struct{ Err error }

func (e *ReadError) Error() string { return "goredact: read: " + e.Err.Error() }
func (e *ReadError) Unwrap() error { return e.Err }

// WriteError wraps an error returned by the destination io.Writer, so
// callers can distinguish destination I/O failures from configuration or
// source failures (see the package documentation's Errors section). The
// wrapped error is produced by the caller's own writer and is preserved
// unmodified for errors.Is/As; goredact itself never puts scanned input
// bytes in an error.
type WriteError struct{ Err error }

func (e *WriteError) Error() string { return "goredact: write: " + e.Err.Error() }
func (e *WriteError) Unwrap() error { return e.Err }

// Engine detects and redacts secrets from byte streams.
//
// An Engine is immutable after construction and safe for concurrent use by
// multiple goroutines; each Redact call maintains independent scan state.
type Engine struct {
	inner *core.Engine
}

// New compiles the active rule set for the configuration and returns a
// reusable Engine.
func New(cfg Config) (*Engine, error) {
	inner, err := core.New(toCoreConfig(cfg))
	if err != nil {
		return nil, err
	}
	return &Engine{inner: inner}, nil
}

// Redact copies src to dst, replacing every confirmed secret according to
// the configured MaskStrategy (by default, one copy of Config.Marker per
// secret), and returns statistics about the scan.
//
// Redact streams: it never buffers more than a bounded window of input and
// never writes unredacted data to temporary storage. It returns the first
// error encountered: ctx.Err() on cancellation, a *ReadError on source
// failure, a *WriteError on destination failure, or an error when a custom
// rule's Validate panics (see CustomRule). On error, output already
// written remains valid redacted output; no unredacted confirmed secret
// has been emitted.
//
// ctx is polled once per read iteration: cancellation cannot interrupt a
// call already blocked inside src.Read.
func (e *Engine) Redact(ctx context.Context, dst io.Writer, src io.Reader) (Stats, error) {
	stats, err := e.inner.Redact(ctx, dst, src)
	return fromCoreStats(stats), fromCoreError(err)
}

// RuleSetVersion reports the version identifier of the compiled built-in
// rule set, for inclusion in caller diagnostics.
func (e *Engine) RuleSetVersion() string { return e.inner.RuleSetVersion() }

// ActiveRules returns the rules compiled into e — the effective result of
// applying Config.Profile, EnableRules, DisableRules, and CustomRules —
// sorted by ID. The returned slice is a copy owned by the caller; mutating
// it does not affect e, and no internal engine state is exposed.
func (e *Engine) ActiveRules() []RuleInfo {
	return fromCoreRuleInfos(e.inner.ActiveRules())
}

// BuiltinRules returns every built-in rule this version of goredact ships,
// regardless of profile, sorted by ID. Use (*Engine).ActiveRules to see
// the rules compiled into a specific Engine.
func BuiltinRules() []RuleInfo {
	return fromCoreRuleInfos(core.BuiltinRules())
}

// --- Conversions between the public API types above and their internal
// implementation-package counterparts. Kept in one place because several
// public types (Config, CustomRule, Finding, RuleInfo) nest other public
// named types (Profile, Confidence) that are not identical to their core
// counterparts, so plain struct conversion is not available for them.

func toCoreConfig(cfg Config) core.Config {
	coreCfg := core.Config{
		Profile:       core.Profile(cfg.Profile),
		ChunkSize:     cfg.ChunkSize,
		Marker:        cfg.Marker,
		MaskStrategy:  core.MaskStrategy(cfg.MaskStrategy),
		EnableRules:   cfg.EnableRules,
		DisableRules:  cfg.DisableRules,
		CustomRules:   toCoreCustomRules(cfg.CustomRules),
		RecordAligned: cfg.RecordAligned,
	}
	if cfg.OnFinding != nil {
		onFinding := cfg.OnFinding
		coreCfg.OnFinding = func(f core.Finding) { onFinding(fromCoreFinding(f)) }
	}
	return coreCfg
}

func toCoreCustomRules(in []CustomRule) []core.CustomRule {
	if in == nil {
		return nil
	}
	out := make([]core.CustomRule, len(in))
	for i, r := range in {
		out[i] = core.CustomRule{
			ID:            r.ID,
			Triggers:      r.Triggers,
			CaseFold:      r.CaseFold,
			Confidence:    core.Confidence(r.Confidence),
			MaxLookbehind: r.MaxLookbehind,
			MaxLookahead:  r.MaxLookahead,
			Validate:      r.Validate,
		}
	}
	return out
}

func fromCoreFinding(f core.Finding) Finding {
	return Finding{
		RuleID:     f.RuleID,
		Confidence: Confidence(f.Confidence),
		Start:      f.Start,
		End:        f.End,
	}
}

func fromCoreStats(s core.Stats) Stats {
	return Stats{
		BytesRead:     s.BytesRead,
		BytesWritten:  s.BytesWritten,
		Candidates:    s.Candidates,
		Findings:      s.Findings,
		RedactedBytes: s.RedactedBytes,
		ByRule:        s.ByRule,
	}
}

func fromCoreRuleInfos(in []core.RuleInfo) []RuleInfo {
	out := make([]RuleInfo, len(in))
	for i, r := range in {
		out[i] = RuleInfo{
			ID:         r.ID,
			Name:       r.Name,
			Confidence: Confidence(r.Confidence),
			MinProfile: Profile(r.MinProfile),
			Custom:     r.Custom,
		}
	}
	return out
}

func fromCoreError(err error) error {
	if err == nil {
		return nil
	}
	var readErr *core.ReadError
	if errors.As(err, &readErr) {
		return &ReadError{Err: readErr.Err}
	}
	var writeErr *core.WriteError
	if errors.As(err, &writeErr) {
		return &WriteError{Err: writeErr.Err}
	}
	return err
}
