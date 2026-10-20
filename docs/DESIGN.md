# Architecture — goredact

This document describes the package architecture and the invariants that
contributors must preserve. Public API documentation lives in `api.go` and
`doc.go`.

## Data flow

```
io.Reader → [chunked buffer] → Aho–Corasick matcher → trigger hits
    → rule validators (bounded windows) → confirmed spans
    → span collector (dedupe/merge/precedence) → redacting emitter → io.Writer
```

## Packages

### `internal/rules`

`Rule`, `Trigger`, `ValidateFunc`, `Set`, `Build`. Generated built-in
tables call `RegisterBuiltins` from an `init` in a generated file inside
this package. `Set.MaxWindow()` is the overlap the engine must retain.

A built-in rule may also be a block rule (`Rule.Block`): it masks a
delimited block of unbounded length — a private key — to its end marker.
`Block.Begin` confirms a candidate like `Validate` over the trigger's
bounded window and reports whether the block runs on past it; while it
does, `Block.Extend` continues the same resumable scan over each following
`MaxLookahead`-byte window, starting at the resume point and carrying a
`uint64` of scanner state:

```go
type BlockBeginFunc func(window []byte, trigStart, trigEnd int, final bool) (start, end int, state uint64, open, ok bool)
type BlockExtendFunc func(window []byte, state uint64, final bool) (end int, next uint64, open bool)
```

`final` reports that a window ends at the end of input. An open result's
`end` is the resume point, so consecutive spans are adjacent and merge.
It is normally the last body byte decided so far, so bytes after it are
masked only if the block goes on past them; where that would not advance
the scan (a long run of separators, a backslash run or a line longer than
the window), it is where the scan stopped, and the bytes before it are
masked with the block. Detection stays window-bounded: only the masked
extent is unbounded, and chained scans mask at least what one unbounded
scan would, and at most a window and a line more (fuzzed by
`FuzzBlockChainMatchesWholeScan`). `Validate` stays required for block
rules and equals `Begin` with `final` set.

### `internal/ahocorasick`

Pure-Go Aho–Corasick over bytes. Contract:

```go
type Pattern struct {
    Literal  string // non-empty
    CaseFold bool   // ASCII case-insensitive match
}

func Compile(patterns []Pattern) (*Automaton, error)

// State carries matcher position across chunk boundaries. Zero value =
// automaton root (start state).
type State uint32

// Scan advances through chunk, invoking fn for every pattern occurrence
// (including overlapping ones) with the pattern index (into the Compile
// slice) and the exclusive end offset of the match within chunk. A match
// that started in a previous chunk reports end < pattern length; the
// caller reconstructs absolute offsets. fn returning false stops the scan
// early. Scan performs no heap allocation.
func (a *Automaton) Scan(s State, chunk []byte, fn func(pattern int, end int) bool) State
```

- Automaton is immutable after Compile; concurrent Scans are race-free.
- Case folding: fold both pattern and input bytes 'A'..'Z' → 'a'..'z' for
  CaseFold patterns; case-sensitive patterns must still match exactly
  (build the automaton over folded bytes with post-check, or dual-plane
  goto — implementation's choice, as long as both semantics hold).
- Overlapping matches via output links (dictionary suffix links).

### `internal/span`

Confirmed-span collection, merge, precedence, ordered release.

```go
type Span struct {
    Start, End int64 // absolute input offsets, half-open
    Rule       int   // index into the active rule set
    Confidence uint8
}

// Collector accumulates spans out of order and releases them in order.
type Collector struct{ ... }

func (c *Collector) Add(s Span)             // dedupes identical spans
// Release appends to dst all merged spans that end at or before limit and
// cannot grow further, removing them from the collector. Returned spans
// are sorted by Start and non-overlapping.
func (c *Collector) Release(dst []Span, limit int64) []Span
func (c *Collector) Pending() bool
func (c *Collector) Reset()
```

Merge/precedence rules (deterministic):
1. Identical spans (same Start/End) dedupe; keep highest Confidence, then
   lowest Rule index.
2. Overlapping or adjacent (End == Start) spans merge into their union;
   attribution goes to the higher-Confidence span, tie → earlier Start,
   tie → lower Rule index.
3. Released output is sorted by Start; no two released spans overlap.

### `internal/goredact`

Implements the streaming loop and the engine exposed through aliases and
constructors in the module-root package.

Requirements:
- Fixed ring/sliding buffer of ChunkSize + MaxWindow overlap.
- Trigger hits whose lookahead window is not yet fully buffered are
  deferred until more input arrives or EOF.
- Emission frontier: bytes may be written once `pos + MaxWindow` has been
  read (or EOF), after applying released spans; each span is replaced per
  `Config.MaskStrategy` (one fixed marker by default, or byte-for-byte
  masked replacements under the preserving strategies).
- Context checked between chunks. Reader errors → *ReadError, writer
  errors → *WriteError, ctx.Err() preserved.
- No temporary files. No allocation proportional to input size.
- Block rules: an open block queues a continuation candidate at its resume
  point (zero-length trigger, no lookbehind), validated like any queued
  candidate once its window is buffered. Its held span pins emission at the
  block's start, so output inside an open block waits for its end; under
  buffer pressure the block's interior is discarded as a gap, keeping memory
  bounded. Every trigger is followed on its own, so a key nested in another
  is masked to its own end. Continuation windows end on a fixed grid of
  absolute offsets (4 KiB cells, at least 2 KiB past the resume point, more
  than the longest PEM armor header line), so scans of the same rule over
  the same bytes stop at the same places; once their states agree they
  reach the same (resume point, state), and the later scan stops there
  (`seenConts`, pruned behind the buffer). A nested key therefore costs its
  trigger window and about one grid cell more: the work stays linear.
  Queued candidates, continuations first, are validated before newly read
  bytes are scanned.

## Cross-cutting invariants (enforced by tests/fuzz)

1. Confirmed span bytes never appear in output. (Exception, by explicit
   opt-in only: `MaskFormatPreserving` passes a span's separator bytes
   — `- _ . : / + = @` — through verbatim and preserves each byte's
   coarse character class; `MaskLengthPreserving` discloses only the
   span's length. The default `MaskFixedMarker` discloses nothing.)
2. Output equals input outside redacted spans.
3. Chunked and unchunked scans of the same input are byte-identical.
4. Same input+config → same output (chunk-size independence). (Exception:
   under the preserving strategies, the interior of a merged span longer
   than the buffer, such as a private key larger than `ChunkSize`, is
   discarded and emitted as `*` bytes, so its masked shape depends on the
   chunk size. It is masked either way.)
5. Errors/log strings never embed input bytes.
6. Any byte sequence is safe: no panics, bounded memory.

## Conventions

- Zero external dependencies (stdlib only) for the library.
- Table-driven tests; fuzz targets under `*_fuzz_test.go` with `FuzzXxx`.
- Benchmarks report MB/s via `b.SetBytes`.
