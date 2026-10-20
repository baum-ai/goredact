package goredact

// This file implements the bounded-memory streaming engine behind
// Engine.Redact.
//
// The engine keeps a single fixed buffer of cfg.ChunkSize bytes holding a
// sliding window [bufBase, bufEnd) of the input. Each loop iteration
// reads into the buffer's free tail, scans only the newly read bytes with
// the resumable Aho–Corasick state, validates trigger candidates whose
// full lookahead window is buffered (queueing the rest), releases
// finalized spans from the collector, and emits the safe prefix of the
// buffer through span.Writer. The engine never creates temporary files:
// input flows exclusively reader -> fixed buffer -> writer.
//
// Safety invariants, with window = rules.Set.MaxWindow():
//
//   - Release limit: pre-EOF, spans are released at bufEnd-window (any
//     future trigger match ends past bufEnd, so any future span starts
//     after bufEnd-window; queued candidates likewise have their window
//     start beyond bufEnd-window, and the limit is defensively capped to
//     the earliest queued candidate's window start anyway). At EOF the
//     limit is the total input length.
//   - Emission frontier: plain bytes are emitted up to
//     min(releaseLimit, earliest held collector span Start) — a held
//     span may still grow, so nothing at or past its Start may be
//     emitted yet.
//   - Buffer retention: everything from min(emitted, earliest relevant
//     window start) is retained; because emitted never passes
//     bufEnd-window pre-EOF, compacting the buffer down to the emission
//     frontier always retains at least the last window bytes.
//
// A chain of overlapping/adjacent confirmed spans can merge into a span
// longer than the buffer. Its interior bytes can never reach the output
// (the whole merged span becomes one marker) and are never needed for a
// validation window (windows only reach back `window` bytes), so under
// buffer pressure the engine discards them, tracking a "gap"
// (bufBase > emitted) that is later emitted as zero-filled scratch while
// replaying the released covering span: under MaskFixedMarker the Writer
// never reads those bytes, and under the preserving strategies the zero
// bytes mask to '*', so discarded input can never reach the output either
// way.
//
// Block rules (rules.Block, the private-key rules) mask a delimited block
// to its end however long it is. Begin confirms the block within the
// trigger's window; when the block runs past that window, the confirmed
// span ends at a resume point and the engine queues a continuation
// candidate there. Validating it (Extend) adds the adjacent span — the
// collector merges the two — and either closes the block or queues the
// next continuation. A continuation behaves like any queued candidate with
// no lookbehind and a zero-length trigger at its resume point, so the
// invariants above hold unchanged: the release limit stays below it, the
// held block span pins emission at its start, and under buffer pressure
// the block's interior is discarded as a gap. Memory stays bounded; output
// inside an open block waits for the block to end.
//
// Every trigger is followed on its own, so a key nested in another (whose
// scan may stop earlier, or on a different END line) is masked to its own
// end. To keep the work linear, continuation windows end on a fixed grid
// of absolute offsets (blockWindowEnd): two scans of the same rule over
// the same bytes stop at the same places, and once their states agree — a
// PEM scan's do after both have seen a plausible base64 run — they reach
// the same (resume point, state), whose future is identical. The second
// to get there stops (seenConts), so a nested key costs its own trigger
// window and about one grid cell more.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/baum-ai/goredact/internal/ahocorasick"
	"github.com/baum-ai/goredact/internal/rules"
	"github.com/baum-ai/goredact/internal/span"
)

// maxConsecutiveZeroReads bounds how many times in a row a misbehaving
// io.Reader may return (0, nil) before the engine gives up with
// io.ErrNoProgress instead of spinning forever (same policy as bufio).
const maxConsecutiveZeroReads = 100

// errBadReadCount reports a reader that returned an out-of-range byte
// count. It never contains input bytes.
var errBadReadCount = errors.New("reader returned an invalid byte count")

// compileTriggers collects the unique (Literal, CaseFold) trigger pairs
// across the active rule set into one Aho–Corasick automaton and builds
// the pattern->rules dispatch table. Case-folded literals are deduplicated
// case-insensitively, since the automaton matches them identically.
func (e *Engine) compileTriggers() error {
	type trigKey struct {
		lit  string
		fold bool
	}
	var patterns []ahocorasick.Pattern
	index := make(map[trigKey]int)
	for ri, r := range e.rules.Rules {
		for _, t := range r.Triggers {
			k := trigKey{lit: t.Literal, fold: t.CaseFold}
			if t.CaseFold {
				k.lit = asciiLower(t.Literal)
			}
			pi, ok := index[k]
			if !ok {
				pi = len(patterns)
				index[k] = pi
				patterns = append(patterns, ahocorasick.Pattern{Literal: t.Literal, CaseFold: t.CaseFold})
				e.patLen = append(e.patLen, len(t.Literal))
				e.dispatch = append(e.dispatch, nil)
			}
			if rs := e.dispatch[pi]; len(rs) > 0 && rs[len(rs)-1] == ri {
				continue // the same rule listed this trigger twice
			}
			e.dispatch[pi] = append(e.dispatch[pi], ri)
		}
	}
	if len(patterns) == 0 {
		// No active rules: Redact degenerates to a plain copy.
		return nil
	}
	ac, err := ahocorasick.Compile(patterns)
	if err != nil {
		return fmt.Errorf("%w: compiling trigger automaton: %v", ErrInvalidConfig, err)
	}
	e.matcher = ac
	return nil
}

// asciiLower folds 'A'..'Z' to lowercase, matching the automaton's ASCII
// case-folding semantics exactly (unlike strings.ToLower, which is
// Unicode-aware).
func asciiLower(s string) string {
	lowered := []byte(s)
	changed := false
	for i, c := range lowered {
		if c >= 'A' && c <= 'Z' {
			lowered[i] = c + ('a' - 'A')
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(lowered)
}

// candidate is a trigger occurrence for one rule, in absolute input
// offsets. Candidates whose lookahead window is not yet fully buffered
// wait in the pending queue until enough input arrives or EOF.
//
// A continuation candidate (cont) carries an open block forward: its
// zero-length trigger sits at the resume point, it has no lookbehind, and
// state is the block scanner's state.
type candidate struct {
	rule               int
	trigStart, trigEnd int64
	cont               bool
	state              uint64
}

// windowStart returns the absolute offset at which c's validation window
// begins.
func (c *candidate) windowStart(rules []rules.Rule) int64 {
	if c.cont {
		return c.trigStart
	}
	return c.trigStart - int64(rules[c.rule].MaxLookbehind)
}

// windowEnd returns the absolute offset one past c's full validation
// window: MaxLookahead past the trigger, or, for a continuation, the
// block grid point blockWindowEnd chooses.
func (c *candidate) windowEnd(rules []rules.Rule) int64 {
	la := int64(rules[c.rule].MaxLookahead)
	if c.cont {
		return blockWindowEnd(c.trigStart, la)
	}
	return c.trigEnd + la
}

// Continuation windows end on multiples of blockGrid, at least
// blockMinStep past their resume point (and never past the rule's
// lookahead, so the retained overlap still covers them).
const (
	blockGrid    = 4096
	blockMinStep = 1024
)

// blockWindowEnd returns where a continuation window resuming at at ends.
// The end depends only on at's grid cell, which is what lets two scans of
// the same bytes meet at the same resume points.
func blockWindowEnd(at, lookahead int64) int64 {
	end := (at + blockMinStep + blockGrid - 1) / blockGrid * blockGrid
	return min(end, at+lookahead)
}

// contKey identifies a continuation: a scan of rule resuming at at with a
// scanner state. Two continuations with the same key have the same future.
type contKey struct {
	rule  int
	at    int64
	state uint64
}

// scanState holds the pooled, reusable per-Redact allocations. All fields
// are reset (length zero) before reuse; capacities are retained across
// calls on the same Engine.
type scanState struct {
	// buf is the fixed input buffer (capacity cfg.ChunkSize). It holds
	// the input range [bufBase, bufBase+len(buf)).
	buf []byte

	// pending queues candidates awaiting lookahead. Structurally bounded:
	// a candidate only waits while its trigger lies within the last
	// `window` buffered bytes, so the queue holds at most
	// O(window * len(patterns)) entries.
	pending []candidate

	// released receives spans from Collector.Release and carries the few
	// spans (if any) whose Start lies at or beyond the emission limit
	// over to the next emission.
	released []span.Span

	// scratch is zero-filled backing data fed to span.Writer for
	// discarded span-interior bytes ("gap" emission). Allocated lazily on
	// first use and never written to, so it stays zero: even if an
	// invariant were violated, discarded input bytes could not leak.
	scratch []byte

	// seenConts records the continuations created so far, so a scan that
	// reaches one another scan already reached stops there. Entries before
	// the retained buffer are pruned on flush: no scan resumes there any
	// more.
	seenConts map[contKey]struct{}

	coll span.Collector
}

func (s *scanState) reset() {
	s.buf = s.buf[:0]
	s.pending = s.pending[:0]
	s.released = s.released[:0]
	clear(s.seenConts)
	s.coll.Reset()
}

// scanRun is the per-Redact state that is not worth pooling.
type scanRun struct {
	e   *Engine
	st  *scanState
	w   *span.Writer
	src io.Reader

	stats Stats

	// bufBase is the absolute input offset of st.buf[0]. emitted is the
	// absolute offset up to which output has been produced; it is always
	// <= bufBase+len(buf), and normally >= bufBase, except while a "gap"
	// of discarded span-interior bytes is outstanding (emitted < bufBase).
	bufBase int64
	emitted int64

	// acState resumes the trigger automaton across reads; scanBase is the
	// absolute offset of the region handed to the current Scan call.
	acState  ahocorasick.State
	scanBase int64
	scanFn   func(pattern, end int) bool

	// scanErr records the first error produced by a validator (a panic
	// converted by callValidate) during a Scan callback. run checks it
	// after each scan and aborts Redact with it.
	scanErr error
}

// redact implements Engine.Redact. See the file comment for the
// algorithm and its invariants.
func (e *Engine) redact(ctx context.Context, dst io.Writer, src io.Reader) (Stats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	st := e.states.Get().(*scanState)
	st.reset()
	defer e.states.Put(st)

	r := &scanRun{e: e, st: st, w: span.NewMaskingWriter(dst, e.marker, e.cfg.MaskStrategy.internal()), src: src}
	r.scanFn = r.onTrigger
	err := r.run(ctx)
	r.stats.BytesWritten = r.w.BytesWritten()
	r.stats.RedactedBytes = r.w.RedactedBytes()
	return r.stats, err
}

// bufEnd returns the absolute offset one past the last buffered byte.
func (r *scanRun) bufEnd() int64 { return r.bufBase + int64(len(r.st.buf)) }

// run is the streaming loop: read, scan, validate, release, emit.
func (r *scanRun) run(ctx context.Context) error {
	zeroReads := 0
	for {
		// Context is checked once per read iteration, between chunks.
		// It is returned unwrapped, per the Redact contract.
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.makeRoom(); err != nil {
			return err
		}
		buf := r.st.buf
		free := buf[len(buf):cap(buf)]
		n, rerr := r.src.Read(free)
		if n < 0 || n > len(free) {
			return &ReadError{Err: errBadReadCount}
		}
		if n > 0 {
			zeroReads = 0
			r.scanBase = r.bufEnd()
			r.st.buf = buf[:len(buf)+n]
			r.stats.BytesRead += int64(n)
			// Queued candidates go first, so an open block's continuation
			// follows it into the new bytes before their triggers are
			// dispatched: a trigger inside that block then sees it covered
			// (see blockEnd). Either order yields the same spans otherwise.
			if err := r.validatePending(false); err != nil {
				return err
			}
			r.scanNew()
			if r.scanErr != nil {
				return r.scanErr
			}
		}
		switch {
		case rerr == io.EOF:
			// Validate the remaining queue against truncated windows
			// (validators handle short windows safely), then release and
			// emit everything.
			if err := r.validatePending(true); err != nil {
				return err
			}
			return r.flush(true)
		case rerr != nil:
			// Emit whatever is already safe (best effort — a write
			// failure here cannot make the output unsafe, only shorter),
			// then surface the read failure.
			_ = r.flush(false)
			return &ReadError{Err: rerr}
		case n == 0:
			zeroReads++
			if zeroReads >= maxConsecutiveZeroReads {
				return &ReadError{Err: io.ErrNoProgress}
			}
			continue
		}
		if err := r.flush(false); err != nil {
			return err
		}
	}
}

// scanNew runs the trigger automaton over the newly read bytes only,
// resuming from the persistent state.
func (r *scanRun) scanNew() {
	if r.e.matcher == nil {
		return
	}
	chunk := r.st.buf[r.scanBase-r.bufBase:]
	r.acState = r.e.matcher.Scan(r.acState, chunk, r.scanFn)
}

// onTrigger dispatches one automaton match to every rule sharing the
// trigger, validating immediately when the rule's full lookahead window is
// buffered and queueing the candidate otherwise.
func (r *scanRun) onTrigger(pattern, end int) bool {
	trigEnd := r.scanBase + int64(end)
	trigStart := trigEnd - int64(r.e.patLen[pattern])
	if trigStart < r.bufBase {
		// Unreachable: MaxWindow includes the trigger length, so the
		// retained overlap always covers a boundary-spanning trigger.
		// Guarded so a violated assumption drops the candidate instead of
		// slicing out of range.
		return true
	}
	be := r.bufEnd()
	for _, ri := range r.e.dispatch[pattern] {
		if r.scanErr != nil {
			// A validator panicked: stop validating further candidates.
			// The scan is abandoned with this error, so the early return's
			// (unresumable) automaton state is never used.
			return true
		}
		c := candidate{rule: ri, trigStart: trigStart, trigEnd: trigEnd}
		if c.windowEnd(r.e.rules.Rules) <= be {
			if err := r.validateChain(c, false); err != nil {
				r.scanErr = err
			}
		} else {
			r.st.pending = append(r.st.pending, c)
		}
	}
	return true
}

// validatePending validates every queued candidate whose lookahead window
// is now fully buffered (or all of them, with truncated windows, at EOF)
// and compacts the queue in place.
//
// Continuations go first, so an open block reaches the newly buffered
// bytes before a scan started by a trigger in them can: the open block
// then holds the continuation points any later scan of the same bytes
// meets (seenConts), whichever order the two were queued in. The order of
// validation does not change the spans.
func (r *scanRun) validatePending(eof bool) error {
	for _, conts := range [2]bool{true, false} {
		if len(r.st.pending) == 0 {
			return nil
		}
		be := r.bufEnd()
		// Validation can queue continuations, which validateChain appends
		// to pending: iterate over the entries present on entry only,
		// compacting them in place, then keep whatever was appended after
		// them.
		n := len(r.st.pending)
		kept := 0
		for i := 0; i < n; i++ {
			c := r.st.pending[i]
			if c.cont == conts && (eof || c.windowEnd(r.e.rules.Rules) <= be) {
				if err := r.validateChain(c, eof); err != nil {
					return err
				}
			} else {
				r.st.pending[kept] = c
				kept++
			}
		}
		added := copy(r.st.pending[kept:], r.st.pending[n:])
		r.st.pending = r.st.pending[:kept+added]
	}
	return nil
}

// validateChain validates c and, while that leaves a block open with the
// next window already buffered (or at EOF), validates the continuation
// too. A continuation whose window is not buffered yet is queued. A
// continuation another scan already reached ends the chain: that scan
// masks everything this one would.
func (r *scanRun) validateChain(c candidate, eof bool) error {
	for {
		next, open, err := r.validate(c)
		if err != nil || !open {
			return err
		}
		key := contKey{rule: next.rule, at: next.trigStart, state: next.state}
		if _, seen := r.st.seenConts[key]; seen {
			return nil
		}
		if r.st.seenConts == nil {
			r.st.seenConts = make(map[contKey]struct{})
		}
		r.st.seenConts[key] = struct{}{}
		if !eof && next.windowEnd(r.e.rules.Rules) > r.bufEnd() {
			r.st.pending = append(r.st.pending, next)
			return nil
		}
		c = next
	}
}

// validate runs one rule's validator over the candidate's bounded window
// and adds a confirmed span to the collector. Validators are pure and
// bounded, so they run synchronously on the scan path. A panic inside a
// validator (only possible with caller-supplied custom rules) is converted
// by callValidate into an error naming the rule, which aborts Redact.
//
// For a block rule it reports, with open, a block that runs past the
// window, and next, the continuation candidate that carries it on.
func (r *scanRun) validate(c candidate) (next candidate, open bool, err error) {
	rule := &r.e.rules.Rules[c.rule]
	wStart := c.windowStart(r.e.rules.Rules)
	if wStart < r.bufBase {
		wStart = r.bufBase
	}
	full := c.windowEnd(r.e.rules.Rules)
	wEnd := full
	if be := r.bufEnd(); wEnd > be {
		wEnd = be
	}
	window := r.st.buf[wStart-r.bufBase : wEnd-r.bufBase]
	// A window cut short of its lookahead ends at the end of input:
	// candidates are only validated early at EOF.
	final := wEnd < full

	var (
		s, en int
		ok    bool
		state uint64
	)
	switch {
	case c.cont:
		en, state, open, err = callExtend(rule, window, c.state, final)
		ok = en > 0
	case rule.Block != nil:
		r.stats.Candidates++
		s, en, state, open, ok, err = callBegin(rule, window, int(c.trigStart-wStart), int(c.trigEnd-wStart), final)
	default:
		r.stats.Candidates++
		s, en, ok, err = callValidate(rule, window, int(c.trigStart-wStart), int(c.trigEnd-wStart))
	}
	if err != nil {
		return candidate{}, false, err
	}
	// An open block must resume strictly inside its window, past where
	// this window started, or the chain would not progress.
	if open && (!ok || en <= int(c.trigEnd-wStart) || en > len(window)) {
		open = false
	}
	if open {
		resume := wStart + int64(en)
		next = candidate{rule: c.rule, trigStart: resume, trigEnd: resume, cont: true, state: state}
	}
	if !ok {
		return next, open, nil
	}
	// Clamp defensively: a validator must report a range within its
	// window, but a buggy custom validator must not crash the engine or
	// leak bytes outside the window.
	if s < 0 {
		s = 0
	}
	if en > len(window) {
		en = len(window)
	}
	if s >= en {
		return next, open, nil
	}
	r.st.coll.Add(span.Span{
		Start:      wStart + int64(s),
		End:        wStart + int64(en),
		Rule:       c.rule,
		Confidence: uint8(rule.Confidence),
	})
	return next, open, nil
}

// callValidate invokes rule.Validate, converting a panic into an error that
// names the rule instead of letting it crash the process. The panic value
// is deliberately not included in the error: it may be input-derived, and
// goredact errors never contain input bytes (see errors.go).
func callValidate(rule *rules.Rule, window []byte, trigStart, trigEnd int) (s, en int, ok bool, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("goredact: rule %q: Validate panicked", rule.ID)
		}
	}()
	s, en, ok = rule.Validate(window, trigStart, trigEnd)
	return s, en, ok, nil
}

// callBegin invokes a block rule's Begin with the same panic conversion
// as callValidate.
func callBegin(rule *rules.Rule, window []byte, trigStart, trigEnd int, final bool) (s, en int, state uint64, open, ok bool, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("goredact: rule %q: Validate panicked", rule.ID)
		}
	}()
	s, en, state, open, ok = rule.Block.Begin(window, trigStart, trigEnd, final)
	return s, en, state, open, ok, nil
}

// callExtend invokes a block rule's Extend with the same panic conversion
// as callValidate.
func callExtend(rule *rules.Rule, window []byte, state uint64, final bool) (en int, next uint64, open bool, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("goredact: rule %q: Validate panicked", rule.ID)
		}
	}()
	en, next, open = rule.Block.Extend(window, state, final)
	return en, next, open, nil
}

// flush releases every span that can no longer grow, records findings,
// and emits the safe prefix of the buffer.
func (r *scanRun) flush(eof bool) error {
	for k := range r.st.seenConts {
		if k.at < r.bufBase {
			delete(r.st.seenConts, k)
		}
	}
	be := r.bufEnd()
	releaseLimit := be
	if !eof {
		releaseLimit = be - int64(r.e.window)
		// Defensive: never release at or past a queued candidate's window
		// start. Structurally this never binds — a candidate only queues
		// while its lookahead extends past bufEnd, which places its
		// window start strictly beyond bufEnd-window — but the Release
		// contract (no later Add with Start <= limit; see
		// span.Collector.Release) depends on it, so enforce it, capping
		// to ws-1 because a span produced from the candidate may start
		// exactly at ws.
		for i := range r.st.pending {
			if ws := r.st.pending[i].windowStart(r.e.rules.Rules); ws <= releaseLimit {
				releaseLimit = ws - 1
			}
		}
	}

	prev := len(r.st.released)
	r.st.released = r.st.coll.Release(r.st.released, releaseLimit)
	r.recordFindings(r.st.released[prev:])

	emitLimit := releaseLimit
	if held, ok := r.st.coll.Earliest(); ok && held.Start < emitLimit {
		emitLimit = held.Start
	}
	if r.e.recordAligned && !eof {
		emitLimit = r.alignToRecord(emitLimit)
	}
	if emitLimit <= r.emitted {
		return nil
	}
	if err := r.emitTo(emitLimit); err != nil {
		return &WriteError{Err: err}
	}
	// Compact lazily: dropping the emitted prefix costs a copy of the
	// retained tail, so only do it once at least half the buffer is
	// reclaimable (makeRoom forces it when the buffer is full).
	if drop := r.emitted - r.bufBase; drop > 0 && drop >= int64(cap(r.st.buf))/2 {
		r.compact()
	}
	return nil
}

// recordFindings updates Stats and invokes the OnFinding callback for
// newly released (merged, input-ordered) spans. Attribution comes from the
// collector's winning rule.
func (r *scanRun) recordFindings(released []span.Span) {
	for _, s := range released {
		r.stats.Findings++
		id := r.e.rules.Rules[s.Rule].ID
		if r.stats.ByRule == nil {
			r.stats.ByRule = make(map[string]int64)
		}
		r.stats.ByRule[id]++
		if r.e.cfg.OnFinding != nil {
			r.e.cfg.OnFinding(Finding{
				RuleID:     id,
				Confidence: Confidence(s.Confidence),
				Start:      s.Start,
				End:        s.End,
			})
		}
	}
}

// emitTo feeds the input range [emitted, limit) to the span.Writer,
// passing each released span exactly once — in the Emit call whose region
// contains the span's Start (the Writer handles straddling internally).
// Spans starting at or past limit are carried to a later emission.
func (r *scanRun) emitTo(limit int64) error {
	spans := r.st.released
	used := 0

	// Gap emission: bytes in [emitted, bufBase) were discarded under
	// buffer pressure (see makeRoom). They are interior bytes of the
	// released span that starts exactly at the emission frontier, so the
	// Writer replaces them with the marker and never reads the data;
	// zero-filled scratch stands in for them.
	for r.emitted < r.bufBase && r.emitted < limit {
		if r.st.scratch == nil {
			r.st.scratch = make([]byte, 32*1024)
		}
		segEnd := r.bufBase
		if limit < segEnd {
			segEnd = limit
		}
		n := segEnd - r.emitted
		if max := int64(len(r.st.scratch)); n > max {
			n = max
		}
		end := r.emitted + n
		k := used
		for k < len(spans) && spans[k].Start < end {
			k++
		}
		if err := r.w.Emit(r.emitted, r.st.scratch[:n], spans[used:k]); err != nil {
			return err
		}
		used = k
		r.emitted = end
	}

	if r.emitted < limit {
		data := r.st.buf[r.emitted-r.bufBase : limit-r.bufBase]
		k := used
		for k < len(spans) && spans[k].Start < limit {
			k++
		}
		if err := r.w.Emit(r.emitted, data, spans[used:k]); err != nil {
			return err
		}
		used = k
		r.emitted = limit
	}

	// Carry not-yet-emittable spans (Start >= limit) to the next call,
	// reusing the slice's capacity.
	n := copy(spans, spans[used:])
	r.st.released = spans[:n]
	return nil
}

// compact drops the emitted prefix of the buffer by copying the retained
// tail to the front. The copy is bounded by the buffer capacity and
// amortised by only compacting when at least half the buffer (or, in
// makeRoom, anything at all) is reclaimable.
func (r *scanRun) compact() {
	drop := r.emitted - r.bufBase
	if drop <= 0 {
		return
	}
	n := copy(r.st.buf, r.st.buf[drop:])
	r.st.buf = r.st.buf[:n]
	r.bufBase += drop
}

// makeRoom guarantees free buffer space before a read. Normally emitted
// bytes are reclaimed by compaction. When the buffer is full and nothing
// has been emitted, emission is pinned by a held span starting at the
// emission frontier that is still growing (a merged chain longer than the
// buffer): its interior bytes — provably covered by the span and useless
// for future validation windows — are discarded, keeping the last
// `window` bytes and leaving a gap for emitTo to fill with scratch.
func (r *scanRun) makeRoom() error {
	if len(r.st.buf) < cap(r.st.buf) {
		return nil
	}
	r.compact()
	if len(r.st.buf) < cap(r.st.buf) {
		return nil
	}
	// Nothing reclaimable: flush once more in case spans became
	// releasable, then re-check.
	if err := r.flush(false); err != nil {
		return err
	}
	r.compact()
	if len(r.st.buf) < cap(r.st.buf) {
		return nil
	}

	keepFrom := r.bufEnd() - int64(r.e.window)
	if held, ok := r.st.coll.Earliest(); ok &&
		held.Start <= r.emitted && held.End >= keepFrom && keepFrom > r.bufBase {
		drop := keepFrom - r.bufBase
		n := copy(r.st.buf, r.st.buf[drop:])
		r.st.buf = r.st.buf[:n]
		r.bufBase = keepFrom
		return nil
	}

	// Structurally unreachable: ChunkSize >= 2*window guarantees the
	// emission frontier can otherwise advance. Grow rather than deadlock
	// on a violated invariant.
	grown := make([]byte, len(r.st.buf), 2*cap(r.st.buf))
	copy(grown, r.st.buf)
	r.st.buf = grown
	return nil
}

// alignToRecord lowers limit to one past the last '\n' at or before it
// within the retained buffer, so downstream consumers observe whole
// records. A found newline always yields a limit strictly past the
// emission frontier (progress is preserved), and when no newline is
// buffered the raw limit is returned, so alignment can never deadlock the
// stream. Enabled by Config.RecordAligned (Engine.recordAligned);
// escaped-JSON record detection builds on this.
func (r *scanRun) alignToRecord(limit int64) int64 {
	lo := r.emitted
	if r.bufBase > lo {
		lo = r.bufBase
	}
	if limit <= lo {
		return limit
	}
	seg := r.st.buf[lo-r.bufBase : limit-r.bufBase]
	if i := bytes.LastIndexByte(seg, '\n'); i >= 0 {
		return lo + int64(i) + 1
	}
	return limit
}
