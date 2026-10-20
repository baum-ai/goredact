package validators

// Private-key material validators: PEM-encapsulated private keys
// (raw multi-line and JSON-escaped single-line forms) and PuTTY PPK
// private-key sections, in plain text and in unified diff patches.
//
// Both rules are block rules (rules.Block). The engine confirms a candidate
// with the Begin function over the trigger's bounded window, exactly as a
// window validator would, and while the block runs on past that window it
// continues the same scan with the Extend function over each following
// window, so a key is masked to its end however long it is. The window
// validators PEMPrivateKey and PuTTYPrivateKey are Begin with final set:
// the scan treats the end of the window as the end of input.
//
// Scans are resumable state machines over tokens. A non-final scan stops
// once it reaches the last pemResumeReserve bytes of its window (PEM), or a
// line the window cuts (PPK), and reports the block open up to the last
// body byte it has decided: the last base64 byte (PEM) or the end of the
// last counted body line (PPK). The next window starts there, with a
// snapshot of the scanner state at that byte (a uint64), and reads the
// bytes after it again, so every token is decided with all of its bytes in
// view and no byte is masked unless the block goes on past it. Chaining windows therefore decides every byte exactly as one
// unbounded scan would, and each window advances by nearly its whole
// length, so the total work is linear in the block's length. They must
// never panic or index out of range on any byte sequence.
//
// Span semantics, PEM:
//
//   - Full match: trigger start through the closing "-----" of the END
//     marker, extended past an immediately following ESCAPED newline (the
//     two-byte sequences `\r` and/or `\n`, covering JSON-escaped keys). A
//     real newline byte after the END marker is NOT consumed.
//   - Fail-safe: when the scan stops without an END marker — the input
//     ends, a byte that cannot be part of a PEM body appears, or a confirmed
//     body goes pemMaxGap bytes without a base64 byte — the span
//     runs from the trigger through the last base64 byte seen, provided at
//     least one plausible body run (>= 16 consecutive base64 bytes)
//     followed the header. Over-redaction is safe, leaking is not. A header
//     followed only by prose ("-----BEGIN PRIVATE KEY----- is the PEM
//     header") has no plausible run and is rejected.
//
// Span semantics, PPK: only the Private-Lines section is redacted — from
// the first byte of "Private-Lines:" through the last base64 byte of the
// last private body line (the terminating newline is not included; the
// public portion of the file is left intact). The same fail-safe applies
// once the Private-Lines header and at least one plausible body line have
// been seen.
//
// Diff patches: in a unified diff every line starts with '+', '-' or ' '.
// The PEM body grammar already accepts those bytes ('+' is base64, '-' and
// ' ' are body punctuation, and a "+-----END" line still ends the block),
// so only the line-anchored PPK grammar needs to know about them: a
// "Private-Lines:" header preceded by one marker switches the scan to diff
// mode (see PuTTYPrivateKey).

import "bytes"

const (
	// pemLabelMax bounds a BEGIN/END label scan; RFC 7468 labels are far
	// shorter, so anything longer is not a PEM marker.
	pemLabelMax = 64

	// pemPlausibleRun is the minimum length of a run of consecutive base64
	// bytes that counts as evidence of real encoded key material. Real PEM
	// and PPK body lines are 64+ bytes; prose words are far shorter.
	pemPlausibleRun = 16

	// pemMaxShortRuns bounds how many consecutive short (< pemPlausibleRun)
	// base64 runs the body scan tolerates before giving up. Encapsulated
	// PEM headers (Proc-Type:, DEK-Info:) produce at most ~10; running
	// prose produces one per word, so this both rejects prose and keeps
	// per-trigger work small on trigger floods.
	pemMaxShortRuns = 24

	// pemResumeReserve is how close to the end of a non-final window a PEM
	// scan stops, at the next token boundary, to report an open block. It
	// exceeds the longest lookahead a body token needs — an END marker:
	// "-----END " (9) + label (65 scanned) + "-----" (5) + two escapes (4)
	// = 83 bytes — so every token the scan decides is wholly in view.
	pemResumeReserve = 128

	// pemMaxGap bounds how many bytes a confirmed PEM body may hold between
	// two base64 bytes — line breaks, escapes, diff markers, header
	// punctuation, END markers of other labels. Real keys need a handful; a
	// longer gap ends the block (fail-safe, through its last base64 byte).
	// It bounds the bytes an open block holds back past its masked part, so
	// a resumed scan always progresses.
	pemMaxGap = 256

	// ppkMaxCount bounds the "Private-Lines: N" count: 1-5 digits.
	ppkMaxCount = 99999

	// ppkMaxSkippedLines bounds, in diff mode, how many lines belonging to
	// a side whose key already ended (its Private-MAC line) the scan steps
	// over while looking for the rest of the other side's key.
	ppkMaxSkippedLines = 2
)

var (
	pemDashes       = []byte("-----")
	pemEndPrefix    = []byte("-----END ")
	pemPrivateLabel = []byte("PRIVATE KEY")
	pemEscCR        = []byte(`\r`)
	pemEscLF        = []byte(`\n`)
	ppkPrivateLines = []byte("Private-Lines:")
)

// pemIsBase64 reports whether c can appear in a base64 body (standard
// alphabet plus padding).
func pemIsBase64(c byte) bool {
	return pemBase64[c]
}

// pemBase64 is pemIsBase64 as a table: body scans spend most of their time
// in base64 runs.
var pemBase64 = func() (t [256]bool) {
	for c := range t {
		t[c] = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
	}
	return t
}()

// pemIsLabelByte reports whether c can appear in a PEM BEGIN/END label
// (uppercase letters, digits, and spaces — covers "RSA PRIVATE KEY",
// "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK", ...).
func pemIsLabelByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || isDigit(c) || c == ' '
}

// pemHasAt reports whether lit occurs in window at offset pos. It never
// indexes out of range.
func pemHasAt(window []byte, pos int, lit []byte) bool {
	return pos >= 0 && pos <= len(window)-len(lit) && bytes.Equal(window[pos:pos+len(lit)], lit)
}

// pemLabelEnd scans a PEM label starting at start and returns the offset of
// the '-' that terminates it. It fails when the label runs past the window,
// exceeds pemLabelMax, or contains a non-label byte.
func pemLabelEnd(window []byte, start int) (end int, ok bool) {
	pos := start
	for {
		if pos >= len(window) || pos-start > pemLabelMax {
			return 0, false
		}
		c := window[pos]
		if c == '-' {
			return pos, true
		}
		if !pemIsLabelByte(c) {
			return 0, false
		}
		pos++
	}
}

// pemEndMarker parses a "-----END <label>-----" marker whose first '-' is
// at pos and whose label contains "PRIVATE KEY". On success it returns the
// offset one past the closing dashes, extended past an immediately
// following escaped `\r` and/or `\n` two-byte sequence (JSON-escaped keys);
// a real newline byte is never consumed.
func pemEndMarker(window []byte, pos int) (end int, ok bool) {
	if !pemHasAt(window, pos, pemEndPrefix) {
		return 0, false
	}
	labelStart := pos + len(pemEndPrefix)
	labelEnd, ok := pemLabelEnd(window, labelStart)
	if !ok {
		return 0, false
	}
	if !bytes.Contains(window[labelStart:labelEnd], pemPrivateLabel) {
		return 0, false
	}
	if !pemHasAt(window, labelEnd, pemDashes) {
		return 0, false
	}
	end = labelEnd + len(pemDashes)
	if pemHasAt(window, end, pemEscCR) {
		end += 2
	}
	if pemHasAt(window, end, pemEscLF) {
		end += 2
	}
	return end, true
}

// pemStop says why a PEM body scan stopped.
type pemStop uint8

const (
	pemStopJunk   pemStop = iota // a byte that cannot be in a body, or too much prose
	pemStopEnd                   // an END marker; the position is one past it
	pemStopWindow                // the window ran out
	pemStopOpen                  // a token boundary at the resume limit
)

// pemScanner is the PEM body state machine. A "run" is a maximal sequence
// of base64 bytes; runs of pemPlausibleRun or more are evidence of real key
// material. runLen and shortRuns survive a resume (see state).
type pemScanner struct {
	runLen     int // base64 bytes in the run in progress
	shortRuns  int // consecutive short runs since the last plausible one
	plausible  bool
	lastB64End int    // one past the last base64 byte seen, or -1
	snap       uint64 // the state at lastB64End, for resuming there
}

// state packs what a resumed scan needs. runLen only matters up to
// pemPlausibleRun and shortRuns never exceeds pemMaxShortRuns+1.
func (s *pemScanner) state() uint64 {
	return uint64(min(s.runLen, pemPlausibleRun)) | uint64(s.shortRuns)<<8
}

// resumePEM rebuilds a scanner for an open block from state. An open block
// was confirmed, so it is plausible, and its window starts right after a
// base64 byte.
func resumePEM(state uint64) pemScanner {
	return pemScanner{
		runLen:     int(state & 0xff),
		shortRuns:  min(int(state>>8&0xff), pemMaxShortRuns+1),
		plausible:  true,
		lastB64End: 0,
		snap:       state,
	}
}

// closeRun ends the run in progress and reports whether the scan may go
// on: false once too many prose-like short runs have been seen in a row.
func (s *pemScanner) closeRun() bool {
	if s.runLen == 0 {
		return true
	}
	n := s.runLen
	s.runLen = 0
	if n >= pemPlausibleRun {
		s.plausible = true
		s.shortRuns = 0
		return true
	}
	s.shortRuns++
	return s.shortRuns <= pemMaxShortRuns
}

// scan runs the body scan from i: base64 characters, whitespace, the
// encapsulated-header punctuation ':' and ',', '-' (checked for an END
// marker first), and the two-byte escapes `\n` `\r` `\t` `\"` so
// JSON-escaped single-line keys in structured logs are covered. With
// limit >= 0, a plausible scan stops at the first token boundary at or past
// limit (pemStopOpen); the block then resumes at lastB64End with snap.
func (s *pemScanner) scan(window []byte, i, limit int) (pos int, stop pemStop) {
	for i < len(window) {
		if limit >= 0 && i >= limit && s.plausible {
			return i, pemStopOpen
		}
		c := window[i]
		if pemBase64[c] {
			// Consume the run at once. plausible only changes when a run
			// closes, so the resume limit binds within the run exactly as
			// it would byte by byte.
			stop := len(window)
			if limit >= 0 && s.plausible && limit < stop {
				stop = limit
			}
			j := i + 1
			for j < stop && pemBase64[window[j]] {
				j++
			}
			s.runLen += j - i
			i = j
			s.lastB64End = i
			s.snap = s.state()
			continue
		}
		if s.plausible && i-s.lastB64End >= pemMaxGap {
			return i, pemStopJunk // too long without key material
		}
		if !s.closeRun() {
			return i, pemStopJunk // too many prose-like short runs: give up
		}
		switch c {
		case ' ', '\t', '\r', '\n', ':', ',':
			// Whitespace and encapsulated-header punctuation
			// (Proc-Type: 4,ENCRYPTED / DEK-Info: ...).
			i++
		case '\\':
			// JSON-style escapes inside string-embedded keys. A run of
			// backslashes is consumed as one unit so that multiply-escaped
			// keys (JSON inside JSON, e.g. `\\n` or `\\\\n` in nested tool
			// output) are covered as well as singly-escaped `\n`.
			j := i
			for j < len(window) && window[j] == '\\' {
				j++
			}
			if j < len(window) {
				switch window[j] {
				case 'n', 'r', 't', '"':
					i = j + 1
					continue
				}
				return i, pemStopJunk
			}
			if limit >= 0 && s.plausible {
				// The run reaches the end of a non-final window, so it may
				// go on in the next: read it again there.
				return i, pemStopOpen
			}
			return i, pemStopJunk
		case '-':
			if e, found := pemEndMarker(window, i); found {
				return e, pemStopEnd
			}
			// Not an END marker for a private key (e.g. the hyphen in
			// "DEK-Info" or "AES-128-CBC", a mismatched END label, or a
			// diff removal marker): body punctuation, keep looking.
			i++
		default:
			return i, pemStopJunk // byte that cannot be part of a PEM body
		}
	}
	return i, pemStopWindow
}

// PEMPrivateKey confirms a PEM-encapsulated private-key block within
// window, treating the end of window as the end of input. It is
// PEMPrivateKeyBegin with final set; see that function and the file
// comment for the grammar and span semantics.
func PEMPrivateKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	start, end, _, _, ok = PEMPrivateKeyBegin(window, trigStart, trigEnd, true)
	return start, end, ok
}

// PEMPrivateKeyBegin confirms a PEM private-key block (rules.BlockBeginFunc).
// The trigger is "-----BEGIN " (trailing space included). The header label
// must contain "PRIVATE KEY" (so CERTIFICATE and PUBLIC KEY blocks are
// rejected), then the body is scanned until the matching
// "-----END ...PRIVATE KEY...-----" marker. When final is false and the
// body runs on past the window after a plausible run, the block is open
// and continues with PEMPrivateKeyExtend.
func PEMPrivateKeyBegin(window []byte, trigStart, trigEnd int, final bool) (start, end int, state uint64, open, ok bool) {
	if trigStart < 0 || trigEnd < trigStart || trigEnd > len(window) {
		return 0, 0, 0, false, false
	}

	// Header: "<label>-----" with a label containing "PRIVATE KEY".
	labelEnd, ok := pemLabelEnd(window, trigEnd)
	if !ok {
		return 0, 0, 0, false, false
	}
	if !bytes.Contains(window[trigEnd:labelEnd], pemPrivateLabel) {
		return 0, 0, 0, false, false
	}
	if !pemHasAt(window, labelEnd, pemDashes) {
		return 0, 0, 0, false, false
	}
	body := labelEnd + len(pemDashes)

	limit := -1
	if !final && len(window)-pemResumeReserve > body {
		limit = len(window) - pemResumeReserve
	}
	s := pemScanner{lastB64End: -1}
	pos, stop := s.scan(window, body, limit)
	switch stop {
	case pemStopEnd:
		if !s.plausible {
			// Marker text with no body between BEGIN and END is
			// prose/template text, not a key.
			return 0, 0, 0, false, false
		}
		return trigStart, pos, 0, false, true
	case pemStopOpen:
		return trigStart, s.lastB64End, s.snap, true, true
	}
	s.closeRun() // close a run cut off by the end of the window
	if stop == pemStopWindow && !final && s.plausible {
		// The body only became plausible at the end of the window: it is
		// confirmed, and may go on in the next one.
		return trigStart, s.lastB64End, s.snap, true, true
	}
	if s.plausible {
		// Fail-safe: no END marker, but plausible body material followed
		// the header — confirm through the last base64 byte seen rather
		// than risk leaking a truncated key.
		return trigStart, s.lastB64End, 0, false, true
	}
	return 0, 0, 0, false, false
}

// PEMPrivateKeyExtend continues an open PEM block (rules.BlockExtendFunc)
// from the token boundary where the previous window stopped, to the END
// marker, to the fail-safe end, or — when the body runs past this window
// too — to the next resume point.
func PEMPrivateKeyExtend(window []byte, state uint64, final bool) (end int, next uint64, open bool) {
	limit := -1
	if !final && len(window) > pemResumeReserve {
		limit = len(window) - pemResumeReserve
	}
	s := resumePEM(state)
	pos, stop := s.scan(window, 0, limit)
	switch stop {
	case pemStopEnd:
		return pos, 0, false
	case pemStopOpen:
		if s.lastB64End > 0 {
			return s.lastB64End, s.snap, true
		}
	}
	return s.lastB64End, 0, false
}

// ppkStop says why a PPK body scan stopped.
type ppkStop uint8

const (
	ppkStopEnd    ppkStop = iota // the section is complete, or a line ended it
	ppkStopWindow                // the input ran out
	ppkStopOpen                  // a non-final window cut a line; resume at lastEnd
)

// ppkAtEOL marks a state resumed at the end of a counted body line, where
// the line's "\r\n" or "\n" comes first.
const ppkAtEOL = 1 << 46

// PPK sides. Outside a diff only ppkNew is used.
const (
	ppkOld = 0 // removed ('-') and context (' ') lines of a diff
	ppkNew = 1 // added ('+') and context (' ') lines of a diff
)

// ppkScanner is the PPK Private-Lines body state machine. Outside a diff
// it counts down the declared number of base64 body lines. In diff mode
// each line opens with a marker, and the old and new file versions each
// have their own count: a "+" line belongs to the new file, a "-" line to
// the old one, and a " " context line to both, so a changed key — whose
// header may be a context line while the bodies are "-" then "+" lines,
// or whose header changed too — is followed through both versions.
type ppkScanner struct {
	diff      bool
	seen      [2]bool // a Private-Lines header was read for the side
	need      [2]int  // body lines still expected for the side
	skipped   int
	plausible bool
	lastEnd   int    // one past the last body base64 byte, or -1
	snap      uint64 // the state at lastEnd, for resuming there
}

// state packs a scanner for resumption. Counts are at most ppkMaxCount
// (17 bits).
func (s *ppkScanner) state() uint64 {
	st := uint64(s.need[ppkOld]) | uint64(s.need[ppkNew])<<20 | uint64(s.skipped)<<44
	if s.seen[ppkOld] {
		st |= 1 << 40
	}
	if s.seen[ppkNew] {
		st |= 1 << 41
	}
	if s.diff {
		st |= 1 << 42
	}
	return st | ppkAtEOL
}

// resumePPK rebuilds a scanner for an open block from state. An open block
// was confirmed, so it is plausible.
func resumePPK(state uint64) ppkScanner {
	return ppkScanner{
		snap:      state,
		need:      [2]int{min(int(state&0xfffff), ppkMaxCount), min(int(state>>20&0xfffff), ppkMaxCount)},
		seen:      [2]bool{state&(1<<40) != 0, state&(1<<41) != 0},
		diff:      state&(1<<42) != 0,
		skipped:   min(int(state>>44&0x3), ppkMaxSkippedLines),
		plausible: true,
		lastEnd:   -1,
	}
}

// ppkSides maps a diff marker to the sides its line belongs to.
func ppkSides(marker byte) (sides [2]bool, ok bool) {
	switch marker {
	case '-':
		return [2]bool{true, false}, true
	case '+':
		return [2]bool{false, true}, true
	case ' ':
		return [2]bool{true, true}, true
	}
	return sides, false
}

// header records a Private-Lines count for the given sides.
func (s *ppkScanner) header(sides [2]bool, n int) {
	for side, in := range sides {
		if in {
			s.seen[side] = true
			s.need[side] = n
		}
	}
}

// done reports whether every side with a header has all its body lines.
func (s *ppkScanner) done() bool {
	return s.need[ppkOld] == 0 && s.need[ppkNew] == 0
}

// wants reports whether a line on sides counts toward a section, and
// counts it.
func (s *ppkScanner) wants(sides [2]bool) bool {
	counted := false
	for side, in := range sides {
		if in && s.need[side] > 0 {
			s.need[side]--
			counted = true
		}
	}
	return counted
}

// finished reports whether every side the line belongs to has a complete
// section (its header was read and all of its lines counted).
func (s *ppkScanner) finished(sides [2]bool) bool {
	for side, in := range sides {
		if in && (!s.seen[side] || s.need[side] > 0) {
			return false
		}
	}
	return true
}

// unseen reports whether a line on sides could open a section: some side
// it belongs to has no header yet.
func (s *ppkScanner) unseen(sides [2]bool) bool {
	for side, in := range sides {
		if in && !s.seen[side] {
			return true
		}
	}
	return false
}

// ppkCount parses the rest of a "Private-Lines:" header line from p:
// optional spaces, 1-5 digits (not zero), optional spaces, optional '\r',
// then '\n'. It returns the count and the offset of the next line.
// incomplete reports that the window ended inside the line.
func ppkCount(window []byte, p int) (n, next int, ok, incomplete bool) {
	for p < len(window) && (window[p] == ' ' || window[p] == '\t') {
		p++
	}
	digStart := p
	for p < len(window) && isDigit(window[p]) && p-digStart < 6 {
		p++
	}
	nd := p - digStart
	if p >= len(window) {
		return 0, 0, false, true
	}
	if nd == 0 || nd > 5 {
		return 0, 0, false, false
	}
	for _, c := range window[digStart:p] {
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return 0, 0, false, false
	}
	for p < len(window) && (window[p] == ' ' || window[p] == '\t') {
		p++
	}
	if p < len(window) && window[p] == '\r' {
		p++
	}
	if p >= len(window) {
		return 0, 0, false, true
	}
	if window[p] != '\n' {
		return 0, 0, false, false
	}
	return n, p + 1, true, false
}

// lines scans body lines from p, which starts a line. Outside a diff a body
// line is a base64 run then an optional '\r' and '\n'; in diff mode it is
// a marker then the same. A line with base64 then junk still counts its
// base64 prefix (fail-safe) and ends the section. When final is false, a
// line the window cuts is not decided: the scan stops (ppkStopOpen) so it
// can resume at the end of the last counted line, lastEnd, with snap —
// the lines after it, already looked at, are read again in the next window
// and no byte past lastEnd is masked unless a later line is counted.
func (s *ppkScanner) lines(window []byte, p int, final bool) (pos int, stop ppkStop) {
	for {
		if s.done() && (!s.diff || s.seen[ppkOld] && s.seen[ppkNew]) {
			// Complete. A diff with one version's section complete still
			// looks a few lines on for the other version's header.
			return p, ppkStopEnd
		}
		if p >= len(window) {
			if final {
				return p, ppkStopWindow
			}
			return p, ppkStopOpen
		}
		lineStart := p
		sides := [2]bool{false, true}
		if s.diff {
			var ok bool
			if sides, ok = ppkSides(window[p]); !ok {
				return lineStart, ppkStopEnd
			}
			p++
		}

		// In a diff, the other file version's header (a changed
		// Private-Lines count, or a key replaced after its old version's
		// Private-MAC line).
		if s.diff && s.unseen(sides) && pemHasAt(window, p, ppkPrivateLines) {
			n, next, ok, incomplete := ppkCount(window, p+len(ppkPrivateLines))
			switch {
			case ok:
				s.header(sides, n)
				p = next
				continue
			case incomplete && !final:
				return lineStart, ppkStopOpen
			}
			return lineStart, ppkStopEnd
		}

		q := p
		for q < len(window) && pemIsBase64(window[q]) {
			q++
		}
		r := q
		if r < len(window) && window[r] == '\r' {
			r++
		}
		complete := r < len(window) && window[r] == '\n'
		if !complete && r >= len(window) && !final {
			return lineStart, ppkStopOpen // the line may go on in the next window
		}
		if q > p && s.wants(sides) {
			s.lastEnd = q
			if q-p >= pemPlausibleRun {
				s.plausible = true
			}
			if !complete {
				return q, ppkStopEnd // junk after the base64 prefix, or end of input
			}
			s.snap = s.state()
			p = r + 1
			continue
		}

		// A line no section needs. In a diff, step over a few lines of a
		// version whose key already ended (its Private-MAC line) while the
		// other version's key may still follow; anything else ends the
		// section.
		if s.diff && s.finished(sides) && s.skipped < ppkMaxSkippedLines {
			nl := bytes.IndexByte(window[p:], '\n')
			if nl < 0 {
				if final {
					return lineStart, ppkStopEnd
				}
				return lineStart, ppkStopOpen
			}
			s.skipped++
			p += nl + 1
			continue
		}
		return lineStart, ppkStopEnd
	}
}

// ppkFindHeader returns the offset of the first "Private-Lines:" at or
// after from that starts a line, either directly or behind one unified
// diff marker, and the marker (0 outside a diff).
func ppkFindHeader(window []byte, from int) (at int, marker byte, ok bool) {
	for from < len(window) {
		rel := bytes.Index(window[from:], ppkPrivateLines)
		if rel < 0 {
			return 0, 0, false
		}
		at = from + rel
		if startsLine(window, at) && at > 0 {
			return at, 0, true
		}
		if at >= 2 && isDiffMarker(window[at-1]) && window[at-2] == '\n' {
			return at, window[at-1], true
		}
		from = at + 1
	}
	return 0, 0, false
}

// PuTTYPrivateKey confirms the private section of a PuTTY PPK file within
// window, treating the end of window as the end of input. It is
// PuTTYPrivateKeyBegin with final set.
func PuTTYPrivateKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	start, end, _, _, ok = PuTTYPrivateKeyBegin(window, trigStart, trigEnd, true)
	return start, end, ok
}

// PuTTYPrivateKeyBegin confirms the private section of a PuTTY PPK file
// (rules.BlockBeginFunc). The trigger is "PuTTY-User-Key-File-"; the
// version digit must be 2 or 3 (followed by ':'). The validator then
// locates the "Private-Lines: N" header at a line start and consumes N
// base64 body lines. Span: first byte of "Private-Lines:" through the last
// base64 byte of the last body line (the public portion stays). If
// "Private-Lines:" never appears in the window the validator reports no
// match; once it has appeared, the fail-safe confirms a partial body with
// at least one plausible (>= 16-byte base64) line.
//
// In a unified diff patch every line opens with '+', '-' or ' ': a header
// behind one such marker selects diff mode, in which every body line must
// open with a marker too and the old and new file versions are counted
// separately (see ppkScanner). A header indented by one space reads as a
// context line, whose body lines then need the same one-byte indent.
func PuTTYPrivateKeyBegin(window []byte, trigStart, trigEnd int, final bool) (start, end int, state uint64, open, ok bool) {
	if trigStart < 0 || trigEnd < trigStart || trigEnd > len(window) {
		return 0, 0, 0, false, false
	}

	// Version: a single digit 2 or 3, immediately followed by ':'.
	if trigEnd+2 > len(window) {
		return 0, 0, 0, false, false
	}
	if v := window[trigEnd]; v != '2' && v != '3' {
		return 0, 0, 0, false, false
	}
	if window[trigEnd+1] != ':' {
		return 0, 0, 0, false, false
	}

	secStart, marker, found := ppkFindHeader(window, trigEnd)
	if !found {
		return 0, 0, 0, false, false
	}
	// Line count. Anything else (prose such as "Private-Lines: 14 is a
	// field", or a window truncated inside the header line, which cannot
	// have leaked any key bytes yet) is not a private-lines section.
	n, p, ok, _ := ppkCount(window, secStart+len(ppkPrivateLines))
	if !ok {
		return 0, 0, 0, false, false
	}

	s := ppkScanner{lastEnd: -1}
	sides := [2]bool{false, true}
	if marker != 0 {
		s.diff = true
		sides, _ = ppkSides(marker)
	}
	s.header(sides, n)
	// Where the section resumes if the window cuts its first body line:
	// that line's start, not at the end of a counted line.
	bodySnap := s.state() &^ ppkAtEOL
	_, stop := s.lines(window, p, final)
	if !s.plausible {
		if stop != ppkStopOpen {
			return 0, 0, 0, false, false
		}
		// Nothing plausible before the window cut a line. The cut line,
		// as far as it is in view, decides as in a window validator; if
		// that confirms the section, it goes on in the next window.
		if _, _, _, _, ok := PuTTYPrivateKeyBegin(window, trigStart, trigEnd, true); !ok {
			return 0, 0, 0, false, false
		}
		if s.lastEnd < 0 {
			return secStart, p, bodySnap, true, true
		}
	}
	if stop == ppkStopOpen {
		return secStart, s.lastEnd, s.snap, true, true
	}
	return secStart, s.lastEnd, 0, false, true
}

// PuTTYPrivateKeyExtend continues an open PPK section
// (rules.BlockExtendFunc) from the end of the last body line counted
// before the previous window cut a line.
func PuTTYPrivateKeyExtend(window []byte, state uint64, final bool) (end int, next uint64, open bool) {
	s := resumePPK(state)
	p := 0
	if state&ppkAtEOL != 0 {
		if p < len(window) && window[p] == '\r' {
			p++
		}
		if p >= len(window) || window[p] != '\n' {
			return 0, 0, false
		}
		p++
	}
	_, stop := s.lines(window, p, final)
	if stop == ppkStopOpen && s.lastEnd > 0 {
		return s.lastEnd, s.snap, true
	}
	return max(s.lastEnd, 0), 0, false
}
