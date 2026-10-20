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
// near the end of its window — once it reaches the last pemResumeReserve
// bytes (PEM), or at a line the window cuts (PPK) — and reports the block
// open up to a resume point: normally the last body byte it has decided
// (the last base64 byte, or the end of the last counted PPK line), with a
// snapshot of the scanner state there (a uint64). The next window starts
// at the resume point and reads the bytes after it again, so every token
// is decided with all of its bytes in view and nothing past the resume
// point is masked unless the block goes on. When that would not advance
// the scan — a long run of separators, a backslash run or a line longer
// than the window — the resume point is where the scan stopped instead,
// so a few separator or stepped-over bytes may be masked that one
// unbounded scan would have left. Each window advances by most of its
// length, so the total work is linear in the block's length. Scans must
// never panic or index out of range on any byte sequence.
//
// Span semantics, PEM:
//
//   - Full match: trigger start through the closing "-----" of the END
//     marker, extended past an immediately following ESCAPED newline (the
//     two-byte sequences `\r` and/or `\n`, covering JSON-escaped keys). A
//     real newline byte after the END marker is NOT consumed.
//   - Fail-safe: when the scan stops without an END marker — the input
//     ends, or a byte that cannot be part of a PEM body appears — the span
//     runs from the trigger through the last base64 byte seen, provided at
//     least one plausible body run (>= 16 consecutive base64 bytes)
//     followed the header. Over-redaction is safe, leaking is not. A header
//     followed only by prose ("-----BEGIN PRIVATE KEY----- is the PEM
//     header") has no plausible run and is rejected.
//   - RFC 4880 armor headers ("Version: GnuPG v1.4.11 (GNU/Linux)",
//     "Comment: ...") directly after the BEGIN line are part of the block,
//     whatever bytes their values hold.
//
// Span semantics, PPK: only the Private-Lines section is redacted — from
// the first byte of "Private-Lines:" through the last base64 byte of the
// last private body line (the terminating newline is not included; the
// public portion of the file is left intact). The same fail-safe applies
// once the Private-Lines header and at least one plausible body line have
// been seen.
//
// Diff patches: in a unified diff every line starts with '+' (the new file
// version), '-' (the old one) or ' ' (context, both). A key whose trigger
// line carries a marker belongs to those versions:
//
//   - PEM: the body grammar accepts the markers ('+' is base64, '-' and ' '
//     are body punctuation), and an END marker on a marked line closes only
//     the versions that line belongs to, so an added key is not closed by
//     the END of a removed one.
//   - PPK: a "Private-Lines:" header behind one marker switches the scan to
//     diff mode, in which each version's section is counted separately (see
//     ppkScanner).

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

	// pemResumeLag is how far the last base64 byte may lie behind the point
	// where a PEM scan stopped for it to be the resume point. Past that (a
	// long run of separators), the scan resumes where it stopped, masking
	// the separators in between, so it always advances.
	pemResumeLag = 128

	// pemArmorLines and pemArmorLineMax bound the RFC 4880 armor headers
	// skipped after a BEGIN line.
	pemArmorLines   = 16
	pemArmorLineMax = 512

	// ppkMaxCount bounds the "Private-Lines: N" count: 1-5 digits.
	ppkMaxCount = 99999

	// ppkMaxStepLines and ppkMaxStepLine bound stepping once no header can
	// come any more (past ppkHeaderReach): a section waiting for more of a
	// version's lines ends after that many lines in a row that no count
	// needs, or at a longer one. They bound what stepping can mask.
	ppkMaxStepLines = 64
	ppkMaxStepLine  = 512

	// ppkHeaderReach is how far past its trigger a PPK file's
	// Private-Lines header may start, for each file version: the
	// putty-private-key rule's lookahead (TestPPKHeaderReachMatchesSpec).
	ppkHeaderReach = 16384
)

var (
	pemDashes       = []byte("-----")
	pemEndPrefix    = []byte("-----END ")
	pemPrivateLabel = []byte("PRIVATE KEY")
	pemEscCR        = []byte(`\r`)
	pemEscLF        = []byte(`\n`)
	ppkPrivateLines = []byte("Private-Lines:")
)

// pemBase64 reports whether a byte can appear in a base64 body (standard
// alphabet plus padding), as a table: body scans spend most of their time
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

// diffSides maps a unified-diff line marker to the file versions its line
// belongs to, as a bitmask: diffOld for '-', diffNew for '+', both for ' '.
func diffSides(marker byte) uint8 {
	switch marker {
	case '-':
		return diffOld
	case '+':
		return diffNew
	case ' ':
		return diffOld | diffNew
	}
	return 0
}

const (
	diffOld uint8 = 1 << iota
	diffNew
)

// pemLineBreak reports the length of a line break at pos: "\n", "\r\n", or
// their escaped two-byte forms `\n` and `\r\n` when escaped is set; 0 when
// there is none.
func pemLineBreak(window []byte, pos int, escaped bool) int {
	switch {
	case pemHasAt(window, pos, []byte("\n")):
		return 1
	case pemHasAt(window, pos, []byte("\r\n")):
		return 2
	case escaped && pemHasAt(window, pos, pemEscLF):
		return 2
	case escaped && pemHasAt(window, pos, []byte(`\r\n`)):
		return 4
	}
	return 0
}

// pemSkipArmorHeaders skips RFC 4880 armor headers ("Key: Value" lines)
// following the BEGIN line, which ends at body. A value may hold bytes the
// body grammar refuses ("Version: GnuPG v1.4.11 (GNU/Linux)"), so the lines
// are taken whole. Each line may open with marker (a diff line). It returns
// the offset of the line break ending the last header line, or body when
// there is none.
func pemSkipArmorHeaders(window []byte, body int, marker byte) int {
	escaped := pemHasAt(window, body, pemEscLF) || pemHasAt(window, body, []byte(`\r\n`))
	end := body
	for range pemArmorLines {
		p := end + pemLineBreak(window, end, escaped)
		if p == end {
			return end
		}
		if marker != 0 {
			if p >= len(window) || window[p] != marker {
				return end
			}
			p++
		}
		key := p
		for p < len(window) && p-key < pemLabelMax && (isASCIILetter(window[p]) || isDigit(window[p]) || window[p] == '-' && p > key) {
			p++
		}
		if p == key || !pemHasAt(window, p, []byte(": ")) {
			return end
		}
		p += 2
		valueStart := p
		for {
			if p >= len(window) || p-valueStart > pemArmorLineMax {
				return end
			}
			if pemLineBreak(window, p, escaped) > 0 {
				break
			}
			c := window[p]
			if c < 0x20 && c != '\t' || c == 0x7f || c == '"' || escaped && c == '\\' {
				return end
			}
			p++
		}
		end = p
	}
	return end
}

// pemStop says why a PEM body scan stopped.
type pemStop uint8

const (
	pemStopJunk   pemStop = iota // a byte that cannot be in a body, or too much prose
	pemStopEnd                   // an END marker; the position is one past it
	pemStopWindow                // the window ran out
	pemStopOpen                  // near the end of a non-final window
)

// PEM scanner state bits (see pemScanner.state).
const (
	pemStateDiff   = 1 << 20 // the block is on diff lines; sides are tracked
	pemStateInRun  = 1 << 18 // resume inside a backslash run
	pemStateLineNL = 1 << 19 // the resume point starts a line
)

// pemScanner is the PEM body state machine. A "run" is a maximal sequence
// of base64 bytes; runs of pemPlausibleRun or more are evidence of real key
// material. runLen, shortRuns and the open diff sides survive a resume
// (see state).
type pemScanner struct {
	runLen     int // base64 bytes in the run in progress
	shortRuns  int // consecutive short runs since the last plausible one
	plausible  bool
	diff       bool   // the block is on diff lines
	sides      uint8  // with diff, the file versions whose END is still to come
	nl         bool   // offset 0 of the window starts a line
	lastB64End int    // one past the last base64 byte seen, or -1
	snap       uint64 // the state at lastB64End, for resuming there
}

// state packs what a resumed scan needs. runLen only matters up to
// pemPlausibleRun and shortRuns never exceeds pemMaxShortRuns+1.
func (s *pemScanner) state() uint64 {
	st := uint64(min(s.runLen, pemPlausibleRun)) | uint64(s.shortRuns)<<8 | uint64(s.sides)<<16
	if s.diff {
		st |= pemStateDiff
	}
	return st
}

// resumePEM rebuilds a scanner for an open block from state. An open block
// was confirmed, so it is plausible.
func resumePEM(state uint64) pemScanner {
	return pemScanner{
		runLen:     int(state & 0xff),
		shortRuns:  min(int(state>>8&0xff), pemMaxShortRuns+1),
		plausible:  true,
		diff:       state&pemStateDiff != 0,
		sides:      uint8(state>>16) & (diffOld | diffNew),
		nl:         state&pemStateLineNL != 0,
		lastB64End: 0,
		snap:       state &^ (pemStateInRun | pemStateLineNL),
	}
}

// startsLineAt reports whether pos starts a line in a window whose offset 0
// starts one exactly when s.nl is set.
func (s *pemScanner) startsLineAt(window []byte, pos int) bool {
	if pos == 0 {
		return s.nl
	}
	return pos > 0 && pos <= len(window) && window[pos-1] == '\n'
}

// openAt reports where an open block resumes when the scan stopped at pos:
// at the last base64 byte if it is close enough behind, else at pos.
func (s *pemScanner) openAt(window []byte, pos int) (resume int, state uint64) {
	if s.lastB64End > 0 && pos-s.lastB64End <= pemResumeLag {
		return s.lastB64End, s.snap
	}
	st := s.state()
	if s.startsLineAt(window, pos) {
		st |= pemStateLineNL
	}
	return pos, st
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
// limit (pemStopOpen), or at the end of the window inside a backslash run
// (pemStopOpen with pos == len(window)).
func (s *pemScanner) scan(window []byte, i, limit int) (pos int, stop pemStop) {
	for {
		if limit >= 0 && i >= limit && s.plausible {
			return i, pemStopOpen
		}
		if i >= len(window) {
			return i, pemStopWindow
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
				// The run reaches the end of a non-final window and may go
				// on in the next.
				return len(window), pemStopOpen
			}
			return i, pemStopJunk
		case '-':
			e, found := pemEndMarker(window, i)
			if !found {
				// Not an END marker for a private key (e.g. the hyphen in
				// "DEK-Info" or "AES-128-CBC", a mismatched END label, or a
				// diff removal marker): body punctuation, keep looking.
				i++
				continue
			}
			if s.diff && i > 0 && s.startsLineAt(window, i-1) {
				if line := diffSides(window[i-1]); line != 0 {
					if s.sides&line == 0 {
						// The END of the other file version's key.
						i++
						continue
					}
					if s.sides &^= line; s.sides != 0 {
						// One version ended; the other's END is still to
						// come.
						i = e
						continue
					}
				}
			}
			return e, pemStopEnd
		default:
			return i, pemStopJunk // byte that cannot be part of a PEM body
		}
	}
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
// and continues with PEMPrivateKeyExtend. A trigger opening a unified diff
// line (the rule's two-byte lookbehind shows the marker) makes the block
// a diff block, closed by the END lines of its own file versions.
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

	s := pemScanner{lastB64End: -1, nl: true}
	var marker byte
	if trigStart > 0 && startsLine(window, trigStart-1) {
		if sides := diffSides(window[trigStart-1]); sides != 0 {
			marker = window[trigStart-1]
			s.diff, s.sides = true, sides
		}
	}
	body := pemSkipArmorHeaders(window, labelEnd+len(pemDashes), marker)

	limit := -1
	if !final && len(window)-pemResumeReserve > body {
		limit = len(window) - pemResumeReserve
	}
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
		resume, st := s.pemOpen(window, pos)
		return trigStart, resume, st, true, true
	}
	s.closeRun() // close a run cut off by the end of the window
	if stop == pemStopWindow && !final && s.plausible {
		// The body only became plausible at the end of the window: it is
		// confirmed, and may go on in the next one.
		resume, st := s.openAt(window, pos)
		return trigStart, resume, st, true, true
	}
	if s.plausible {
		// Fail-safe: no END marker, but plausible body material followed
		// the header — confirm through the last base64 byte seen rather
		// than risk leaking a truncated key.
		return trigStart, s.lastB64End, 0, false, true
	}
	return 0, 0, 0, false, false
}

// pemOpen reports the resume point and state of a scan that stopped open
// at pos: inside a backslash run cut by the window end, or at a token
// boundary near it.
func (s *pemScanner) pemOpen(window []byte, pos int) (resume int, state uint64) {
	if pos == len(window) && len(window) > 0 && window[pos-1] == '\\' {
		return pos, s.state() | pemStateInRun
	}
	return s.openAt(window, pos)
}

// PEMPrivateKeyExtend continues an open PEM block (rules.BlockExtendFunc)
// from the previous window's resume point, to the END marker, to the
// fail-safe end, or — when the body runs past this window too — to the
// next resume point.
func PEMPrivateKeyExtend(window []byte, state uint64, final bool) (end int, next uint64, open bool) {
	limit := -1
	if !final && len(window) > pemResumeReserve {
		limit = len(window) - pemResumeReserve
	}
	s := resumePEM(state)
	i := 0
	if state&pemStateInRun != 0 {
		for i < len(window) && window[i] == '\\' {
			i++
		}
		if i == len(window) {
			if final || i == 0 {
				return 0, 0, false
			}
			return i, state, true
		}
		switch window[i] {
		case 'n', 'r', 't', '"':
			i++
		default:
			return 0, 0, false
		}
	}
	pos, stop := s.scan(window, i, limit)
	switch stop {
	case pemStopEnd:
		return pos, 0, false
	case pemStopOpen:
		if resume, st := s.pemOpen(window, pos); resume > 0 {
			return resume, st, true
		}
	}
	return s.lastB64End, 0, false
}

// PPK scanner state layout (see ppkScanner.stateAt).
const (
	ppkStateNeedBits  = 17 // per version: counts are at most ppkMaxCount
	ppkStateSeenOld   = 1 << 34
	ppkStateSeenNew   = 1 << 35
	ppkStateDiff      = 1 << 36
	ppkStateAllowOld  = 1 << 37
	ppkStateAllowNew  = 1 << 38
	ppkStateModeAt    = 39 // two bits: ppkModeLine...ppkModeStep
	ppkStateSteppedAt = 41 // seven bits: lines stepped over since a count
	ppkStateReachAt   = 48 // 16 bits: header reach left past the resume point
)

// Where a resumed PPK scan stands at offset 0 of its window.
const (
	ppkModeLine = iota // at the start of a line
	ppkModeEOL         // after a counted line's base64, before its line break
	ppkModeMid         // inside a counted line's base64
	ppkModeStep        // inside a line being stepped over
)

// PPK sides. Outside a diff only ppkNew is used.
const (
	ppkOld = 0 // removed ('-') and context (' ') lines of a diff
	ppkNew = 1 // added ('+') and context (' ') lines of a diff
)

// ppkScanner is the PPK Private-Lines body state machine. Outside a diff
// it counts down the declared number of base64 body lines. In diff mode
// each line opens with a marker, and the old and new file versions each
// have their own Private-Lines header and count: a "+" line belongs to the
// new file, a "-" line to the old one, and a " " context line to both.
// The versions a key follows (allow) are those of its trigger line: a key
// whose "PuTTY-User-Key-File-" line was added follows the new file only,
// one whose trigger line is context follows both. While a followed version
// still needs lines, or has not shown its header and is within reach of
// the trigger (ppkHeaderReach), the scan steps over lines no count needs —
// the other version's lines, a Private-MAC line, the new version's public
// lines before its header — and those between two counted lines are
// masked with them.
type ppkScanner struct {
	diff      bool
	allow     [2]bool // file versions this key follows
	seen      [2]bool // a Private-Lines header was read for the version
	need      [2]int  // body lines still expected for the version
	reach     int     // window offset before which a header may start
	plausible bool
	lastEnd   int    // one past the last body base64 byte, or -1
	snap      uint64 // the state at lastEnd, for resuming there
	stepped   int    // lines stepped over since the last counted one
}

// stateAt packs the scanner for resuming at window offset pos in mode.
func (s *ppkScanner) stateAt(pos int, mode uint64) uint64 {
	st := uint64(s.need[ppkOld]) | uint64(s.need[ppkNew])<<ppkStateNeedBits | mode<<ppkStateModeAt |
		uint64(min(s.stepped, ppkMaxStepLines))<<ppkStateSteppedAt
	flag := func(on bool, bit uint64) {
		if on {
			st |= bit
		}
	}
	flag(s.seen[ppkOld], ppkStateSeenOld)
	flag(s.seen[ppkNew], ppkStateSeenNew)
	flag(s.diff, ppkStateDiff)
	flag(s.allow[ppkOld], ppkStateAllowOld)
	flag(s.allow[ppkNew], ppkStateAllowNew)
	return st | uint64(min(max(s.reach-pos, 0), 0xffff))<<ppkStateReachAt
}

// resumePPK rebuilds a scanner for an open block from state. An open block
// was confirmed, so it is plausible.
func resumePPK(state uint64) ppkScanner {
	return ppkScanner{
		need: [2]int{
			min(int(state&(1<<ppkStateNeedBits-1)), ppkMaxCount),
			min(int(state>>ppkStateNeedBits&(1<<ppkStateNeedBits-1)), ppkMaxCount),
		},
		stepped:   int(state >> ppkStateSteppedAt & 0x7f),
		seen:      [2]bool{state&ppkStateSeenOld != 0, state&ppkStateSeenNew != 0},
		diff:      state&ppkStateDiff != 0,
		allow:     [2]bool{state&ppkStateAllowOld != 0, state&ppkStateAllowNew != 0},
		reach:     int(state >> ppkStateReachAt & 0xffff),
		plausible: true,
		lastEnd:   0,
	}
}

// ppkSides maps a diff marker to the versions its line belongs to.
func ppkSides(marker byte) (sides [2]bool, ok bool) {
	m := diffSides(marker)
	return [2]bool{m&diffOld != 0, m&diffNew != 0}, m != 0
}

// pending reports whether version side still holds the scan at line start
// p: it needs body lines, or may still show its header.
func (s *ppkScanner) pending(side, p int) bool {
	if !s.allow[side] {
		return false
	}
	if s.seen[side] {
		return s.need[side] > 0
	}
	return s.diff && p < s.reach
}

// complete reports whether no followed version holds the scan at p.
func (s *ppkScanner) complete(p int) bool {
	return !s.pending(ppkOld, p) && !s.pending(ppkNew, p)
}

// headerWanted reports whether a header on a line of sides starting at p
// would open a section: a followed version of the line has none yet.
func (s *ppkScanner) headerWanted(sides [2]bool, p int) bool {
	for side, in := range sides {
		if in && s.allow[side] && !s.seen[side] && p < s.reach {
			return true
		}
	}
	return false
}

// header records a Private-Lines count for the followed versions of sides
// that have none yet.
func (s *ppkScanner) header(sides [2]bool, n int) {
	for side, in := range sides {
		if in && s.allow[side] && !s.seen[side] {
			s.seen[side] = true
			s.need[side] = n
		}
	}
}

// counts reports whether a line on sides counts toward a section.
func (s *ppkScanner) counts(sides [2]bool) bool {
	for side, in := range sides {
		if in && s.allow[side] && s.seen[side] && s.need[side] > 0 {
			return true
		}
	}
	return false
}

// count counts a body line on sides.
func (s *ppkScanner) count(sides [2]bool) {
	for side, in := range sides {
		if in && s.allow[side] && s.seen[side] && s.need[side] > 0 {
			s.need[side]--
		}
	}
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

// cutOpen reports where a scan resumes when the window cuts the line at
// lineStart that it cannot decide yet: at the end of the last counted line
// when this window counted one, else at cut, masking the lines stepped
// over in between (bounded by ppkHeaderReach and ppkMaxStepLines).
func (s *ppkScanner) cutOpen(cut int, mode uint64) (resume int, state uint64, open bool) {
	if s.lastEnd > 0 {
		return s.lastEnd, s.snap, true
	}
	if cut > 0 {
		return cut, s.stateAt(cut, mode), true
	}
	return 0, 0, false
}

// lines scans body lines from p, which starts a line. Outside a diff a body
// line is a base64 run then an optional '\r' and '\n'; in diff mode it is
// a marker then the same. A line with base64 then junk still counts its
// base64 prefix (fail-safe) and ends the section. When final is false and
// the window cuts a line, the scan stops open: a counted line is split at
// the window end, anything else resumes as cutOpen says.
func (s *ppkScanner) lines(window []byte, p int, final bool) (resume int, state uint64, open bool) {
	for {
		if s.complete(p) {
			return 0, 0, false
		}
		if p >= len(window) {
			if final {
				return 0, 0, false
			}
			return s.cutOpen(p, ppkModeLine)
		}
		lineStart := p
		sides := [2]bool{false, true}
		if s.diff {
			var ok bool
			if sides, ok = ppkSides(window[p]); !ok {
				return 0, 0, false
			}
			p++
		}

		// In a diff, a followed version's header after the first: the other
		// version of a changed key, after the old version's lines or the new
		// version's public lines.
		if s.diff && s.headerWanted(sides, lineStart) {
			if pemHasAt(window, p, ppkPrivateLines) {
				n, next, ok, incomplete := ppkCount(window, p+len(ppkPrivateLines))
				if ok {
					s.header(sides, n)
					p = next
					continue
				}
				if incomplete && !final {
					return s.cutOpen(lineStart, ppkModeLine)
				}
			} else if rest := window[p:]; !final && len(rest) < len(ppkPrivateLines) && bytes.HasPrefix(ppkPrivateLines, rest) {
				return s.cutOpen(lineStart, ppkModeLine)
			}
		}

		q := p
		for q < len(window) && pemBase64[window[q]] {
			q++
		}
		r := q
		if r < len(window) && window[r] == '\r' {
			r++
		}
		complete := r < len(window) && window[r] == '\n'
		cut := !complete && r >= len(window) && !final
		if cut && q == p && s.counts(sides) {
			// Nothing of the line's body is in view yet.
			return s.cutOpen(lineStart, ppkModeLine)
		}
		if q > p && s.counts(sides) {
			s.count(sides)
			s.lastEnd = q
			if q-p >= pemPlausibleRun {
				s.plausible = true
			}
			switch {
			case complete:
				s.stepped = 0
				s.snap = s.stateAt(q, ppkModeEOL)
				p = r + 1
				continue
			case cut && q == len(window):
				// The window ends inside the line's base64: mask what is in
				// view and go on inside the line.
				return q, s.stateAt(q, ppkModeMid), true
			case cut:
				return q, s.stateAt(q, ppkModeEOL), true
			}
			return 0, 0, false // junk after the base64 prefix, or end of input
		}

		// A line no count needs. Outside a diff, or on a version still
		// counting (an empty or junk line), it ends the section; in a diff
		// it is stepped over while a followed version holds the scan.
		if !s.diff || s.counts(sides) {
			return 0, 0, false
		}
		// Past the header reach, stepping is bounded (ppkMaxStepLines,
		// ppkMaxStepLine), the same however the input is windowed.
		beyond := lineStart >= s.reach
		if beyond && s.stepped >= ppkMaxStepLines {
			return 0, 0, false
		}
		nl := bytes.IndexByte(window[p:], '\n')
		if nl < 0 {
			switch {
			case final, beyond && len(window)-lineStart > ppkMaxStepLine:
				return 0, 0, false
			case beyond:
				return s.cutOpen(lineStart, ppkModeLine)
			}
			return s.cutOpen(len(window), ppkModeStep)
		}
		if beyond && p+nl-lineStart > ppkMaxStepLine {
			return 0, 0, false
		}
		s.stepped++
		p += nl + 1
	}
}

// ppkTriggerSides reports the file versions a PPK trigger line belongs to:
// its diff marker's, or both (any) when the trigger does not open a marked
// line.
func ppkTriggerSides(window []byte, trigStart int) (sides [2]bool, marked bool) {
	if trigStart > 0 && startsLine(window, trigStart-1) {
		if s, ok := ppkSides(window[trigStart-1]); ok {
			return s, true
		}
	}
	return [2]bool{true, true}, false
}

// ppkFindHeader returns the offset of the first "Private-Lines:" at or
// after from that starts a line, either directly or behind one unified
// diff marker, and the marker (0 outside a diff). A header of a marked
// trigger must open a line of a version the trigger belongs to.
func ppkFindHeader(window []byte, from int, allow [2]bool, marked bool) (at int, marker byte, ok bool) {
	for from < len(window) {
		rel := bytes.Index(window[from:], ppkPrivateLines)
		if rel < 0 {
			return 0, 0, false
		}
		at = from + rel
		if !marked && at > 0 && startsLine(window, at) {
			return at, 0, true
		}
		if at >= 2 && window[at-2] == '\n' {
			if sides, ok := ppkSides(window[at-1]); ok && (sides[ppkOld] && allow[ppkOld] || sides[ppkNew] && allow[ppkNew]) {
				return at, window[at-1], true
			}
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
// open with a marker too and each file version is counted separately (see
// ppkScanner). The rule's two-byte lookbehind shows the trigger line's own
// marker, which selects the versions the key follows. A header indented
// by one space reads as a context line, whose body lines then need the
// same one-byte indent.
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

	allow, marked := ppkTriggerSides(window, trigStart)
	secStart, marker, found := ppkFindHeader(window, trigEnd, allow, marked)
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

	s := ppkScanner{lastEnd: -1, reach: trigEnd + ppkHeaderReach}
	sides := [2]bool{false, true}
	if marker != 0 {
		s.diff, s.allow = true, allow
		sides, _ = ppkSides(marker)
	} else {
		s.allow = [2]bool{false, true}
	}
	s.header(sides, n)
	// Where the section resumes if the window cuts its first body line
	// before anything is counted: that line's start.
	bodyState := s.stateAt(p, ppkModeLine)
	resume, st, open := s.lines(window, p, final)
	if !s.plausible {
		if !open {
			return 0, 0, 0, false, false
		}
		// Nothing plausible before the window cut a line. The cut line,
		// as far as it is in view, decides as in a window validator; if
		// that confirms the section, it goes on in the next window.
		if _, _, _, _, ok := PuTTYPrivateKeyBegin(window, trigStart, trigEnd, true); !ok {
			return 0, 0, 0, false, false
		}
		if s.lastEnd < 0 {
			resume, st = p, bodyState
		}
	}
	if open {
		return secStart, resume, st, true, true
	}
	return secStart, s.lastEnd, 0, false, true
}

// PuTTYPrivateKeyExtend continues an open PPK section
// (rules.BlockExtendFunc) from the previous window's resume point: a line
// start, the end of a counted line's base64, or inside a counted or
// stepped-over line.
func PuTTYPrivateKeyExtend(window []byte, state uint64, final bool) (end int, next uint64, open bool) {
	s := resumePPK(state)
	p := 0
	switch state >> ppkStateModeAt & 3 {
	case ppkModeMid:
		for p < len(window) && pemBase64[window[p]] {
			p++
		}
		if p > 0 {
			s.lastEnd = p
		}
		if p == len(window) {
			if final || p == 0 {
				return p, 0, false
			}
			return p, s.stateAt(p, ppkModeMid), true
		}
		fallthrough
	case ppkModeEOL:
		if p < len(window) && window[p] == '\r' {
			p++
		}
		if p >= len(window) && !final && s.lastEnd > 0 {
			return s.lastEnd, s.stateAt(s.lastEnd, ppkModeEOL), true
		}
		if p >= len(window) || window[p] != '\n' {
			return max(s.lastEnd, 0), 0, false
		}
		p++
		s.snap = s.stateAt(max(s.lastEnd, 0), ppkModeEOL)
	case ppkModeStep:
		nl := bytes.IndexByte(window, '\n')
		if nl < 0 {
			if final {
				return 0, 0, false
			}
			return s.cutOpen(len(window), ppkModeStep)
		}
		s.stepped++
		p = nl + 1
	}
	resume, st, open := s.lines(window, p, final)
	if open && resume > 0 {
		return resume, st, true
	}
	return max(s.lastEnd, 0), 0, false
}
