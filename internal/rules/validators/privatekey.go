package validators

// Private-key material validators: PEM-encapsulated private keys and
// PuTTY PPK private-key sections, in plain text, in string literals
// (JSON-escaped, also as PHP and .NET encoders escape '/' and '+'), behind
// per-line prefixes (quotes, comments, line numbers, indentation),
// concatenated from one string literal per line, and in unified diff
// patches. keylines.go recognises those line shapes.
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
//   - At the start of every line (after a raw or an escaped line feed)
//     the scan skips the line's frame — an email or Markdown quote ("> >
//     "), a comment marker ("# ", "// ", " * "), a line number ("    12→",
//     "12\t"), an indentation, an opening quote — and a unified diff hunk
//     header line ("@@ -1,7 +1,9 @@ ...", which git may give a key line as
//     its section heading): a key spanning two hunks is masked whole,
//     hunk header included. A quote closing a string literal's line ("...\n"
//     +) is taken with its line break.
//
// Span semantics, PPK: only the Private-Lines section is redacted — from
// the first byte of "Private-Lines:" through the last base64 byte of the
// last private body line (the terminating newline is not included; the
// public portion of the file is left intact). The same fail-safe applies
// once the Private-Lines header and at least one plausible body line have
// been seen. Body lines may carry the same frames and line ends as PEM
// lines, and base64 lines past a count that is too low are masked up to
// the Private-MAC line (ppkScanner.overflow).
//
// Diff patches: in a unified diff every line starts with '+' (the new file
// version), '-' (the old one) or ' ' (context, both). A key whose trigger
// line carries a marker belongs to those versions:
//
//   - PEM: each line's marker is read at its start (pemScanner.lineStart;
//     lines without one are accepted too), and an END marker on a marked
//     line closes only the versions that line belongs to, so an added key
//     is not closed by the END of a removed one.
//   - PPK: a "Private-Lines:" header behind one marker switches the scan to
//     diff mode, in which each version's section is counted separately (see
//     ppkScanner).
//
// A marker may be followed by a frame ("+> " on a quoted line, "+\t\"" on
// a line of Go source), so both rules read the trigger line from its
// start: their lookbehind is keyLookbehind. A frame that starts with a
// space reads as a context marker and a frame, so an indented key (a YAML
// block) is read as context lines, which belong to both versions.

import (
	"bytes"
)

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
	pemArmorLines   = 32
	pemArmorLineMax = 1024

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

	// ppkMaxOverflow bounds the base64 lines masked past a Private-Lines
	// count that is too low (see ppkScanner.overflow).
	ppkMaxOverflow = 100
)

var (
	pemDashes       = []byte("-----")
	pemEndPrefix    = []byte("-----END ")
	pemPrivateLabel = []byte("PRIVATE KEY")
	pemEscCR        = []byte(`\r`)
	pemEscLF        = []byte(`\n`)
	ppkPrivateLines = []byte("Private-Lines:")
	ppkPrivateMAC   = []byte("Private-MAC:")
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

// pemArmorBreak reports the line break ending an armor header line at
// pos: a raw one, or with escaped set (a key in a string literal) an
// escaped one; either may close a string literal's line first (see
// keyLineEnd). end is one past it.
func pemArmorBreak(window []byte, pos int, escaped bool) (end int, ok, need bool) {
	if escaped {
		if pos < len(window) && window[pos] == '\\' && bsRunEnd(window, pos)-pos > keyRunMax {
			return 0, false, false // no line break: decided in any window holding the line
		}
		return keyLineEnd(window, pos)
	}
	if pos < len(window) && (window[pos] == '"' || window[pos] == '\'') {
		_, end, ok, need = keyQuoteTail(window, pos)
		if ok && window[end-1] != '\n' {
			return 0, false, false // an escaped break: not a raw key
		}
		return end, ok, need
	}
	if pos < len(window) && window[pos] == '\\' {
		return 0, false, false
	}
	return keyBreak(window, pos)
}

// pemArmorLine parses one RFC 4880 armor header line ("Key: Value")
// following the line ending at end: the line break, then up to two diff
// markers or list bullets (whichever file version: the line is masked
// with the key), a line frame (keyFrameLen: an indentation, as in a YAML block, a quote
// or comment marker, an opening quote), the key, ':' with an optional ' '
// or '\t', and a value of up to pemArmorLineMax bytes. A value may hold
// bytes the body grammar refuses ("Version: GnuPG v1.4.11 (GNU/Linux)",
// `Comment: "Alice" <alice@example.com>`), so the line is taken whole. In
// a key in a string literal (lines broken by an escaped `\n`) a value
// ends at a bare '"' and may hold escapes (`\"`, `\\`, `\t`, `\/`, `\u0022`).
// It returns the offset of the line break ending the header line. cut
// reports that a non-final window ends before the line is decided.
func pemArmorLine(window []byte, end int, escaped, final bool) (lineEnd int, ok, cut bool) {
	p, ok, need := pemArmorBreak(window, end, escaped)
	if !ok {
		return 0, false, need && !final
	}
	if p >= len(window) {
		return 0, false, !final
	}
	// Any diff marker, or none: a header line is masked with the key
	// whichever file version it belongs to, and the BEGIN line's first
	// byte may be an indentation or a list bullet ("  ", "- ") the header
	// lines do not share. A second one is a list bullet or a nested
	// marker on a patch line ("+- Comment: ...").
	for k := 0; k < 2 && p < len(window) && diffSides(window[p]) != 0; k++ {
		p++
	}
	f, need := keyFrameLen(window, p, len(window))
	if need && !final {
		return 0, false, true
	}
	p += f
	key := p
	for p < len(window) && p-key < pemLabelMax && (isASCIILetter(window[p]) || isDigit(window[p]) || window[p] == '-' && p > key) {
		p++
	}
	if p >= len(window) {
		return 0, false, !final
	}
	if p == key || window[p] != ':' {
		return 0, false, false
	}
	p++
	switch {
	case p < len(window) && (window[p] == ' ' || window[p] == '\t'):
		p++
	case escaped && pemHasAt(window, p, []byte(`\t`)):
		p += 2
	}
	valueStart := p
	for {
		if p-valueStart > pemArmorLineMax {
			return 0, false, false
		}
		if p >= len(window) {
			return 0, false, !final
		}
		if _, ok, need := pemArmorBreak(window, p, escaped); ok {
			return p, true, false
		} else if need && !final {
			return 0, false, true
		}
		c := window[p]
		switch {
		case c < 0x20 && c != '\t' || c == 0x7f:
			return 0, false, false
		case escaped && c == '"':
			return 0, false, false // the end of the JSON string
		case escaped && c == '\\':
			j := bsRunEnd(window, p)
			if j-p > keyRunMax {
				return 0, false, false
			}
			if j >= len(window) {
				return 0, false, !final
			}
			if (j-p)%2 == 0 {
				p = j // escaped backslashes
				continue
			}
			switch window[j] {
			case '"', 't', '/', '\'':
				p = j + 1
				continue
			case 'u':
				if j+5 > len(window) {
					return 0, false, !final
				}
				if _, ok := hex4(window, j+1); ok {
					p = j + 5
					continue
				}
			}
			return 0, false, false
		}
		p++
	}
}

// armorScan skips RFC 4880 armor header lines after the line ending at
// end — the BEGIN line, or the last header line a previous window read —
// up to pemArmorLines of them. It returns where the body begins, or, when
// a non-final window ends inside the headers, open with the end of the
// last header line read as the resume point.
func (s *pemScanner) armorScan(window []byte, end int, final bool) (pos int, open bool) {
	for s.armorLines < pemArmorLines {
		next, ok, cut := pemArmorLine(window, end, s.escaped, final)
		if cut {
			return end, true
		}
		if !ok {
			break
		}
		s.armorLines++
		end = next
	}
	s.armor = false
	return end, false
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
	pemStatePrevAt = 21      // two bits: versions of a diff marker right before the resume point

	pemStateArmor     = 1 << 23 // armor headers are still being skipped
	pemStateArmorAt   = 24      // six bits: armor header lines skipped so far
	pemStateEscaped   = 1 << 30 // the block's lines break on escaped `\n`
	pemStateArmorMask = pemStateArmor | 0x3f<<pemStateArmorAt | pemStateEscaped
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
	prev       uint8  // versions of a diff marker opening a line right before offset 0
	armor      bool   // RFC 4880 armor headers are still being skipped
	armorLines int    // armor header lines skipped so far
	escaped    bool   // the block's lines break on escaped `\n`
	lastB64End int    // one past the last base64 byte seen, or -1
	snap       uint64 // the state at lastB64End, for resuming there
	frameEnd   int    // where the current line's diff marker and frame end, or -1
	frameSides uint8  // with diff, the versions of that line's marker
}

// state packs what a resumed scan needs. runLen only matters up to
// pemPlausibleRun and shortRuns never exceeds pemMaxShortRuns+1.
func (s *pemScanner) state() uint64 {
	st := uint64(min(s.runLen, pemPlausibleRun)) | uint64(s.shortRuns)<<8 | uint64(s.sides)<<16
	if s.diff {
		st |= pemStateDiff
	}
	if s.armor {
		st |= pemStateArmor | uint64(s.armorLines)<<pemStateArmorAt
		if s.escaped {
			st |= pemStateEscaped
		}
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
		prev:       uint8(state>>pemStatePrevAt) & (diffOld | diffNew),
		armor:      state&pemStateArmor != 0,
		armorLines: min(int(state>>pemStateArmorAt&0x3f), pemArmorLines),
		escaped:    state&pemStateEscaped != 0,
		lastB64End: 0,
		snap:       state &^ (pemStateInRun | pemStateLineNL | 3<<pemStatePrevAt),
		frameEnd:   0,
		frameSides: uint8(state>>pemStatePrevAt) & (diffOld | diffNew),
	}
}

// startsLineAt reports whether pos starts a line — follows a raw or an
// escaped line feed — in a window whose offset 0 starts one exactly when
// s.nl is set.
func (s *pemScanner) startsLineAt(window []byte, pos int) bool {
	if pos == 0 {
		return s.nl
	}
	return keyAfterBreak(window, pos)
}

// markerBefore reports the versions of the diff marker opening the line
// whose marker and frame end at window offset i (the line start processed
// last, or offset 0 of a resumed window), or of a marker right before i
// opening its line; 0 otherwise.
func (s *pemScanner) markerBefore(window []byte, i int) uint8 {
	if i == s.frameEnd {
		return s.frameSides
	}
	if i > 0 && i <= len(window) && s.startsLineAt(window, i-1) {
		return diffSides(window[i-1])
	}
	return 0
}

// plainLine is the cheapest case of newLine, small enough to inline: a line
// that opens with a letter or '=', behind a diff marker in diff mode.
func (s *pemScanner) plainLine(window []byte, i int) (next int, ok bool) {
	if !s.diff {
		return i, i < len(window) && keyLetterLine[window[i]]
	}
	if i+1 < len(window) && keyLetterLine[window[i+1]] {
		if sides := diffSides(window[i]); sides != 0 {
			s.frameEnd, s.frameSides = i+1, sides
			return i + 1, true
		}
	}
	return i, false
}

// newLine is lineStart with a fast path for the lines of a bare key, which
// start with key content (keyPlainLine), behind a diff marker in diff
// mode: they hold no hunk header, END marker or frame.
func (s *pemScanner) newLine(window []byte, i int, final bool) (next int, cut bool) {
	if !s.diff {
		if keyPlainLine(window, i) {
			return i, false
		}
	} else if i < len(window) {
		if sides := diffSides(window[i]); sides != 0 && keyPlainLine(window, i+1) {
			s.frameEnd, s.frameSides = i+1, sides
			return i + 1, false
		}
	}
	return s.lineStart(window, i, final)
}

// lineStart processes the start of a line at i, just past a line feed:
// with diff, the line's marker (recorded for its END line) and frame
// (keyLineMarker), else the frame (keyFrameLen); then a unified diff hunk
// header line ("@@ -1,7 +1,9 @@ ..."), which a key spanning two hunks of a
// patch holds and which is masked with it. It returns where the body scan goes on; cut
// reports that the window ends before the line start is decided.
func (s *pemScanner) lineStart(window []byte, i int, final bool) (next int, cut bool) {
	start := i
	var sides uint8
	framed := false
	if i < len(window) {
		if _, isEnd := pemEndMarker(window, i); !isEnd {
			switch {
			case s.diff:
				m, c, need, _ := keyLineMarker(window, i, len(window))
				if need && !final {
					return start, true
				}
				if m == '-' && c > i+1 {
					if _, isEnd := pemEndMarker(window, c-1); isEnd {
						m, c = 0, c-1 // "> -----END": the '-' opens the END marker
					}
				}
				sides, i, framed = diffSides(m), c, true
			case window[i] == '-':
				// Outside diff mode (the BEGIN line had more than a
				// marker and a frame before its trigger: code, a key
				// name), a removed line's marker before a frame or a hunk
				// header.
				if f, _ := keyFrameLen(window, i+1, len(window)); f > 0 || bytes.HasPrefix(window[i+1:], []byte("@@ -")) {
					i++
				}
			}
		}
	}
	if !framed {
		f, need := keyFrameLen(window, i, len(window))
		if need && !final {
			return start, true
		}
		i += f
	}
	// A hunk header, behind the frame and marker of a numbered or quoted
	// patch too ("    40→@@ -40,7 +40,7 @@").
	if end, ok, need := keyHunkHeader(window, i, final); ok {
		return end, false
	} else if need {
		return start, true
	}
	s.frameEnd, s.frameSides = i, sides
	return i, false
}

// resumeAt completes st, a scanner state for resuming at pos, with what the
// next window cannot see: whether pos starts a line, and the diff marker
// right before it (a "+" before "-----END" is base64, so a resume point can
// fall between them).
func (s *pemScanner) resumeAt(window []byte, pos int, st uint64) (int, uint64) {
	st &^= pemStateLineNL | 3<<pemStatePrevAt
	if s.startsLineAt(window, pos) {
		st |= pemStateLineNL
	}
	return pos, st | uint64(s.markerBefore(window, pos))<<pemStatePrevAt
}

// openAt reports where an open block resumes when the scan stopped at pos:
// at the last base64 byte if it is close enough behind, else at pos.
func (s *pemScanner) openAt(window []byte, pos int) (resume int, state uint64) {
	if s.lastB64End > 0 && pos-s.lastB64End <= pemResumeLag {
		return s.resumeAt(window, s.lastB64End, s.snap)
	}
	return s.resumeAt(window, pos, s.state())
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
// marker first), and the backslash escapes of a key in a string literal
// (keyEscape: `\n` `\r` `\t` `\"`, `\/` and `\u002B` as PHP and .NET encode
// '/' and '+', any backslash run) so JSON-escaped keys in structured logs
// are covered. At the start of each line (after a raw or an escaped line
// feed) it skips a hunk header line, the diff marker and the line's frame
// (lineStart), and a quote closing a string literal's line (`" +`) is
// taken with the line break after it. With limit >= 0, a plausible scan
// stops at the first token boundary at or past limit (pemStopOpen), at
// the end of the window inside a backslash run (pemStopOpen with pos ==
// len(window)), or at a line start the window cuts.
func (s *pemScanner) scan(window []byte, i, limit int, final bool) (pos int, stop pemStop) {
	for {
		if limit >= 0 && i >= limit && s.plausible {
			return i, pemStopOpen
		}
		if i >= len(window) {
			return i, pemStopWindow
		}
		c := window[i]
		kind, e := escJunk, 0
		if c == '\\' {
			if i+1 < len(window) && window[i+1] == 'n' {
				kind, e = escLF, i+2 // the common case, decoded inline
			} else {
				kind, e, _ = keyEscape(window, i)
			}
		}
		if pemBase64[c] || kind == escB64 {
			// Consume the run at once, with the escapes that stand for
			// base64 bytes. plausible only changes when a run closes, so the
			// resume limit binds within the run exactly as it would byte by
			// byte.
			stop := len(window)
			if limit >= 0 && s.plausible && limit < stop {
				stop = limit
			}
			j := i
			for j < stop {
				// A range loop over the slice, free of bounds checks: body
				// scans spend most of their time here.
				n := 0
				for _, c := range window[j:stop] {
					if !pemBase64[c] {
						break
					}
					n++
				}
				if j += n; j >= stop || window[j] != '\\' {
					break
				}
				e := keyB64Escape(window, j)
				if e == 0 {
					break
				}
				j = e
			}
			s.runLen += j - i
			i = j
			s.lastB64End = i
			s.snap = s.state()
			continue
		}
		if kind == escNeed && limit >= 0 && s.plausible && bsRunEnd(window, i) == len(window) {
			// A backslash run reaches the end of a non-final window: it may
			// go on in the next one, as an escape that continues the run in
			// progress or ends it.
			return len(window), pemStopOpen
		}
		if !s.closeRun() {
			return i, pemStopJunk // too many prose-like short runs: give up
		}
		switch c {
		case ' ', '\t', '\r', ':', ',':
			// Whitespace and encapsulated-header punctuation
			// (Proc-Type: 4,ENCRYPTED / DEK-Info: ...).
			i++
		case '\n':
			i++
			if j, ok := s.plainLine(window, i); ok {
				i = j
				continue
			}
			next, cut := s.newLine(window, i, final)
			if cut {
				return s.cutStop(i)
			}
			i = next
		case '\\':
			// JSON-style escapes inside string-embedded keys. A run of
			// backslashes is consumed as one unit so that multiply-escaped
			// keys (JSON inside JSON, e.g. `\\n` or `\\\\n` in nested tool
			// output) are covered as well as singly-escaped `\n`.
			switch kind {
			case escSep:
				i = e
			case escLF:
				i = e
				if j, ok := s.plainLine(window, i); ok {
					i = j
					continue
				}
				next, cut := s.newLine(window, i, final)
				if cut {
					return s.cutStop(i)
				}
				i = next
			case escNeed:
				// The window cuts the escape (a run that began before the
				// block was plausible is not held at the resume limit).
				if !final {
					return s.cutStop(i)
				}
				return i, pemStopJunk
			default:
				return i, pemStopJunk
			}
		case '"', '\'':
			// A quote closing a string literal's line: "...\n" + or "...",
			// then the line break.
			at, _, ok, need := keyQuoteTail(window, i)
			if !ok {
				if need && !final {
					return s.cutStop(i)
				}
				return i, pemStopJunk
			}
			i = at
		case '-':
			e, found := pemEndMarker(window, i)
			if !found {
				// Not an END marker for a private key (e.g. the hyphen in
				// "DEK-Info" or "AES-128-CBC", a mismatched END label, or a
				// diff removal marker): body punctuation, keep looking.
				i++
				continue
			}
			if s.diff {
				if line := s.markerBefore(window, i); line != 0 {
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

// cutStop reports how a scan stops at the start of a line, at, that the
// window cuts before it is decided: open there for a plausible block in a
// non-final window, which decides it again in the next, else as at junk.
func (s *pemScanner) cutStop(at int) (int, pemStop) {
	if s.plausible {
		return at, pemStopOpen
	}
	return at, pemStopJunk
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

	s := pemScanner{lastB64End: -1, nl: true, frameEnd: -1}
	if marker := keyTriggerMarker(window, trigStart); marker != 0 {
		s.diff, s.sides = true, diffSides(marker)
	}
	body := labelEnd + len(pemDashes)
	s.armor = true
	if body < len(window) && window[body] == '\\' {
		_, s.escaped, _ = keyBreak(window, body)
	}
	body, open = s.armorScan(window, body, final)
	if open {
		// Armor header lines run to the end of the window: a block that
		// long behind a private-key BEGIN line is taken as a key (masking
		// is the safe side) and followed into the next window.
		resume, st := s.resumeAt(window, body, s.state())
		return trigStart, resume, st, true, true
	}

	limit := -1
	if !final && len(window)-pemResumeReserve > body {
		limit = len(window) - pemResumeReserve
	}
	pos, stop := s.scan(window, body, limit, final)
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
		return s.resumeAt(window, pos, s.state()|pemStateInRun)
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
	inArmor := s.armor
	if s.armor {
		pos, open := s.armorScan(window, 0, final)
		if open {
			if pos == 0 {
				return 0, 0, false
			}
			resume, st := s.resumeAt(window, pos, s.state())
			return resume, st, true
		}
		i = pos
		s.snap = s.state()
	}
	switch {
	case state&pemStateInRun != 0:
		// The previous window ended inside a backslash run: the escape it
		// opens continues the run in progress or ends it.
		j := bsRunEnd(window, 0)
		if j == len(window) {
			if final || j == 0 {
				return 0, 0, false
			}
			return j, state, true
		}
		kind, e, _ := keyEscapeAfter(window, j)
		switch kind {
		case escB64:
			s.runLen += e
			i = e
			s.lastB64End = i
			s.snap = s.state()
		case escSep, escLF:
			if !s.closeRun() {
				return 0, 0, false
			}
			i = e
			if kind == escLF {
				next, cut := s.lineStart(window, e, final)
				if cut {
					// Decide the line start in the next window, which
					// starts there.
					return e, s.state()&^(3<<pemStatePrevAt) | pemStateLineNL, true
				}
				i = next
			}
		case escNeed:
			if final || j == 0 {
				return 0, 0, false
			}
			return j, state, true
		default:
			return 0, 0, false
		}
	case s.nl && !inArmor:
		// The window starts a line: a hunk header the previous window cut,
		// or a line whose start it already read the same way.
		next, cut := s.lineStart(window, 0, final)
		if cut {
			return 0, 0, false
		}
		i = next
	}
	pos, stop := s.scan(window, i, limit, final)
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
	ppkStateSteppedAt = 41 // seven bits: lines stepped over since a count, or overflow lines
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
		uint64(min(s.stepped, 0x7f))<<ppkStateSteppedAt
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
// optional spaces, 1-5 digits (not zero), optional spaces, then the end
// of the line (keyLineEnd: a raw or escaped line break, or the end of a
// string literal's line). It returns the count and the offset of the next
// line. incomplete reports that the window ended inside the line.
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
	next, ok, need := keyLineEnd(window, p)
	if need {
		return 0, 0, false, true
	}
	if !ok {
		return 0, 0, false, false
	}
	return n, next, true, false
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

// ppkContent returns the end of a body line's content from p: base64
// bytes and the escapes that stand for them (`\/`, `\u002B`).
func ppkContent(window []byte, p int) int {
	for p < len(window) {
		if pemBase64[window[p]] {
			p++
			continue
		}
		if e := keyB64Escape(window, p); e > 0 {
			p = e
			continue
		}
		break
	}
	return p
}

// lines scans body lines from p, which starts a line. Outside a diff a body
// line is a frame (keyFrameLen: an indentation, a quote or comment marker,
// a line number), base64 content and a line end (keyLineEnd: a raw or
// escaped line break, or the end of a string literal's line); in diff
// mode a marker comes first. A line with base64 then junk still counts its
// base64 prefix (fail-safe) and ends the section. In diff mode a hunk
// header line between two hunks is stepped over; outside a diff, base64
// lines past a count that is too low follow (overflow). When final is
// false and the window cuts a line, the scan stops open: a counted line is
// split at the window end, anything else resumes as cutOpen says.
func (s *ppkScanner) lines(window []byte, p int, final bool) (resume int, state uint64, open bool) {
	for {
		if s.complete(p) && !s.overflowing() {
			return 0, 0, false
		}
		if p >= len(window) {
			if final {
				return 0, 0, false
			}
			return s.cutOpen(p, ppkModeLine)
		}
		lineStart := p
		if s.complete(p) {
			next, ok, cut := s.overflow(window, p, final)
			switch {
			case cut:
				return s.cutOpen(lineStart, ppkModeLine)
			case !ok:
				return 0, 0, false
			}
			p = next
			continue
		}

		l, ok, cut := s.head(window, p, final)
		switch {
		case cut:
			return s.cutOpen(lineStart, ppkModeLine)
		case !ok:
			return 0, 0, false
		case l.hunk >= 0:
			// A hunk header between two hunks of a patch: a key's lines go
			// on in the next hunk. It is stepped over, and masked between
			// counted lines.
			if lineStart >= s.reach && s.stepped >= ppkMaxStepLines {
				return 0, 0, false
			}
			s.stepped++
			p = l.hunk
			continue
		case s.diff && !l.marked:
			return 0, 0, false
		}
		sides := l.sides
		p = l.content

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

		q := ppkContent(window, p)
		next, complete, need := keyLineEnd(window, q)
		cut = !complete && need && !final
		if cut && q == p && s.counts(sides) {
			if p < len(window) && window[p] == '\\' && bsRunEnd(window, p) == len(window) {
				// A backslash run can encode a base64 slash beyond this
				// window. Replaying the framed line would make no progress
				// when the run itself is longer than a window. Count the
				// potential body line and retain one slash for the escape.
				if resume := len(window) - 1; resume > p {
					s.count(sides)
					return resume, s.stateAt(resume, ppkModeMid), true
				}
			}
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
				p = next
				continue
			case cut:
				// The window ends inside the line: mask what is in view
				// and go on inside the line.
				return q, s.stateAt(q, ppkModeMid), true
			}
			return 0, 0, false // junk after the base64 prefix, or end of input
		}

		// A line no count needs. Outside a diff, or on a version still
		// counting (an empty or junk line), it ends the section; in a diff
		// it is stepped over while a followed version holds the scan.
		if !s.diff || s.counts(sides) {
			return 0, 0, false
		}
		// A version whose section is complete while the other still holds
		// the scan may go on past its count (overflow).
		if s.overflowing() && s.doneOn(sides) {
			next, ok, cut := s.overflowBody(window, lineStart, p, final)
			if cut {
				return s.cutOpen(lineStart, ppkModeLine)
			}
			if ok {
				p = next
				continue
			}
		}
		// Stepping is bounded the same however the input is windowed: a
		// stepped line may end at most ppkMaxStepLine bytes past where it
		// starts or past the header reach, whichever is later, and past
		// the reach at most ppkMaxStepLines lines in a row are stepped.
		beyond := lineStart >= s.reach
		if beyond && s.stepped >= ppkMaxStepLines {
			return 0, 0, false
		}
		limit := max(lineStart, s.reach) + ppkMaxStepLine
		at, end, cutAt := keyNextBreak(window, p)
		if at < 0 {
			switch {
			case final, len(window) > limit:
				return 0, 0, false
			case beyond || s.lastEnd > 0 || cutAt <= lineStart:
				return s.cutOpen(lineStart, ppkModeLine)
			}
			// Go on inside the line in the next window, with what is left
			// of its allowance.
			return cutAt, s.stepStateAt(cutAt, limit), true
		}
		if at > limit {
			return 0, 0, false
		}
		s.stepped++
		p = end
	}
}

// doneOn reports whether a followed version of sides has read its whole
// count.
func (s *ppkScanner) doneOn(sides [2]bool) bool {
	for side, in := range sides {
		if in && s.allow[side] && s.seen[side] && s.need[side] == 0 {
			return true
		}
	}
	return false
}

// overflowing reports whether a complete section may still take base64
// lines past its count (see overflow).
func (s *ppkScanner) overflowing() bool {
	return (s.seen[ppkOld] || s.seen[ppkNew]) && s.stepped < ppkMaxOverflow
}

// overflow reads a line past the end of a section whose Private-Lines
// count was too low: a line of base64 content (behind a frame and, in a
// diff, a followed version's marker) is masked as a body line when it is
// at least pemPlausibleRun bytes long, ends with '=' padding, or is
// followed by the "Private-MAC:" line that ends a PPK file's private
// section. At most ppkMaxOverflow such lines of at most ppkMaxStepLine
// bytes each (line end included), counted in stepped: no line is stepped
// over once the section is complete. In a well-formed file the
// Private-MAC line follows the count at once, so nothing changes. It
// returns the next line's start; cut reports that the window ends before
// the line is decided.
func (s *ppkScanner) overflow(window []byte, p int, final bool) (next int, ok, cut bool) {
	l, ok, cut := s.head(window, p, final)
	switch {
	case cut:
		return 0, false, true
	case !ok:
		return 0, false, false
	case l.hunk >= 0:
		// A hunk header: the key's lines may go on in the next hunk.
		s.stepped++
		return l.hunk, true, false
	case s.diff && !(l.marked && (l.sides[ppkOld] && s.allow[ppkOld] || l.sides[ppkNew] && s.allow[ppkNew])):
		return 0, false, false
	}
	return s.overflowBody(window, p, l.content, final)
}

// ppkLine is the start of a line as a PPK scan reads it.
type ppkLine struct {
	sides   [2]bool // the versions of its diff marker; outside a diff, the new one
	marked  bool    // in diff mode, the line has a marker
	content int     // where its content starts
	hunk    int     // for a hunk header line, the start of the next line, else -1
}

// head reads the start of the line at p: in diff mode its marker and frame
// in either order (keyLineMarker), else its frame (keyFrameLen), then a
// hunk header behind them. cut reports that a non-final window ends before
// that is decided; !ok, a hunk header at the end of input.
func (s *ppkScanner) head(window []byte, p int, final bool) (l ppkLine, ok, cut bool) {
	l = ppkLine{sides: [2]bool{false, true}, hunk: -1}
	if s.diff {
		m, c, need, spaced := keyLineMarker(window, p, len(window))
		if need && !final {
			return l, false, true
		}
		l.content = c
		if m == 0 && spaced {
			// A patch quoted with no space (">" + marker): the quote
			// marker's conventional space is the context marker.
			m = ' '
		}
		if m != 0 {
			l.sides, _ = ppkSides(m)
			l.marked = true
		}
	} else {
		f, need := keyFrameLen(window, p, len(window))
		if need && !final {
			return l, false, true
		}
		l.content = p + f
	}
	if end, ok, need := keyHunkHeader(window, l.content, final); ok {
		next, ok, need := keyLineEnd(window, end)
		switch {
		case need && !final:
			return l, false, true
		case !ok:
			return l, false, false
		}
		l.hunk = next
	} else if need {
		return l, false, true
	}
	return l, true, false
}

// overflowBody is overflow from body, where the content of the line at
// start begins.
func (s *ppkScanner) overflowBody(window []byte, start, body int, final bool) (next int, ok, cut bool) {
	q := ppkContent(window, body)
	next, ok, need := keyLineEnd(window, q)
	switch {
	case ok && next-start > ppkMaxStepLine, !ok && len(window)-start > ppkMaxStepLine:
		return 0, false, false // not a PPK body line
	case need && !final:
		return 0, false, true
	case q == body:
		return 0, false, false
	case !ok && !(final && q == len(window)):
		return 0, false, false // junk after base64: "Private-MAC" itself
	}
	if q-body < pemPlausibleRun && window[q-1] != '=' {
		if !ok {
			return 0, false, false
		}
		var c int
		if s.diff {
			_, c, need, _ = keyLineMarker(window, next, len(window))
		} else {
			var f int
			f, need = keyFrameLen(window, next, len(window))
			c = next + f
		}
		if need && !final {
			return 0, false, true
		}
		if rest := window[c:]; !bytes.HasPrefix(rest, ppkPrivateMAC) {
			if !final && len(rest) < len(ppkPrivateMAC) && bytes.HasPrefix(ppkPrivateMAC, rest) {
				return 0, false, true
			}
			return 0, false, false
		}
	}
	s.stepped++
	s.lastEnd = q
	if !ok {
		return len(window), true, false // the end of input
	}
	s.snap = s.stateAt(q, ppkModeEOL)
	return next, true, false
}

// stepStateAt packs the scanner for resuming at pos inside a stepped line
// that may run up to limit: in that mode the reach field holds the line's
// remaining allowance (the reach is then at most ppkMaxStepLine less).
func (s *ppkScanner) stepStateAt(pos, limit int) uint64 {
	st := s.stateAt(pos, ppkModeStep) &^ (0xffff << ppkStateReachAt)
	return st | uint64(min(max(limit-pos, 0), 0xffff))<<ppkStateReachAt
}

// ppkTriggerSides reports the file versions a PPK trigger line belongs to:
// its diff marker's (keyTriggerPrefix: the marker may be followed by a
// frame), or both (any) when the trigger does not open a marked line.
// loose reports a marker followed by a frame, which may as well be an
// indentation or a quote: such a trigger also takes an unmarked header,
// as an unmarked trigger does.
func ppkTriggerSides(window []byte, trigStart int) (sides [2]bool, marked, loose bool) {
	if marker, framed := keyTriggerPrefix(window, trigStart); marker != 0 {
		sides, _ := ppkSides(marker)
		return sides, true, framed
	}
	return [2]bool{true, true}, false, false
}

// ppkFindHeader returns the offset of the first "Private-Lines:" at or
// after from that opens a line — directly, behind a frame (keyFrameLen:
// an indentation, a quote or comment marker, a line number), or behind one
// unified diff marker and a frame — after a raw or an escaped line feed,
// and the marker (0 outside a diff). A header of a marked trigger must
// open a line of a version the trigger belongs to.
func ppkFindHeader(window []byte, from int, allow [2]bool, marked, loose bool) (at int, marker byte, ok bool) {
	for from < len(window) {
		rel := bytes.Index(window[from:], ppkPrivateLines)
		if rel < 0 {
			return 0, 0, false
		}
		at = from + rel
		if ls, ok := keyLineStart(window, at, false); ok {
			if m, ok := keyLinePrefix(window, ls, at); ok {
				if m == 0 && (!marked || loose) {
					return at, 0, true
				}
				if sides, ok := ppkSides(m); ok && (sides[ppkOld] && allow[ppkOld] || sides[ppkNew] && allow[ppkNew]) {
					return at, m, true
				}
			}
		}
		from = at + 1
	}
	return 0, 0, false
}

// ppkQuotedPatch reports a header at at, behind a quote marker and its
// conventional space (">" + " " + "Private-Lines:"), whose next line, at
// next, puts a diff marker right after the quote marker (">-", ">+"): a
// patch quoted with no space, in which that space is a context marker.
func ppkQuotedPatch(window []byte, at, next int) bool {
	ls, ok := keyLineStart(window, at, false)
	if !ok {
		return false
	}
	if m, c, _, spaced := keyLineMarker(window, ls, at); m != 0 || !spaced || c != at {
		return false
	}
	m, _, _, spaced := keyLineMarker(window, next, len(window))
	return (m == '+' || m == '-') && !spaced
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

	allow, marked, loose := ppkTriggerSides(window, trigStart)
	secStart, marker, found := ppkFindHeader(window, trigEnd, allow, marked, loose)
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
	if marker == 0 && ppkQuotedPatch(window, secStart, p) {
		marker = ' ' // a context line of a patch quoted with no space
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
	case ppkModeMid, ppkModeEOL:
		// Inside or at the end of a counted line's content (or an overflow
		// line's): the rest of the content, then the line end.
		p = ppkContent(window, 0)
		if p > 0 {
			s.lastEnd = p
		}
		next, ok, need := keyLineEnd(window, p)
		if !ok {
			if need && !final {
				if p == 0 {
					// A line end longer than the window: a backslash run.
					p = keyCutResume(window, 0)
				}
				if p > 0 {
					return p, s.stateAt(p, ppkModeMid), true
				}
			}
			return max(s.lastEnd, 0), 0, false
		}
		p = next
		s.snap = s.stateAt(max(s.lastEnd, 0), ppkModeEOL)
	case ppkModeStep:
		// The reach field holds the stepped line's remaining allowance.
		allowance := s.reach
		s.reach = max(allowance-ppkMaxStepLine, 0)
		at, end, cutAt := keyNextBreak(window, 0)
		if at < 0 {
			if final || len(window) > allowance || cutAt == 0 {
				return 0, 0, false
			}
			return cutAt, s.stepStateAt(cutAt, allowance), true
		}
		if at > allowance {
			return 0, 0, false
		}
		s.stepped++
		p = end
	}
	resume, st, open := s.lines(window, p, final)
	if open && resume > 0 {
		return resume, st, true
	}
	return max(s.lastEnd, 0), 0, false
}
