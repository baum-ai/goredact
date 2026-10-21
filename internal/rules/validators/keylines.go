package validators

// Line shapes shared by the private-key scans (privatekey.go). A key is
// rarely pasted bare: it sits in a string literal (escaped by JSON, PHP or
// .NET encoders), behind a per-line prefix (an email or Markdown quote, a
// comment, a line number, an indentation, an opening quote), at the end of
// a concatenated string line, or between two hunks of a patch. These
// helpers recognise those shapes so the scans can read the key lines
// inside them.
//
// Every helper is bounded and never indexes out of range. Those that look
// ahead report need when the window ends before they can decide: a scan
// over a non-final window then stops before the shape and decides it in
// the next window, which starts at or before it.

const (
	// keyFrameMax bounds a line frame, the prefix before a key line's
	// content (see keyFrameLen).
	keyFrameMax = 64

	// keyLookbehind is the key rules' lookbehind: a trigger line's frame,
	// its diff marker and the (possibly escaped) line break before them
	// (TestKeyLookbehindMatchesSpec).
	keyLookbehind = keyFrameMax + 3

	// keyTailMax bounds the bytes between a closing quote and the line
	// break of a concatenated string line (`" +`, `",`, `");`).
	keyTailMax = 8

	// keyHunkMax bounds a unified diff hunk header line, its section
	// heading included (git truncates that heading to 80 bytes).
	keyHunkMax = 256

	// keyNumberMax bounds the digits of a line number frame.
	keyNumberMax = 9
)

// bsRunEnd returns the offset one past the run of backslashes at i.
func bsRunEnd(w []byte, i int) int {
	for i < len(w) && w[i] == '\\' {
		i++
	}
	return i
}

// escKind classifies a backslash escape.
type escKind uint8

const (
	escJunk escKind = iota // not an escape a key can hold
	escNeed                // the window ends inside it
	escSep                 // \r \t \" \' or a \u escape of a separator
	escLF                  // \n, \u000A, or a backslash ending the line (a continuation)
	escB64                 // \/ or + / =: a base64 byte
)

// hex4 decodes four hex digits at p.
func hex4(w []byte, p int) (v int, ok bool) {
	if p < 0 || p+4 > len(w) {
		return 0, false
	}
	for _, c := range w[p : p+4] {
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

// keyEscapeAfter decodes an escape whose backslash run ends at j (w[j] is
// the escaped byte): its kind, the offset one past it, and for \r the
// byte 'r' (so a caller can expect an escaped \n after it).
func keyEscapeAfter(w []byte, j int) (kind escKind, end int, c byte) {
	if j >= len(w) {
		return escNeed, len(w), 0
	}
	switch c = w[j]; c {
	case 'n', '\n':
		return escLF, j + 1, c
	case 'r':
		return escSep, j + 1, c
	case 't', '"', '\'':
		return escSep, j + 1, c
	case '/':
		return escB64, j + 1, c
	case '\r':
		// A backslash before "\r\n" continues the line.
		if j+1 >= len(w) {
			return escNeed, len(w), c
		}
		if w[j+1] == '\n' {
			return escLF, j + 2, c
		}
	case 'u':
		// JSON \uXXXX, as .NET's System.Text.Json writes '+' (+).
		for k := j + 1; k < j+5; k++ {
			if k >= len(w) {
				return escNeed, len(w), c
			}
			if !isHexByte(w[k]) {
				return escJunk, j, c
			}
		}
		v, _ := hex4(w, j+1)
		switch v {
		case '\n':
			return escLF, j + 5, 'n'
		case '\r':
			return escSep, j + 5, 'r'
		case '+', '/', '=':
			return escB64, j + 5, byte(v)
		case '\t', ' ', '"', '\'', ',', ':':
			return escSep, j + 5, byte(v)
		}
	}
	return escJunk, j, c
}

// keyEscape decodes the escape at i (w[i] == '\\'). A run of backslashes
// escapes like one, so multiply-escaped keys (JSON inside JSON) read like
// singly-escaped ones.
func keyEscape(w []byte, i int) (kind escKind, end int, c byte) {
	return keyEscapeAfter(w, bsRunEnd(w, i))
}

// keyB64Escape returns the offset one past an escape at i that stands for
// a base64 byte (`\/`, `+`, ...), or 0.
func keyB64Escape(w []byte, i int) int {
	if i >= len(w) || w[i] != '\\' {
		return 0
	}
	if kind, end, _ := keyEscape(w, i); kind == escB64 {
		return end
	}
	return 0
}

// keyBreak reports a line break at p: "\n" or "\r\n", or an escaped one —
// `\n` or `\r\n` (any backslash run), \u000A, or a backslash continuing
// the line. end is one past it.
func keyBreak(w []byte, p int) (end int, ok, need bool) {
	if p >= len(w) {
		return 0, false, true
	}
	switch w[p] {
	case '\n':
		return p + 1, true, false
	case '\r':
		if p+1 >= len(w) {
			return 0, false, true
		}
		if w[p+1] == '\n' {
			return p + 2, true, false
		}
		return 0, false, false
	case '\\':
		kind, e, c := keyEscape(w, p)
		switch {
		case kind == escNeed:
			return 0, false, true
		case kind == escLF:
			return e, true, false
		case kind == escSep && c == 'r' && e < len(w) && w[e] == '\\':
			if kind, e2, _ := keyEscape(w, e); kind == escLF {
				return e2, true, false
			} else if kind == escNeed {
				return 0, false, true
			}
		case kind == escSep && c == 'r' && e >= len(w):
			return 0, false, true
		}
	}
	return 0, false, false
}

// keyQuoteTail reports the end of a string literal's line at p: a closing
// quote (", ' or an escaped quote), up to keyTailMax bytes of " \t+,;)",
// and a line break. at is where that line break starts, end one past it.
func keyQuoteTail(w []byte, p int) (at, end int, ok, need bool) {
	q := p
	if q < len(w) && w[q] == '\\' {
		q = bsRunEnd(w, q)
	}
	if q >= len(w) {
		return 0, 0, false, true
	}
	if w[q] != '"' && w[q] != '\'' {
		return 0, 0, false, false
	}
	q++
	for n := 0; q < len(w) && n < keyTailMax && isTailByte(w[q]); n++ {
		q++
	}
	end, ok, need = keyBreak(w, q)
	return q, end, ok, need
}

func isTailByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '+' || c == ',' || c == ';' || c == ')'
}

// keyLineEnd reports the end of a key line at p: a line break, or the end
// of a string literal's line — an escaped line break then a closing quote
// tail (`\n" +` and a raw line break, as when a key is concatenated from
// one string per line), or a closing quote tail alone. end is one past it.
func keyLineEnd(w []byte, p int) (end int, ok, need bool) {
	end, ok, need = keyBreak(w, p)
	if need {
		return 0, false, true
	}
	if ok {
		if w[p] == '\\' {
			if _, e2, ok2, need2 := keyQuoteTail(w, end); ok2 {
				return e2, true, false
			} else if need2 {
				return 0, false, true
			}
		}
		return end, true, false
	}
	_, end, ok, need = keyQuoteTail(w, p)
	return end, ok, need
}

// keyAfterBreak reports whether pos (> 0) directly follows a raw or an
// escaped line feed (`\n` after any backslash run, or \u000A).
func keyAfterBreak(w []byte, pos int) bool {
	if pos <= 0 || pos > len(w) {
		return false
	}
	switch w[pos-1] {
	case '\n':
		return true
	case 'n':
		return pos >= 2 && w[pos-2] == '\\'
	case 'A', 'a':
		v, ok := hex4(w, pos-4)
		return ok && v == '\n' && pos >= 6 && w[pos-6] == '\\' && w[pos-5] == 'u'
	}
	return false
}

// keyNumberSep reports the separator after a line number at p — a tab
// (as `cat -n` writes it, raw or escaped) or the arrow U+2192 that agent
// transcripts use (raw UTF-8 or escaped →) — and the offset one past
// it, or 0.
func keyNumberSep(w []byte, p int) (end int, need bool) {
	if p >= len(w) {
		return 0, true
	}
	switch w[p] {
	case '\t':
		return p + 1, false
	case 0xe2:
		if p+3 > len(w) {
			return 0, true
		}
		if w[p+1] == 0x86 && w[p+2] == 0x92 {
			return p + 3, false
		}
	case '\\':
		j := bsRunEnd(w, p)
		if j >= len(w) {
			return 0, true
		}
		if w[j] == 't' {
			return j + 1, false
		}
		if w[j] == 'u' {
			if j+5 > len(w) {
				return 0, true
			}
			if v, ok := hex4(w, j+1); ok && v == 0x2192 {
				return j + 5, false
			}
		}
	}
	return 0, false
}

// keyFrameLen returns the length of the line frame at p, at most
// keyFrameMax bytes and ending at or before limit: a sequence of
// indentation (spaces, tabs, escaped tabs), quote markers ('>'), comment
// markers ('#', "//", ';', '*', '%', '|'), a leading '+' of a continued
// expression, opening quotes (", ' or an escaped quote) and line numbers
// followed by a tab or an arrow ("    12→", "12\t"). It never takes a '-',
// so it cannot hide an END marker. need reports that the window ends
// before the frame does.
func keyFrameLen(w []byte, p, limit int) (n int, need bool) {
	start := p
	limit = min(limit, len(w), start+keyFrameMax)
	// The window ends before the frame is decided only when it ends
	// within keyFrameMax bytes: a token running past that is no frame.
	short := len(w) < start+keyFrameMax
	for p < limit {
		var next int
		switch c := w[p]; {
		case c == ' ' || c == '\t' || c == '>' || c == '#' || c == ';' || c == '*' ||
			c == '%' || c == '|' || c == '+' || c == '"' || c == '\'':
			next = p + 1
		case c == '/':
			if p+1 >= len(w) {
				return p - start, short
			}
			if w[p+1] != '/' {
				return p - start, false
			}
			next = p + 2
		case c == '\\':
			j := bsRunEnd(w, p)
			if j >= len(w) {
				return p - start, short
			}
			if w[j] != 't' && w[j] != '"' && w[j] != '\'' {
				return p - start, false
			}
			next = j + 1
		case isDigit(c):
			j := p
			for j < len(w) && isDigit(w[j]) && j-p < keyNumberMax {
				j++
			}
			e, need := keyNumberSep(w, j)
			if need {
				return p - start, short
			}
			if e == 0 {
				return p - start, false
			}
			next = e
		default:
			return p - start, false
		}
		if next > limit {
			break
		}
		p = next
	}
	return p - start, p == len(w) && short
}

// keyPlainLine reports whether the line starting at p (a body line outside
// a diff) begins with no frame or hunk header: its first byte is a letter,
// '=', or a digit run that no tab or arrow follows. Scans use it to skip
// keyFrameLen and keyHunkHeader on the lines of a bare key.
func keyPlainLine(w []byte, p int) bool {
	if p >= len(w) || !keyContentStart[w[p]] {
		return false
	}
	if !isDigit(w[p]) {
		return true
	}
	j := p + 1
	for j < len(w) && j-p < keyNumberMax && isDigit(w[j]) {
		j++
	}
	return j < len(w) && w[j] != '\t' && w[j] != 0xe2 && w[j] != '\\' && !isDigit(w[j])
}

// keyLetterLine holds the bytes that open a key line and nothing else:
// letters and '='.
var keyLetterLine = func() (t [256]bool) {
	for c := range t {
		t[c] = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '='
	}
	return t
}()

// keyContentStart holds the bytes that can open a key line but no frame
// or hunk header: letters, digits (unless a line number) and '='.
var keyContentStart = func() (t [256]bool) {
	for c := range t {
		t[c] = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '='
	}
	return t
}()

// keyLineStart returns the start of the line holding at when it begins at
// most keyFrameMax+1 bytes before at: just past a raw or escaped line
// feed, or at the start of the window when fromInput reports that the
// window starts at the start of input.
func keyLineStart(w []byte, at int, fromInput bool) (int, bool) {
	if at < 0 || at > len(w) {
		return 0, false
	}
	lo := max(0, at-keyFrameMax-2)
	for k := at - 1; k >= lo; k-- {
		if keyAfterBreak(w, k+1) {
			return k + 1, true
		}
	}
	if lo == 0 && fromInput {
		return 0, true
	}
	return 0, false
}

// keyLinePrefix parses w[ls:at], what precedes at on its line: a unified
// diff marker ('+', '-' or ' ') then a frame, or a frame alone. marker is
// 0 for a frame alone. A prefix that is a frame alone but starts with a
// space reads as a context marker and a frame.
func keyLinePrefix(w []byte, ls, at int) (marker byte, ok bool) {
	if ls < 0 || ls > at || at > len(w) {
		return 0, false
	}
	if ls < at && diffSides(w[ls]) != 0 {
		if n, _ := keyFrameLen(w, ls+1, at); n == at-ls-1 {
			return w[ls], true
		}
	}
	if n, _ := keyFrameLen(w, ls, at); n == at-ls {
		return 0, true
	}
	return 0, false
}

// keyHunkHeader reports a unified diff hunk header line at p ("@@ -12,7
// +12,8 @@" and an optional section heading, keyHunkMax bytes at most):
// end is where the line break ending it starts (the end of input when
// final and no break follows).
func keyHunkHeader(w []byte, p int, final bool) (end int, ok, need bool) {
	if p >= len(w) {
		return 0, false, !final
	}
	if w[p] != '@' {
		return 0, false, false
	}
	// "@@ -" N[,N] " +" N[,N] " @@", decided byte by byte.
	q := p
	for part := 0; part < 5; part++ {
		switch part {
		case 0, 2, 4:
			lit := [...]string{"@@ -", "", " +", "", " @@"}[part]
			for i := 0; i < len(lit); i++ {
				if q >= len(w) {
					return 0, false, !final
				}
				if w[q] != lit[i] {
					return 0, false, false
				}
				q++
			}
		default:
			for n := 0; n < 2; n++ {
				d := q
				for q < len(w) && isDigit(w[q]) && q-d < 10 {
					q++
				}
				if q >= len(w) {
					return 0, false, !final
				}
				if q == d {
					return 0, false, false
				}
				if n == 1 || w[q] != ',' {
					break
				}
				q++
			}
		}
	}
	for q < len(w) && q-p <= keyHunkMax {
		switch w[q] {
		case '\n':
			return q, true, false
		case '\r':
			if q+1 < len(w) && w[q+1] == '\n' {
				return q, true, false
			}
		case '\\':
			kind, e, _ := keyEscape(w, q)
			switch {
			case kind == escLF:
				return q, true, false
			case kind == escNeed && !final && e-p <= keyHunkMax:
				return 0, false, true
			}
			q = max(e, q+1)
			continue
		}
		q++
	}
	if q-p > keyHunkMax {
		return 0, false, false
	}
	if final {
		return q, true, false
	}
	return 0, false, true
}

// keyNextBreak finds the next raw or escaped line feed at or after p: at
// is where it starts and end one past it. When there is none, at is -1
// and cut is where a break could still start (a backslash run reaching
// the end of the window, or a cut \u escape), else len(w). A backslash
// run that fills the window from p may be split anywhere, so cut is then
// len(w).
func keyNextBreak(w []byte, p int) (at, end, cut int) {
	start := p
	for p < len(w) {
		switch w[p] {
		case '\n':
			return p, p + 1, 0
		case '\\':
			kind, e, _ := keyEscape(w, p)
			switch kind {
			case escLF:
				return p, e, 0
			case escNeed:
				if p == start && bsRunEnd(w, p) == len(w) {
					return -1, 0, len(w)
				}
				return -1, 0, p
			}
			p = max(e, p+1)
			continue
		}
		p++
	}
	return -1, 0, len(w)
}

// keyTriggerMarker returns the unified diff marker opening the line of a
// trigger at trigStart, when what precedes the trigger on its line is that
// marker and a frame (keyLinePrefix); 0 otherwise. The window holds
// keyLookbehind bytes before the trigger unless it starts at the start of
// input.
func keyTriggerMarker(w []byte, trigStart int) byte {
	marker, _ := keyTriggerPrefix(w, trigStart)
	return marker
}

// keyTriggerPrefix is keyTriggerMarker that also reports framed: a frame
// follows the marker, so the marker may as well be part of an indentation
// or another prefix ("  ", "+> ").
func keyTriggerPrefix(w []byte, trigStart int) (marker byte, framed bool) {
	ls, ok := keyLineStart(w, trigStart, trigStart < keyLookbehind)
	if !ok {
		return 0, false
	}
	marker, _ = keyLinePrefix(w, ls, trigStart)
	return marker, marker != 0 && trigStart-ls > 1
}

// keyCutResume returns where a scan may resume when the window ends before
// the line end at p is decided because of a backslash run (an escaped line
// break may be any number of backslashes then 'n'): at the start of a
// trailing backslash run that begins after p, or at the end of the window
// when the run fills it from p. It returns 0 when the window ends without
// a trailing run.
func keyCutResume(w []byte, p int) int {
	r := len(w)
	for r > p && w[r-1] == '\\' {
		r--
	}
	switch {
	case r == len(w):
		return 0
	case r > p:
		return r
	}
	return len(w)
}
