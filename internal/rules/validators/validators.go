// Package validators holds the ValidateFunc implementations referenced by
// the generated built-in rule tables (internal/rules/zz_generated_rules.go).
//
// Every function here has the signature
//
//	func(window []byte, trigStart, trigEnd int) (start, end int, ok bool)
//
// as required by rules.ValidateFunc: window is the bounded slice of bytes
// around a trigger occurrence (trigger occupies window[trigStart:trigEnd]),
// and the function reports the half-open span within window to redact.
// Implementations here are pure functions of window: no I/O, no logging,
// and no retention of window past the call. They must never panic or index
// out of range, regardless of how short window is relative to the trigger
// or the rule's configured lookahead — callers may hand them a window
// truncated at a chunk or input boundary.
//
// This package currently holds two seed validators (GitHubPAT,
// SlackBotToken) that prove the spec-to-generated-code pipeline end to end.
// Additional files in this package provide the full validator catalog.
package validators

// isDigit reports whether c is an ASCII decimal digit.
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isDiffMarker reports whether c is one of the bytes that open a line of a
// unified diff hunk: '+' (added), '-' (removed) or ' ' (context).
func isDiffMarker(c byte) bool {
	return c == '+' || c == '-' || c == ' '
}

// startsLine reports whether pos is the first byte of a line: the start of
// window or the byte after a '\n'. The start of window is only the start
// of a line when it is the start of input, so a rule using this to look at
// the byte before its trigger declares a lookbehind that covers that byte:
// the engine hands a validator its full lookbehind except at the start of
// input.
func startsLine(window []byte, pos int) bool {
	return pos == 0 || pos > 0 && pos <= len(window) && window[pos-1] == '\n'
}

// isDiffRemovalMarker reports whether window[pos] is '-' opening a line,
// i.e. the marker of a removed line in a unified diff, so that a check
// rejecting a '-' before a trigger ("x-sk-...", "---password") can still
// accept a token or flag that starts a removed line. Callers need a
// lookbehind of two bytes before the trigger (see startsLine).
func isDiffRemovalMarker(window []byte, pos int) bool {
	return pos >= 0 && pos < len(window) && window[pos] == '-' && startsLine(window, pos)
}

// isAlnum reports whether c is an ASCII letter or digit.
func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || isDigit(c)
}

// allAlnum reports whether every byte in b is an ASCII letter or digit.
// An empty slice is not all-alnum (there is nothing to confirm).
func allAlnum(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !isAlnum(c) {
			return false
		}
	}
	return true
}

// allSame reports whether every byte in b is identical to the first. A
// slice of length 0 or 1 is trivially "all same" by this definition, so
// callers only use it once they already know the length is meaningful.
func allSame(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, c := range b[1:] {
		if c != b[0] {
			return false
		}
	}
	return true
}

// boundaryOK reports whether the byte at window[pos], if any, does not
// continue an alphanumeric run — i.e. pos is at the end of window (end of
// window/input) or the byte there is not alphanumeric. This is the "end of
// word" check shared by the seed validators: a token immediately followed
// by more alphanumeric bytes is not this token, it's a prefix of a longer
// one.
func boundaryOK(window []byte, pos int) bool {
	if pos >= len(window) {
		return true
	}
	return !isAlnum(window[pos])
}

// GitHubPAT confirms the classic GitHub personal access token shape:
// trigger "ghp_" followed by exactly 36 ASCII alphanumeric characters and a
// non-alphanumeric byte (or end of window). It rejects placeholder bodies
// (isPlaceholder): repeated characters ("XXXX...X"), ascending
// alphabet runs ("ABCDEFGH..."), and keyword stand-ins, which real tokens
// never are but test fixtures and documentation examples routinely use.
func GitHubPAT(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return fixedAlnumToken(window, trigStart, trigEnd, 36)
}

// SlackBotToken confirms the Slack bot token shape: trigger "xoxb-"
// preceded by a non-identifier byte (or start of window), followed by
// <10-13 digits>-<10-13 digits>-<24-34 alphanumeric characters> and a
// non-alphanumeric byte (or end of window). Every segment is checked
// against isPlaceholder, so fixture shapes like
// "xoxb-1234567890-..." are rejected along with all-identical segments.
func SlackBotToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if precededByIdentByte(window, trigStart) {
		return 0, 0, false
	}
	pos := trigEnd

	seg1Start := pos
	pos, ok = consumeDigitRun(window, pos, 10, 13)
	if !ok || isPlaceholder(window[seg1Start:pos]) {
		return 0, 0, false
	}
	pos, ok = consumeByte(window, pos, '-')
	if !ok {
		return 0, 0, false
	}
	seg2Start := pos
	pos, ok = consumeDigitRun(window, pos, 10, 13)
	if !ok || isPlaceholder(window[seg2Start:pos]) {
		return 0, 0, false
	}
	pos, ok = consumeByte(window, pos, '-')
	if !ok {
		return 0, 0, false
	}

	segStart := pos
	segEnd, ok := consumeAlnumRun(window, pos, 24, 34)
	if !ok {
		return 0, 0, false
	}
	if !boundaryOK(window, segEnd) {
		return 0, 0, false
	}
	if isPlaceholder(window[segStart:segEnd]) {
		return 0, 0, false
	}
	return trigStart, segEnd, true
}

// consumeByte reports whether window[pos] == c, returning pos+1 on success.
// It never indexes out of range.
func consumeByte(window []byte, pos int, c byte) (next int, ok bool) {
	if pos >= len(window) || window[pos] != c {
		return pos, false
	}
	return pos + 1, true
}

// consumeDigitRun consumes the maximal run of ASCII digits starting at pos
// and reports whether its length is within [min, max]. It never indexes
// out of range.
func consumeDigitRun(window []byte, pos, min, max int) (next int, ok bool) {
	start := pos
	for pos < len(window) && isDigit(window[pos]) {
		pos++
	}
	n := pos - start
	if n < min || n > max {
		return pos, false
	}
	return pos, true
}

// consumeAlnumRun consumes the maximal run of ASCII alphanumeric bytes
// starting at pos and reports the end offset if its length is within
// [min, max]. It never indexes out of range.
func consumeAlnumRun(window []byte, pos, min, max int) (end int, ok bool) {
	start := pos
	for pos < len(window) && isAlnum(window[pos]) {
		pos++
	}
	n := pos - start
	if n < min || n > max {
		return pos, false
	}
	return pos, true
}
