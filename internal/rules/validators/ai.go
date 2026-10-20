package validators

import "bytes"

// This file holds validators for AI-platform provider secrets from
// Anthropic, OpenAI (project-scoped and legacy), Hugging Face, Groq,
// Cohere, DeepSeek, Deepgram, Cerebras, and Cursor API keys. See
// validators.go for the shared ValidateFunc contract and low-level byte
// helpers (isAlnum, allAlnum, boundaryOK, consumeByte, consumeDigitRun,
// consumeAlnumRun) that these validators build on; isPlaceholder itself
// lives in sourcecontrol.go. devops.go provides consumeAssignedValue,
// reused here for the providers (Cohere, Deepgram) whose key has no
// prefix of its own.
//
// Google's "AIza..." API key shape is intentionally NOT implemented here;
// it belongs to the cloud-provider validator set.

// isAlnumExt reports whether c is an ASCII letter, digit, hyphen, or
// underscore — the character class used by the body of Anthropic and
// OpenAI project-scoped keys, which (unlike the classic GitHub/Slack/
// Hugging Face/Groq token bodies) legitimately contain '-' and '_'.
func isAlnumExt(c byte) bool {
	return isAlnum(c) || c == '-' || c == '_'
}

// consumeExtRun consumes the maximal run of isAlnumExt bytes starting at
// pos and reports the end offset if its length is within [min, max]. Like
// consumeAlnumRun, a maximal run longer than max is rejected outright
// (there is no non-arbitrary shorter cut that would leave a valid
// boundary), and it never indexes out of range.
func consumeExtRun(window []byte, pos, min, max int) (end int, ok bool) {
	start := pos
	for pos < len(window) && isAlnumExt(window[pos]) {
		pos++
	}
	n := pos - start
	if n < min || n > max {
		return pos, false
	}
	return pos, true
}

// precedingBoundaryOK reports whether the byte immediately before pos in
// window, if any, does not continue an alphanumeric run — the mirror image
// of boundaryOK, used to confirm a trigger isn't a suffix of a longer
// identifier or word (e.g. the "sk-ant-" in "risk-ant-eater").
func precedingBoundaryOK(window []byte, pos int) bool {
	if pos <= 0 {
		return true
	}
	return !isAlnum(window[pos-1])
}

// precedingBoundaryExtOK is precedingBoundaryOK extended to also reject a
// preceding '-' or '_', for tokens whose trigger is short and generic
// enough (bare "sk-") that a preceding hyphen/underscore still plausibly
// means "this is part of a larger token", not a real boundary. A '-' that
// opens a line is a unified-diff removal marker, not part of a token, so a
// token starting a removed line in a patch still has its boundary; rules
// using this declare a two-byte lookbehind so the byte before that '-' is
// in the window.
func precedingBoundaryExtOK(window []byte, pos int) bool {
	if pos <= 0 {
		return true
	}
	if isDiffRemovalMarker(window, pos-1) {
		return true
	}
	return !isAlnumExt(window[pos-1])
}

// hasRepeatRun reports whether b contains a run of n or more consecutive
// identical bytes. Real high-entropy secrets essentially never contain
// such runs; placeholder/redacted fixtures ("xxxxxxxxxxxx...") commonly
// do, so this is used alongside isPlaceholder to catch placeholders that are
// only partially repeated (e.g. a real-looking prefix/suffix wrapped
// around a long run of 'x').
func hasRepeatRun(b []byte, n int) bool {
	if n <= 0 || len(b) < n {
		return false
	}
	run := 1
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1] {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// AnthropicAPIKey confirms the Anthropic API key shape: trigger "sk-ant-"
// followed by 80-130 bytes of [A-Za-z0-9_-] (this covers both the common
// "api03-"/"admin01-"-style sub-segment plus the ~80-120 character body,
// since that sub-segment's own alphabet is a subset of the body's, and the
// literal "sk-ant-" prefix's total post-prefix length is what's actually
// bounded). Real Anthropic keys are never shorter than ~100 characters
// after the prefix; the 80 floor rejects the short fabricated
// "sk-ant-api03-<32-40 chars>" keys that dominate documentation and test
// fixtures. It also rejects placeholder bodies (all one character, or any
// long repeated run) and requires a non-alphanumeric byte (or end of
// window) on both sides.
func AnthropicAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	bodyEnd, ok2 := consumeExtRun(window, trigEnd, 80, 130)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if isPlaceholder(body) || hasRepeatRun(body, 5) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// openAIInfix is the fixed "T3BlbkFJ" substring (base64 of "OpenAI"
// shifted by the key-format framing OpenAI uses) that appears in both
// legacy and project-scoped OpenAI keys.
var openAIInfix = []byte("T3BlbkFJ")

// openAIProjectExclusions lists the byte sequences that, if found
// immediately after a bare "sk-" trigger, mean the match belongs to a
// different, more specific rule (openai-project-key or anthropic-api-key)
// and must not be confirmed by openai-legacy-key.
var openAIProjectExclusions = [][]byte{
	[]byte("ant-"),
	[]byte("proj-"),
	[]byte("svcacct-"),
	[]byte("admin-"),
}

// OpenAIProjectKey confirms the OpenAI project-scoped key shapes: trigger
// "sk-proj-", "sk-svcacct-", or "sk-admin-" followed by [A-Za-z0-9_-].
// The body must be at least 40 bytes and at most 200. If it contains the
// "T3BlbkFJ" infix anywhere, it is confirmed regardless of length beyond
// that floor/ceiling; without the infix, it must additionally be at least
// 48 bytes and not look like a placeholder (all one character, or a long
// repeated run).
func OpenAIProjectKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	bodyEnd, ok2 := consumeExtRun(window, trigEnd, 40, 200)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if bytes.Contains(body, openAIInfix) {
		return trigStart, bodyEnd, true
	}
	if len(body) < 48 {
		return 0, 0, false
	}
	if isPlaceholder(body) || hasRepeatRun(body, 5) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// OpenAILegacyKey confirms the classic OpenAI secret key shape: trigger
// "sk-" followed by exactly 20 [A-Za-z0-9], the literal infix "T3BlbkFJ",
// then exactly 20 more [A-Za-z0-9] (48 bytes total), with a
// non-alphanumeric byte (or end of window) on the right and a byte that is
// not [A-Za-z0-9_-] (or start of window) on the left.
//
// Because "sk-" is a substring of "sk-ant-", "sk-proj-", "sk-svcacct-",
// and "sk-admin-", this validator explicitly refuses to confirm when the
// bytes immediately after the trigger begin with any of those other
// rules' distinguishing suffixes — those occurrences belong to
// anthropic-api-key or openai-project-key instead.
func OpenAILegacyKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryExtOK(window, trigStart) {
		return 0, 0, false
	}

	rest := window[trigEnd:]
	for _, excl := range openAIProjectExclusions {
		if bytes.HasPrefix(rest, excl) {
			return 0, 0, false
		}
	}

	const (
		segLen   = 20
		infixLen = 8
		total    = segLen + infixLen + segLen
	)
	bodyEnd := trigEnd + total
	if bodyEnd > len(window) {
		return 0, 0, false
	}
	first := window[trigEnd : trigEnd+segLen]
	infix := window[trigEnd+segLen : trigEnd+segLen+infixLen]
	last := window[trigEnd+segLen+infixLen : bodyEnd]

	if !allAlnum(first) || !allAlnum(last) {
		return 0, 0, false
	}
	if !bytes.Equal(infix, openAIInfix) {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	if isPlaceholder(first) || isPlaceholder(last) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// HuggingFaceToken confirms the Hugging Face token shape: trigger "hf_"
// followed by exactly 34 [A-Za-z0-9] and a non-alphanumeric byte (or end
// of window). Identifiers like "hf_hub_download" are naturally excluded:
// the underscore after "hub" ends the alphanumeric run well short of 34.
func HuggingFaceToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	const tokenLen = 34
	bodyEnd, ok2 := consumeAlnumRun(window, trigEnd, tokenLen, tokenLen)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if isPlaceholder(body) || hasRepeatRun(body, 8) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// GroqAPIKey confirms the Groq API key shape: trigger "gsk_" followed by
// exactly 52 [A-Za-z0-9] and a non-alphanumeric byte (or end of window).
func GroqAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	const tokenLen = 52
	bodyEnd, ok2 := consumeAlnumRun(window, trigEnd, tokenLen, tokenLen)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if isPlaceholder(body) || hasRepeatRun(body, 8) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// isLowerAlnum reports whether c is an ASCII lowercase letter or digit —
// the alphabet DeepSeek and Deepgram API keys use for their bodies (no
// uppercase, unlike every other provider in this family).
func isLowerAlnum(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z'
}

// CohereAPIKey confirms the shape of a value assigned to CO_API_KEY or
// COHERE_API_KEY (matched case-insensitively; CO_API_KEY is the keyword
// gitleaks' own "cohere-api-token" rule keys on): 40 characters of
// mixed-case alphanumeric. Cohere's key has no prefix of its own — a bare
// 40-character token, the same shape as many unrelated opaque or hex
// identifiers — so this rule is keyed on the documented variable name
// instead, the same design AWSSecretAccessKey (cloud.go) already uses for
// AWS's equally prefix-less secret access key.
//
// https://docs.cohere.com
func CohereAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	start, end, ok = consumeAssignedValue(window, trigEnd, 40, isAlnum)
	if !ok {
		return 0, 0, false
	}
	if hasRepeatRun(window[start:end], 5) {
		return 0, 0, false
	}
	return start, end, true
}

// DeepSeekAPIKey confirms the DeepSeek API key shape: trigger "sk-"
// followed by exactly 32 lowercase alphanumeric characters (35 bytes
// total including the prefix). This shares its trigger literal with
// openai-legacy-key but the two never both confirm the same occurrence:
// OpenAI's legacy key is 51 bytes total with a mixed-case body containing
// the mandatory uppercase "T3BlbkFJ" infix, which a lowercase-only,
// exactly-32-byte DeepSeek body can never satisfy, and vice versa.
//
// https://api-docs.deepseek.com
func DeepSeekAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryExtOK(window, trigStart) {
		return 0, 0, false
	}
	const tokenLen = 32
	bodyEnd, ok2 := consumeRun(window, trigEnd, tokenLen, tokenLen, isLowerAlnum)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	// DeepSeek's body alphabet is lowercase-only (36 symbols, versus the
	// 62-64 symbols every other rule in this file draws its body from),
	// so a coincidental run of 5 identical characters in a genuinely
	// random 32-byte key is measurably more likely here than it is for
	// e.g. AnthropicAPIKey at the same threshold. Requiring 6 restores a
	// safety margin comparable to (in fact tighter than) that baseline.
	if isPlaceholder(body) || hasRepeatRun(body, 6) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// DeepgramAPIKey confirms the shape of a value assigned to
// DEEPGRAM_API_KEY (matched case-insensitively): 40 characters of
// lowercase alphanumeric. Like Cohere's, Deepgram's key has no prefix of
// its own — TruffleHog's own detector keys on the literal word "deepgram"
// appearing nearby rather than on any byte prefix — so this rule is
// keyed on the documented environment-variable name instead.
//
// https://developers.deepgram.com
func DeepgramAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	start, end, ok = consumeAssignedValue(window, trigEnd, 40, isLowerAlnum)
	if !ok {
		return 0, 0, false
	}
	// See the matching comment on DeepSeekAPIKey: Deepgram's body is the
	// same 36-symbol lowercase-only alphabet, so this uses the same
	// widened threshold for the same reason.
	if hasRepeatRun(window[start:end], 6) {
		return 0, 0, false
	}
	return start, end, true
}

// CerebrasAPIKey confirms the Cerebras API key shape: trigger "csk-"
// followed by 32-64 alphanumeric characters.
//
// Cerebras does not publish a format spec on any source reachable during
// development: no gitleaks or TruffleHog detector exists for it, and
// inference-docs.cerebras.ai itself was unreachable. The "csk-" prefix
// and a 32-character example body come from several independent
// third-party integration guides that converge on the same placeholder
// shape ("csk-1234567890abcdef1234567890abcdef"), not from Cerebras's own
// docs, which show only a generic "your-api-key-here" placeholder. This
// should be re-verified against
// inference-docs.cerebras.ai/api-reference/authentication when reachable.
func CerebrasAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	bodyEnd, ok2 := consumeAlnumRun(window, trigEnd, 32, 64)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if isPlaceholder(body) || hasRepeatRun(body, 5) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// CursorAPIKey confirms the Cursor API key shape: trigger "crsr_"
// followed by 20 or more characters of [A-Za-z0-9_-]. Cursor's own
// sensitive-prompt-guard hook script (github.com/cursor/cookbook) uses
// the regex crsr_[A-Za-z0-9_-]{20,} — an open floor with no upper bound
// at all, unlike every other rule in this file — so this validator
// imposes no separate maximum of its own: it consumes the maximal
// [A-Za-z0-9_-] run and only requires the 20-byte floor, relying on the
// rule's own maxLookahead (deliberately generous, in ai.json) as the
// practical ceiling rather than an arbitrary internal cap that a longer
// real key could silently fall outside of.
func CursorAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	pos := trigEnd
	for pos < len(window) && isAlnumExt(window[pos]) {
		pos++
	}
	if pos-trigEnd < 20 {
		return 0, 0, false
	}
	body := window[trigEnd:pos]
	if isPlaceholder(body) || hasRepeatRun(body, 5) {
		return 0, 0, false
	}
	return trigStart, pos, true
}
