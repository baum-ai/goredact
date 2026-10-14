// This file implements generic-secret-assignment, the one deep-profile-
// only heuristic rule this codebase ships as of this writing. It exists
// to give the deep profile a real meaning distinct from balanced (see
// docs/PROFILES.md): balanced's three generic contextual rules in
// generic.go are deliberately tuned to a tight keyword list
// (api_key, secret_key, password, token, ...) to keep their
// false-positive rate low enough for a default profile. This rule
// widens that keyword surface to bare, generic words — "key", "secret",
// "auth", "access", "credential", "creds" — the same broader anchor set
// gitleaks' and betterleaks' own "generic-api-key" rule uses (confirmed
// directly against both projects' source: neither is actually
// keyword-free, despite sometimes being described that way — both
// require one of that same broad keyword set followed eventually by an
// assignment operator).
//
// That broader surface catches real assignments balanced's specific
// keywords structurally cannot, e.g. "AWS Secret Key = ..." or
// "Client Auth Token: ..." contain no literal "secret_key" or
// "auth_token" substring. It also fires on far more ordinary, non-secret
// text (English prose containing "key"/"auth"/"access", source
// identifiers like "keyboard_layout" or "author"), so it is deliberately
// confined to the deep profile and paired with a stricter entropy bar
// (entropy.PresetDeepGenericValue) than any balanced-profile generic
// rule uses.
package validators

import "github.com/baum-ai/goredact/internal/entropy"

// weakAssignmentGapMax bounds how many word/space/dot/hyphen characters
// may separate a weak generic trigger from its assignment operator —
// enough for a short English phrase ("AWS Secret Key") or a
// hyphenated/underscored identifier ("my-secret-value") to intervene,
// matching the distance gitleaks/betterleaks' own generic-api-key rule
// allows between its keyword and operator groups.
const weakAssignmentGapMax = 20

// isWeakGapByte reports whether c may appear in the gap between a weak
// generic trigger (see GenericSecretAssignment) and its assignment
// operator. The alphabet deliberately excludes every assignment
// separator byte (=, :) and quote byte, so skipWeakGap naturally stops
// exactly where parseAssignmentValue's own separator search should
// begin, rather than needing a separate "did we find the operator"
// scan.
func isWeakGapByte(c byte) bool {
	return isAlnum(c) || c == '_' || c == ' ' || c == '\t' || c == '.' || c == '-'
}

// skipWeakGap scans forward from pos for up to weakAssignmentGapMax gap
// bytes (see isWeakGapByte) and reports the offset of the first byte
// that is not one — the position parseAssignmentValue should resume
// from. It never indexes out of range.
func skipWeakGap(window []byte, pos int) int {
	end := pos
	for end < len(window) && end-pos < weakAssignmentGapMax && isWeakGapByte(window[end]) {
		end++
	}
	return end
}

// GenericSecretAssignment confirms an assignment behind one of this
// rule's broad, generic triggers (key, secret, auth, access, credential,
// creds — see internal/rules/specs/generic-deep.json), not itself a
// suffix of a longer identifier. Like the balanced generic rules, it
// first rejects an empty inline assignment (isEmptyInlineAssignment) —
// documentation fragments such as `key=` — since without that
// guard the closing quote is mistaken for an opening value quote and
// unrelated following text is captured as the "secret". It then tries
// the same tight, zero-gap parse the balanced generic rules use
// (parseAssignmentValue, which already understands the "key": ...
// JSON-quoted-key shape); if that fails to find an immediate separator,
// it falls back to a gap-tolerant parse (skipWeakGap) that allows a
// short intervening phrase or hyphenated/underscored identifier before
// the separator. The captured value must pass the same shape checks the
// balanced rules use (isIndirectAssignmentValue, isMachineTokenValue,
// isAlphaSpaceOnly) plus entropy.Secretlike under the stricter
// entropy.PresetDeepGenericValue. Only the value is reported for
// redaction.
func GenericSecretAssignment(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !isTriggerBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	if isEmptyInlineAssignment(window, trigStart, trigEnd) {
		return 0, 0, false
	}
	valStart, valEnd, ok := parseAssignmentValue(window, trigEnd)
	if !ok {
		gapEnd := skipWeakGap(window, trigEnd)
		valStart, valEnd, ok = parseAssignmentValue(window, gapEnd)
		if !ok {
			return 0, 0, false
		}
	}
	value := window[valStart:valEnd]
	if isIndirectAssignmentValue(value) {
		return 0, 0, false
	}
	if !isMachineTokenValue(value) {
		return 0, 0, false
	}
	if isAlphaSpaceOnly(value) {
		return 0, 0, false
	}
	if !entropy.Secretlike(value, entropy.PresetDeepGenericValue) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}
