// This file implements the contextual detectors: credentials that
// are identified by WHERE they appear (an HTTP Authorization header, a
// Cookie/Set-Cookie header, the userinfo component of a URL, a CLI
// password/token flag) rather than by a provider-specific token shape
// (validators.go et al.) or a bare key=value assignment (generic.go);
// assignments are deliberately not duplicated here.
//
// All four validators redact ONLY the credential value: header names, URL
// scheme/host/path structure, cookie names, and flag names are always
// preserved byte for byte.
//
// # Escaped/embedded header lines
//
// Log pipelines frequently embed raw header lines inside JSON strings
// (`{"line":"\"authorization: bearer abc...\""}`). The case-folded
// triggers still hit inside such strings, so every value alphabet here
// deliberately excludes '"' and '\\': a value terminated by an escaped
// closing quote (`...abc\"`) simply ends at the backslash instead of
// swallowing the JSON framing.
//
// # Cookie multi-pair design tension
//
// A ValidateFunc returns exactly one span, but one Cookie header can carry
// several credential-bearing pairs. Returning one wide span from the first
// to the last qualifying value would over-redact the benign pairs between
// them, and the `cookie:` trigger fires only once per header no matter how
// many pairs follow. The resolution used by cookie-session-token: the
// header trigger (`cookie:` / `set-cookie:`) confirms the FIRST qualifying
// pair's value, and the rule additionally registers the qualifying pair
// names themselves (`session=`, `sid=`, `token=`, `jwt=`, `auth=`) as
// triggers, so each qualifying pair produces its own trigger occurrence
// and therefore its own span. The Aho-Corasick matcher reports every
// occurrence of every literal, so a header with three token-bearing pairs
// gets three pair-trigger hits even though `cookie:` hits once. To keep
// those weak pair literals from firing on arbitrary key=value text (which
// the generic assignment rules already cover), the pair-trigger
// path demands cookie context: the literal "ookie" (Cookie:/Set-Cookie:,
// however cased) somewhere in the lookbehind, or an immediately preceding
// `;`-separated pair boundary. When that context is absent the pair path
// reports no match.
package validators

import "github.com/baum-ai/goredact/internal/entropy"

// ---------------------------------------------------------------------------
// Shared byte-class helpers
// ---------------------------------------------------------------------------

// isASCIILetter reports whether c is an ASCII letter.
func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// lineEnd returns the offset of the first '\n' or '\r' at or after pos, or
// len(window) if the line runs to the end of the window.
func lineEnd(window []byte, pos int) int {
	for pos < len(window) && window[pos] != '\n' && window[pos] != '\r' {
		pos++
	}
	return pos
}

// indexLiteral returns the offset of the first case-SENSITIVE occurrence
// of lit in b, or -1.
func indexLiteral(b []byte, lit string) int {
	n := len(lit)
	if n == 0 || n > len(b) {
		return -1
	}
	for i := 0; i+n <= len(b); i++ {
		j := 0
		for j < n && b[i+j] == lit[j] {
			j++
		}
		if j == n {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// authorization-bearer
// ---------------------------------------------------------------------------

// isAuthTokenChar is the RFC 6750 token68 alphabet (plus '_' and '-' for
// base64url, so JWTs are captured whole rather than truncated at their
// first url-safe byte, which would leak the remainder). It excludes
// quotes, backslash, and whitespace, so values embedded in JSON-escaped
// strings terminate at the escape.
func isAuthTokenChar(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '~' || c == '+' ||
		c == '/' || c == '=' || c == '-'
}

// isBase64Char is the standard (non-url-safe) base64 alphabet with
// padding, the alphabet of a Basic authorization value.
func isBase64Char(c byte) bool {
	return isAlnum(c) || c == '+' || c == '/' || c == '='
}

// authBearerMinLen is the minimum bearer/token value length. Real bearer
// tokens are essentially never shorter; short values in this position are
// doc examples ("Bearer abc").
const authBearerMinLen = 16

// authBasicMinLen is the minimum Basic base64 blob length. base64("a:b")
// is 4 bytes; 12 corresponds to ~9 bytes of user:pass, about the shortest
// plausible real credential pair.
const authBasicMinLen = 12

// authSignatureMinLen is the minimum length of a Signature= parameter
// value (AWS SigV4 signatures are 64 hex characters).
const authSignatureMinLen = 16

// AuthorizationHeader confirms a credential in an Authorization: or
// Proxy-Authorization: header (the triggers include the colon and are
// case-folded). Per-scheme behavior, kept deliberately small:
//
//   - Bearer / Token (case-insensitive): the value is the following run of
//     token68 bytes (see isAuthTokenChar). It must be at least
//     authBearerMinLen bytes and not an isPlaceholder value; pure
//     template refs ("${...}") and angle-bracket placeholders ("<token>")
//     never even parse, since '$', '{', '<' are outside the value
//     alphabet, leaving an empty (rejected) value.
//   - Basic: the value is the following run of base64 bytes, at least
//     authBasicMinLen long. No placeholder/entropy check: a well-formed
//     base64 credential pair in this position is always sensitive.
//   - Any other scheme (Digest, AWS4-HMAC-SHA256, ...): conservative. If
//     the rest of the line contains a case-sensitive "Signature=" (AWS
//     SigV4), only that parameter's value token is redacted. Otherwise,
//     if the rest of the line mentions "password" (case-insensitive), the
//     whole parameter blob up to end of line is redacted (over-redaction
//     of an explicitly password-bearing header is the safe direction).
//     Otherwise there is no match — a plain Digest challenge/response
//     never fires.
//
// Only the credential value (or parameter blob) is redacted, never the
// header name or scheme word.
func AuthorizationHeader(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !isTriggerBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	pos := skipHSpace(window, trigEnd)
	schemeStart := pos
	for pos < len(window) && (isAlnum(window[pos]) || window[pos] == '-') {
		pos++
	}
	scheme := window[schemeStart:pos]
	if len(scheme) == 0 {
		return 0, 0, false
	}

	switch {
	case asciiEqualFold(scheme, "bearer") || asciiEqualFold(scheme, "token"):
		valStart := skipHSpace(window, pos)
		if valStart == pos { // require whitespace between scheme and value
			return 0, 0, false
		}
		valEnd := valStart
		for valEnd < len(window) && isAuthTokenChar(window[valEnd]) {
			valEnd++
		}
		if valEnd-valStart < authBearerMinLen {
			return 0, 0, false
		}
		if isPlaceholder(window[valStart:valEnd]) {
			return 0, 0, false
		}
		if isIndirectAssignmentValue(window[valStart:valEnd]) {
			return 0, 0, false
		}
		return valStart, valEnd, true

	case asciiEqualFold(scheme, "basic"):
		valStart := skipHSpace(window, pos)
		if valStart == pos {
			return 0, 0, false
		}
		valEnd := valStart
		for valEnd < len(window) && isBase64Char(window[valEnd]) {
			valEnd++
		}
		if valEnd-valStart < authBasicMinLen {
			return 0, 0, false
		}
		return valStart, valEnd, true

	default:
		eol := lineEnd(window, pos)
		rest := window[pos:eol]
		if i := indexLiteral(rest, "Signature="); i >= 0 {
			valStart := pos + i + len("Signature=")
			valEnd := valStart
			for valEnd < eol && isAuthTokenChar(window[valEnd]) {
				valEnd++
			}
			if valEnd-valStart < authSignatureMinLen {
				return 0, 0, false
			}
			return valStart, valEnd, true
		}
		if containsFold(rest, "password") {
			blobStart := skipHSpace(window, pos)
			blobEnd := eol
			for blobEnd > blobStart && isSpaceByte(window[blobEnd-1]) {
				blobEnd--
			}
			if blobEnd <= blobStart {
				return 0, 0, false
			}
			return blobStart, blobEnd, true
		}
		return 0, 0, false
	}
}

// ---------------------------------------------------------------------------
// cookie-session-token
// ---------------------------------------------------------------------------

// cookieNameKeywords are the (lowercase) substrings that mark a cookie
// name as credential-bearing. CSRF/XSRF tokens are deliberately excluded
// (see cookieNameExclusions): they are lower-value, short-lived
// request-forgery nonces, not authentication material.
var cookieNameKeywords = []string{
	"session", "sessid", "sid", "token", "auth", "jwt", "bearer", "secret", "key",
}

// cookieNameExclusions veto a name even when a keyword matches (e.g.
// "csrftoken" contains "token" but is a CSRF nonce).
var cookieNameExclusions = []string{"csrf", "xsrf"}

// cookieValueMinLen is the minimum qualifying cookie value length; real
// session identifiers and tokens are essentially never shorter.
const cookieValueMinLen = 16

// isCookieNameChar restricts cookie names to the shapes seen in practice:
// alphanumerics plus '_', '-', '.'. Anything else (including '&', so URL
// query pairs never read as cookie names) ends the name.
func isCookieNameChar(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-' || c == '.'
}

// isCookieValueChar is RFC 6265's cookie-octet, minus nothing: printable
// ASCII excluding whitespace, '"', ',', ';', and '\\'. The exclusions make
// values embedded in JSON-escaped strings self-terminating.
func isCookieValueChar(c byte) bool {
	if c < 0x21 || c > 0x7e {
		return false
	}
	return c != '"' && c != ',' && c != ';' && c != '\\'
}

// cookieNameQualifies reports whether name (a raw cookie name) contains a
// credential keyword and none of the exclusions.
func cookieNameQualifies(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, kw := range cookieNameExclusions {
		if containsFold(name, kw) {
			return false
		}
	}
	for _, kw := range cookieNameKeywords {
		if containsFold(name, kw) {
			return true
		}
	}
	return false
}

// cookieValueQualifies reports whether val is long and random-looking
// enough to be a real session/token value (entropy.PresetLooseToken, the
// same preset the generic bearer-like rule uses for weak triggers).
func cookieValueQualifies(val []byte) bool {
	return len(val) >= cookieValueMinLen &&
		!isIndirectAssignmentValue(val) &&
		entropy.Secretlike(val, entropy.PresetLooseToken)
}

// CookieSessionToken confirms a credential-bearing cookie pair. The rule
// registers two kinds of triggers and this validator dispatches on which
// one fired (by inspecting window[trigStart:trigEnd]):
//
//   - Header triggers ("cookie:", "set-cookie:", trailing ':'): the pairs
//     after the colon are scanned in order and the FIRST pair whose name
//     qualifies (cookieNameQualifies) and whose value qualifies
//     (cookieValueQualifies) has its value confirmed. Later qualifying
//     pairs in the same header are caught by the pair triggers below —
//     see the file comment for why one validator call cannot return them
//     all. Note the pair triggers fire only when a keyword directly
//     abuts the '=' ("...token=", "...sid=", "sessionid="), so a
//     non-first pair whose name buries its keyword elsewhere
//     ("session_2=") is a known miss; the trigger list carries the
//     common real-world names rather than every conceivable shape.
//   - Pair triggers ("session=", "sessionid=", "sid=", "token=",
//     "jwt=", "auth=", trailing '='): the full cookie name is extended
//     backwards over
//     name bytes (so "auth_token=" and "connect.sid=" are judged by
//     their whole name, and "csrftoken=" is vetoed by its "csrf"
//     prefix), cookie context is required (see cookiePairContextOK), and
//     the following value must qualify. Without cookie context the pair
//     path never matches: bare key=value assignments belong to the
//     generic rules, not this one.
//
// Only the cookie VALUE is redacted, never the name or header structure.
func CookieSessionToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if trigEnd <= trigStart || trigEnd > len(window) {
		return 0, 0, false
	}
	if window[trigEnd-1] == ':' {
		if !isTriggerBoundaryOK(window, trigStart) {
			return 0, 0, false
		}
		return cookieHeaderScan(window, trigEnd)
	}
	return cookiePairCheck(window, trigStart, trigEnd)
}

// cookieHeaderScan walks "name=value; name=value; ..." pairs starting at
// pos (just past the header colon) and returns the value span of the
// first qualifying pair. The scan is line- and string-bounded: it stops
// at end of line and at '"'/'\\' (the framing of an embedded/escaped
// header), and it never indexes out of range.
func cookieHeaderScan(window []byte, pos int) (start, end int, ok bool) {
	for pos < len(window) {
		pos = skipHSpace(window, pos)
		nameStart := pos
		for pos < len(window) && isCookieNameChar(window[pos]) {
			pos++
		}
		if pos >= len(window) {
			return 0, 0, false
		}
		if pos == nameStart || window[pos] != '=' {
			// Not a pair here (e.g. a valueless attribute like HttpOnly,
			// or free text): resync at the next ';' on this line.
			next, resync := cookieResync(window, pos)
			if !resync {
				return 0, 0, false
			}
			pos = next
			continue
		}
		name := window[nameStart:pos]
		valStart := pos + 1
		valEnd := valStart
		for valEnd < len(window) && isCookieValueChar(window[valEnd]) {
			valEnd++
		}
		if cookieNameQualifies(name) && cookieValueQualifies(window[valStart:valEnd]) {
			return valStart, valEnd, true
		}
		next, resync := cookieResync(window, valEnd)
		if !resync {
			return 0, 0, false
		}
		pos = next
	}
	return 0, 0, false
}

// cookieResync advances from pos to just past the next ';', skipping any
// non-pair bytes (attribute values with spaces or commas, free text). It
// reports failure at end of line, end of window, or a '"'/'\\' string
// terminator, which ends the whole header scan.
func cookieResync(window []byte, pos int) (next int, ok bool) {
	for pos < len(window) {
		switch window[pos] {
		case ';':
			return pos + 1, true
		case '\n', '\r', '"', '\\':
			return 0, false
		}
		pos++
	}
	return 0, false
}

// cookiePairCheck handles a pair trigger occurrence: window[trigStart:
// trigEnd] is "<keyword>=". See CookieSessionToken for the contract.
func cookiePairCheck(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	// Extend the name backwards so the whole cookie name is judged, not
	// just the keyword the trigger matched.
	nameStart := trigStart
	for nameStart > 0 && isCookieNameChar(window[nameStart-1]) {
		nameStart--
	}
	name := window[nameStart : trigEnd-1] // excludes the '='
	if !cookieNameQualifies(name) {
		return 0, 0, false
	}
	if !cookiePairContextOK(window, nameStart) {
		return 0, 0, false
	}
	valStart := trigEnd
	valEnd := valStart
	for valEnd < len(window) && isCookieValueChar(window[valEnd]) {
		valEnd++
	}
	if !cookieValueQualifies(window[valStart:valEnd]) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

// cookiePairContextOK reports whether the bytes before nameStart look like
// the inside of a cookie header: either the literal "ookie" (the tail of
// Cookie:/Set-Cookie:, any case, possibly JSON-quoted) appears in the
// available lookbehind, or the name is immediately preceded by a ';' pair
// separator (with at most one space). This is the guard that keeps the
// weak pair triggers from firing on arbitrary assignments and URL query
// strings — those are generic-rule territory.
func cookiePairContextOK(window []byte, nameStart int) bool {
	if nameStart >= 1 && window[nameStart-1] == ';' {
		return true
	}
	if nameStart >= 2 && window[nameStart-1] == ' ' && window[nameStart-2] == ';' {
		return true
	}
	return containsFold(window[:nameStart], "ookie")
}

// ---------------------------------------------------------------------------
// url-credentials
// ---------------------------------------------------------------------------

// urlPasswordPlaceholders are whole-value (case-insensitive) placeholder
// passwords rejected on top of isPlaceholder. isPlaceholder
// already covers several of these ("password" by substring, "xxx"/"***"
// as repeated single bytes, "secret" as a whole value); the short forms
// "pass" and "pwd" are the additions that matter, but the full list is
// kept verbatim so this rule's placeholder policy is readable in one
// place.
var urlPasswordPlaceholders = []string{"pass", "password", "pwd", "token", "xxx", "***"}

// urlPasswordMinLen is the minimum password length: 3 keeps short-but-real
// database passwords in fixtures and dev DSNs while dropping one- and
// two-byte junk.
const urlPasswordMinLen = 3

// isSchemeChar is the RFC 3986 scheme alphabet (letters, digits, '+',
// '.', '-'). Uppercase letters are accepted too — schemes are
// case-insensitive in practice ("HTTP://") even though canonical form is
// lowercase.
func isSchemeChar(c byte) bool {
	return isAlnum(c) || c == '+' || c == '.' || c == '-'
}

// isUserinfoTerminator reports bytes that cannot appear before the '@' of
// a userinfo component: hitting one of these while scanning for '@' means
// the URL has no userinfo at all. '/' also catches the '?'/'#'-less
// common case of "scheme://host/path", and quotes/backslash/angle
// brackets terminate URLs embedded in strings and prose. Anything at or
// below space (and DEL/non-ASCII) also terminates.
func isUserinfoTerminator(c byte) bool {
	if c <= ' ' || c >= 0x7f {
		return true
	}
	switch c {
	case '/', '?', '#', '"', '\'', '`', '\\', '<', '>':
		return true
	}
	return false
}

// URLCredentials confirms a password inside a URL's userinfo component
// ("scheme://user:password@host/..."). The trigger is the literal "://".
//
// The scheme before "://" must look like a scheme: a run of scheme bytes
// at least 2 long whose first byte is a letter — this rejects prose like
// `the "://" separator`. After "://", the userinfo is scanned for '@'; if
// a terminator byte appears first there is no userinfo and no match.
//
// Only the PASSWORD is redacted: the bytes after the first ':' of the
// userinfo up to (excluding) the '@'. A username-only URL
// ("https://user@host") is deliberately not a match: a bare username is
// an identifier, not a secret, and redacting it would destroy far more
// benign URLs than it would protect (gitleaks flags whole user:pass
// URLs; this rule intentionally preserves everything but the password so
// the URL stays byte-for-byte usable around the marker). An empty
// password ("redis://:@host") is likewise no match. Percent-encoded
// bytes pass through unexamined — they are just bytes to this scan.
//
// Placeholders and plain word-like values are rejected via entropy helpers
// plus the tiny urlPasswordPlaceholders whole-value list, so documentation
// and development-default shapes like "user:pass", "user:content", and
// "foo:xxx" never fire. Random-looking passwords remain detectable.
func URLCredentials(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	// Scheme: scan backwards from the trigger.
	schemeStart := trigStart
	for schemeStart > 0 && isSchemeChar(window[schemeStart-1]) {
		schemeStart--
	}
	if trigStart-schemeStart < 2 || !isASCIILetter(window[schemeStart]) {
		return 0, 0, false
	}

	// Userinfo: find '@' before any terminator; remember the first ':'.
	at := -1
	colon := -1
	for i := trigEnd; i < len(window); i++ {
		c := window[i]
		if c == '@' {
			at = i
			break
		}
		if c == ':' {
			if colon < 0 {
				colon = i
			}
			continue
		}
		if isUserinfoTerminator(c) {
			return 0, 0, false
		}
	}
	if at < 0 || colon < 0 {
		return 0, 0, false
	}

	pwStart, pwEnd := colon+1, at
	if pwEnd-pwStart < urlPasswordMinLen {
		return 0, 0, false
	}
	pw := window[pwStart:pwEnd]
	if isPlaceholder(pw) {
		return 0, 0, false
	}
	if entropy.Classify(pw) == entropy.ClassWordlike {
		return 0, 0, false
	}
	if !validPercentEncoding(pw) {
		return 0, 0, false
	}
	for _, p := range urlPasswordPlaceholders {
		if asciiEqualFold(pw, p) {
			return 0, 0, false
		}
	}
	return pwStart, pwEnd, true
}

func validPercentEncoding(value []byte) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if i+2 >= len(value) || !isHexByte(value[i+1]) || !isHexByte(value[i+2]) {
			return false
		}
		i += 2
	}
	return true
}

// ---------------------------------------------------------------------------
// command-line-password-flag
// ---------------------------------------------------------------------------

// cliPasswordMinLen and cliTokenMinLen are the per-flavor minimum value
// lengths: passwords run short (6 keeps realistic DB passwords), while
// token/key/secret material is essentially never under 12 bytes.
const (
	cliPasswordMinLen = 6
	cliTokenMinLen    = 12
)

// isBareCLIValueChar is the alphabet of an unquoted CLI argument value:
// printable ASCII excluding whitespace, quotes, and backslash (the latter
// so values inside JSON-escaped command lines self-terminate).
func isBareCLIValueChar(c byte) bool {
	return isPrintableByte(c) && !isQuoteByte(c) && c != '\\'
}

// CommandLinePasswordFlag confirms a secret passed to a CLI flag
// (--password, --passwd, --token, --api-key, --secret; case-folded). The
// short "-p " form is deliberately not a trigger — it is hopelessly
// false-positive-prone (-p is "port" as often as "password").
//
// The byte immediately after the trigger must be '=' or horizontal
// whitespace: anything else means the flag name continues
// ("--password-file", "--token-url") and there is no match. The byte
// before the trigger must not be '-' or alphanumeric ("---password",
// "x--token" are not flags). A bare (unquoted) value must not start with
// '-': that is the next flag, not a value ("--password --prompt").
//
// The value is either quoted (single/double/backtick, tolerating a
// backslash-escaped opening quote for JSON-embedded command lines, via
// the shared detectQuote/findQuotedEnd helpers) or a bare argument run.
// Placeholder and template-ref values are rejected via
// isPlaceholder. Password flags require only length >=
// cliPasswordMinLen; token/key/secret flags require length >=
// cliTokenMinLen AND entropy.PresetLooseToken, since their values are
// machine-generated and should look random. Only the value is redacted.
func CommandLinePasswordFlag(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if trigStart > 0 {
		if p := window[trigStart-1]; p == '-' || isAlnum(p) {
			return 0, 0, false
		}
	}
	if trigEnd >= len(window) {
		return 0, 0, false
	}

	var valPos int
	switch {
	case window[trigEnd] == '=':
		valPos = trigEnd + 1
	case isSpaceByte(window[trigEnd]):
		valPos = skipHSpace(window, trigEnd)
	default:
		// The flag name continues (e.g. --password-file) or the line ends.
		return 0, 0, false
	}

	quote, escaped, pos := detectQuote(window, valPos)
	var valStart, valEnd int
	if quote != 0 {
		valStart = pos
		var found bool
		valEnd, found = findQuotedEnd(window, pos, quote, escaped)
		if !found {
			return 0, 0, false
		}
	} else {
		if valPos < len(window) && window[valPos] == '-' {
			return 0, 0, false // next flag, not a value
		}
		valStart = valPos
		valEnd = valStart
		for valEnd < len(window) && isBareCLIValueChar(window[valEnd]) {
			valEnd++
		}
	}
	if valEnd <= valStart {
		return 0, 0, false
	}
	val := window[valStart:valEnd]
	if isPlaceholder(val) {
		return 0, 0, false
	}
	if isIndirectAssignmentValue(val) {
		return 0, 0, false
	}

	trig := window[trigStart:trigEnd]
	if asciiEqualFold(trig, "--password") || asciiEqualFold(trig, "--passwd") {
		if len(val) < cliPasswordMinLen || entropy.Classify(val) == entropy.ClassWordlike {
			return 0, 0, false
		}
		return valStart, valEnd, true
	}
	if len(val) < cliTokenMinLen {
		return 0, 0, false
	}
	opts := entropy.PresetLooseToken
	opts.MinLen = cliTokenMinLen
	if !entropy.Secretlike(val, opts) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}
