// This file implements the generic contextual credential rules:
// heuristic ValidateFuncs that fire on assignment-style context around
// keyword triggers like "api_key", "password", or "token" (as opposed to
// the deterministic provider-specific validators in validators.go, which
// confirm exact known token shapes). Header/URL/cookie contexts are
// intentionally out of scope here and handled by contextual validators.
//
// # Parsing model
//
// All three validators share one parse: after the trigger, skip optional
// horizontal whitespace, skip one optional quote character (the trigger's
// own closing quote, for JSON-style quoted keys like "api_key": ...),
// skip optional whitespace again, require an assignment separator ("=",
// ":", or "=>"), skip optional whitespace again, then capture a value:
//
//   - If the next byte is a quote character (double quote, single quote,
//     or backtick) — optionally itself escaped with a leading backslash
//     (the case where an already-quoted string is embedded in a further
//     layer of escaping, e.g. JSON embedded in a log line) — the value
//     runs until the matching quote (or matching escaped-quote sequence,
//     if the opening quote was itself escaped) and is captured without
//     the quotes.
//   - Otherwise the value is the maximal run of printable, non-space
//     bytes, stopping at whitespace or one of the printable separators
//     comma, semicolon, closing brace, or a stray quote character.
//
// This is deliberately not a full unescaping parser: a value containing
// an actual backslash-escaped instance of its own delimiting quote (e.g.
// a JSON string value that itself contains \") will be truncated at that
// inner escape rather than continuing past it. That is an accepted
// simplification — the truncated prefix is still fed through
// entropy.Secretlike and, being shorter, is if anything less likely to
// pass, which is the conservative failure direction for a redaction tool.
//
// The trigger's preceding byte is also checked (isTriggerBoundaryOK):
// triggers are rejected when immediately preceded by an alphanumeric
// byte, so "x_api_key=" still fires (preceded by '_', non-alnum) but
// "capi_key=" does not (preceded by 'c', alnum) — the trigger must not be
// a suffix of a longer identifier.
//
// # False-positive budget
//
// FalsePositiveBudgetPerTenMiB documents the accuracy target these
// balanced-profile rules are tuned against. It is enforced empirically by
// the accuracy corpus harness, not by any check in this package;
// the constant exists so that harness (and this file's authors) have one
// canonical number to reference and keep in sync.
package validators

import "github.com/baum-ai/goredact/internal/entropy"

// FalsePositiveBudgetPerTenMiB is the accuracy target for the balanced-
// profile generic contextual rules in this file: fewer than this many
// false-positive redactions per 10 MiB of ordinary keyword-dense log and
// config data (the kind of text where "password", "token", "api_key" etc.
// appear constantly without carrying an actual secret value). The
// accuracy corpus harness measures against this number; it is not
// self-enforcing at build or test time.
const FalsePositiveBudgetPerTenMiB = 1

// bearerLikeTokenMinLen is the minimum captured value length required by
// GenericBearerLikeTokenAssignment, stricter than entropy.PresetLooseToken's
// own MinLen: the bare "token" trigger is much weaker evidence of a secret
// position than "api_key" or "password" (it fires on ordinary variable
// names, loop cursors, CSV/DB row tokens, etc.), so the value has to clear
// a higher length bar before entropy is even considered.
const bearerLikeTokenMinLen = 20

// isTriggerBoundaryOK reports whether the byte immediately preceding
// window[trigStart], if any, does not continue an identifier — i.e.
// trigStart is at the start of window (start of input) or the preceding
// byte is not alphanumeric. This rejects a trigger literal that is really
// a suffix of a longer identifier, e.g. the "api_key" trigger must not
// fire on "capi_key" (preceded by 'c'), but must still fire on
// "x_api_key" (preceded by '_', which is not alphanumeric).
func isTriggerBoundaryOK(window []byte, trigStart int) bool {
	if trigStart <= 0 {
		return true
	}
	return !isAlnum(window[trigStart-1])
}

// isSpaceByte reports whether c is ASCII horizontal whitespace (space or
// tab). Only horizontal whitespace is skipped between a trigger and its
// separator/value: a newline ends the search, since an assignment cannot
// span a line break in the formats these rules target (shell, YAML,
// JSON, .env).
func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t'
}

// skipHSpace returns the offset of the first byte at or after pos that is
// not ASCII horizontal whitespace (or len(window) if none remains). It
// never indexes out of range.
func skipHSpace(window []byte, pos int) int {
	for pos < len(window) && isSpaceByte(window[pos]) {
		pos++
	}
	return pos
}

// consumeSeparator consumes one assignment separator ("=>", "=", or ":")
// at pos, preferring the two-byte "=>" so that a lone "=" is not consumed
// out from under it. It never indexes out of range.
func consumeSeparator(window []byte, pos int) (next int, ok bool) {
	if pos+1 < len(window) && window[pos] == '=' && window[pos+1] == '>' {
		return pos + 2, true
	}
	if pos+1 < len(window) && window[pos] == ':' && window[pos+1] == ':' {
		// A "::" after the trigger is a Rust/C++ path segment
		// ("token::instruction::..."), not an assignment.
		return pos, false
	}
	if pos < len(window) && (window[pos] == '=' || window[pos] == ':') {
		return pos + 1, true
	}
	return pos, false
}

// isQuoteByte reports whether c is one of the three quote characters this
// parser recognizes: double quote, single quote, or backtick.
func isQuoteByte(c byte) bool {
	return c == '"' || c == '\'' || c == '`'
}

// isPrintableByte reports whether c is a printable, non-space ASCII byte
// (0x21-0x7E): the alphabet allowed in an unquoted captured value.
func isPrintableByte(c byte) bool {
	return c >= 0x21 && c <= 0x7E
}

// detectQuote looks at window starting at pos for an opening quote,
// optionally itself backslash-escaped, and reports which quote byte was
// found, whether it was escaped, and the offset just past it. If pos does
// not point at a quote (escaped or not), it reports quote 0 and next ==
// pos unchanged, meaning "no quote, parse an unquoted value instead". It
// never indexes out of range.
func detectQuote(window []byte, pos int) (quote byte, escaped bool, next int) {
	if pos+1 < len(window) && window[pos] == '\\' && isQuoteByte(window[pos+1]) {
		return window[pos+1], true, pos + 2
	}
	if pos < len(window) && isQuoteByte(window[pos]) {
		return window[pos], false, pos + 1
	}
	return 0, false, pos
}

// findQuotedEnd scans window from pos for the terminator of a quoted
// value: the bare quote byte if the opening quote was not itself escaped,
// or the two-byte sequence \<quote> if it was (see detectQuote and the
// file-level doc comment on why escaped opens use an escaped close). A
// literal newline before the terminator is treated as an unterminated
// value and reported as failure, matching this parser's line-oriented
// scope. It never indexes out of range.
func findQuotedEnd(window []byte, pos int, quote byte, escaped bool) (end int, ok bool) {
	for i := pos; i < len(window); i++ {
		if window[i] == '\n' {
			return 0, false
		}
		if escaped {
			if window[i] == '\\' && i+1 < len(window) && window[i+1] == quote {
				return i, true
			}
			continue
		}
		if window[i] == quote {
			return i, true
		}
	}
	return 0, false
}

// findUnquotedEnd scans window from pos for the end of an unquoted value:
// the maximal run of printable, non-space bytes, stopping at whitespace,
// a stray quote character, or one of ',', ';', '}'. It never indexes out
// of range.
func findUnquotedEnd(window []byte, pos int) (end int) {
	i := pos
	for i < len(window) {
		c := window[i]
		if !isPrintableByte(c) {
			break
		}
		if c == ',' || c == ';' || c == '}' || isQuoteByte(c) {
			break
		}
		i++
	}
	return i
}

// parseAssignmentValue implements the shared assignment-value parse
// documented at the top of this file, starting at pos (normally
// trigEnd). It reports the half-open span of the captured value
// (excluding any quotes) within window, and ok == false if no
// separator/value could be parsed at all (including running off the end
// of window at any step). It never indexes out of range.
func parseAssignmentValue(window []byte, pos int) (valStart, valEnd int, ok bool) {
	pos = skipHSpace(window, pos)
	// A JSON-style quoted key ("api_key": ...) leaves its own closing
	// quote directly after the trigger; skip at most one such quote byte
	// before looking for the separator. Unquoted keys (YAML, shell,
	// .env) simply won't have one here, so this is a no-op for them.
	if pos < len(window) && isQuoteByte(window[pos]) {
		pos++
		pos = skipHSpace(window, pos)
	}
	pos, ok = consumeSeparator(window, pos)
	if !ok {
		return 0, 0, false
	}
	pos = skipHSpace(window, pos)

	quote, escaped, pos := detectQuote(window, pos)
	valStart = pos
	if quote != 0 {
		valEnd, ok = findQuotedEnd(window, pos, quote, escaped)
		if !ok {
			return 0, 0, false
		}
	} else {
		valEnd = findUnquotedEnd(window, pos)
		// Source embedded in JSON often reaches this path as an unquoted
		// assignment followed by one or more escape backslashes and the
		// JSON string's closing quote. The backslashes frame the containing
		// string; they are not part of the assigned value.
		if valEnd < len(window) && isQuoteByte(window[valEnd]) {
			for valEnd > valStart && window[valEnd-1] == '\\' {
				valEnd--
			}
		}
	}
	if valEnd <= valStart {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

// GenericAPIKeyAssignment confirms an api-key/access-token-shaped
// assignment: one of this rule's triggers (api_key, apikey, api-key,
// access_token, auth_token, client_secret, secret_key, secret_key_base,
// session_secret, private_token —
// see internal/rules/specs/generic-credentials.json), not itself a suffix
// of a longer identifier, followed by an assignment separator and a value
// that entropy.Secretlike confirms as plausibly random under
// entropy.PresetAssignmentValue. Only the value is reported for
// redaction.
func GenericAPIKeyAssignment(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !isTriggerBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	if isEmptyInlineAssignment(window, trigStart, trigEnd) {
		return 0, 0, false
	}
	valStart, valEnd, ok := parseAssignmentValue(window, trigEnd)
	if !ok {
		return 0, 0, false
	}
	if isIndirectAssignmentValue(window[valStart:valEnd]) {
		return 0, 0, false
	}
	if !isMachineTokenValue(window[valStart:valEnd]) {
		return 0, 0, false
	}
	if isAlphaSpaceOnly(window[valStart:valEnd]) {
		return 0, 0, false
	}
	if !entropy.Secretlike(window[valStart:valEnd], entropy.PresetAssignmentValue) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

// isEmptyInlineAssignment recognizes quoted documentation fragments such as
// `token=` and `x_api_key=`. Without this check, the closing quote after '='
// is mistaken for an opening value quote and prose is captured up to the next
// quote in the document.
func isEmptyInlineAssignment(window []byte, trigStart, trigEnd int) bool {
	if trigStart <= 0 || !isQuoteByte(window[trigStart-1]) {
		return false
	}
	quote := window[trigStart-1]
	pos := skipHSpace(window, trigEnd)
	next, ok := consumeSeparator(window, pos)
	if !ok {
		return false
	}
	next = skipHSpace(window, next)
	return next < len(window) && window[next] == quote
}

// isMachineTokenValue enforces the basic shape implied by API-key and bearer
// token assignments. These values may contain punctuation, but not whitespace,
// non-ASCII prose, or backticks from source-code concatenation.
func isMachineTokenValue(value []byte) bool {
	for _, c := range value {
		if c <= ' ' || c >= 0x7f || c == '`' {
			return false
		}
	}
	return true
}

// isIndirectAssignmentValue rejects values that name or retrieve a secret
// rather than containing one. These shapes are common in source code,
// configuration templates, secret-manager references, and source embedded in
// JSON logs. Entropy is not useful for them: punctuation and mixed-case
// identifiers can make a URL or expression look more random than a real key.
func isIndirectAssignmentValue(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	if value[0] == '$' && !isModularCryptShape(value) {
		return true
	}
	if value[0] == '/' || value[0] == '~' || value[0] == '-' || value[0] == '.' || value[0] == ':' {
		return true
	}
	for _, marker := range []string{"\\n", "\\r", "...", "://", "::", "?.", "&amp", "process.env", "os.environ", "os.getenv", "secretparam(", "secrets.string(", "data.get("} {
		if containsFold(value, marker) {
			return true
		}
	}
	for _, c := range value {
		switch c {
		case '(', ')', '[', ']', '{', '}', '<', '>', '|', '^':
			return true
		}
	}
	for _, prefix := range []string{"env.", "cfg.", "config.", "var.", "excluded.", "this.", "self."} {
		if startsFold(value, prefix) {
			return true
		}
	}
	if startsFold(value, "dev-") || startsFold(value, "dev_") {
		return true
	}
	for _, suffix := range []string{".value", ".api_key", "_api_key", "apikey", ".apikey", ".access_token", ".auth_token", ".refresh_token", ".client_secret", ".secret_key", ".private_token"} {
		if endsFold(value, suffix) {
			return true
		}
	}
	if hasInteriorEqual(value) {
		return true
	}
	if isUpperCredentialIdentifier(value) || isHexAddress(value) {
		return true
	}
	if isIdentifierChain(value) {
		return true
	}
	return false
}

// isModularCryptShape reports whether value (which must start with '$')
// has the modular-crypt-format grammar used by password hashes such as
// "$2b$12$..." (bcrypt), "$argon2id$v=19$..." (argon2), or "$6$..."
// (sha512crypt): a leading '$', a recognized algorithm identifier, and at
// least one more '$'-delimited field. A shell/template reference ("$VAR",
// "${VAR}", "$(cmd)"), or a chain of concatenated shell variables like
// "$user$pass$env", never has that grammar, so this is what distinguishes
// a password hash — exactly the value a password assignment needs to
// redact — from an indirect reference. Delegates to
// entropy.IsModularCryptHash, which mirrors this reasoning for
// entropy.isTemplateRef's use of the same shape.
func isModularCryptShape(value []byte) bool {
	return entropy.IsModularCryptHash(value)
}

// isIdentifierChain reports whether value is a dot-separated chain of two
// or more source-code identifiers ("this.apiToken", "SyntaxKind.WithKeyword",
// "k.cfg.DataStreamsKey"): a member expression that names a value rather
// than containing one. JWTs are also dot-separated and must stay matchable,
// but their first segment is always base64 of `{"` ("eyJ"), so they are
// exempted before the shape check.
func isIdentifierChain(value []byte) bool {
	if len(value) >= 3 && value[0] == 'e' && value[1] == 'y' && value[2] == 'J' {
		return false
	}
	// Modular-crypt-format hashes (bcrypt's alphabet includes '.') must
	// stay matchable for the same reason JWTs are exempted above: a
	// dot inside the hash body is not a member-expression separator, and
	// '$' is intentionally accepted as an identifier byte below (for
	// shell-style "$var.field" chains), which would otherwise make the
	// hash's own "$"-delimited fields look like chain segments.
	if len(value) >= 1 && value[0] == '$' && isModularCryptShape(value) {
		return false
	}
	segments := 0
	segStart := 0
	for i := 0; i <= len(value); i++ {
		if i < len(value) && value[i] != '.' {
			continue
		}
		seg := value[segStart:i]
		if !isIdentifierSegment(seg) {
			return false
		}
		segments++
		segStart = i + 1
	}
	return segments >= 2
}

// isIdentifierSegment reports whether seg is a plausible source-code
// identifier: a leading ASCII letter, '_', or '$', followed by letters,
// digits, '_', or '$'.
func isIdentifierSegment(seg []byte) bool {
	if len(seg) == 0 {
		return false
	}
	c := seg[0]
	if c != '_' && c != '$' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	for _, c := range seg[1:] {
		if c != '_' && c != '$' && !isAlnum(c) {
			return false
		}
	}
	return true
}

func isUpperCredentialIdentifier(value []byte) bool {
	for _, c := range value {
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	for _, suffix := range []string{"_TOKEN", "_KEY", "_SECRET", "_PASSWORD"} {
		if endsFold(value, suffix) {
			return true
		}
	}
	return false
}

func isHexAddress(value []byte) bool {
	if len(value) != 42 || value[0] != '0' || value[1] != 'x' {
		return false
	}
	for _, c := range value[2:] {
		if !isHexByte(c) {
			return false
		}
	}
	return true
}

// hasInteriorEqual permits ordinary base64 padding but rejects structured
// expressions such as "vault=Name" and concatenated assignments.
func hasInteriorEqual(value []byte) bool {
	for i, c := range value {
		if c != '=' {
			continue
		}
		for _, rest := range value[i:] {
			if rest != '=' {
				return true
			}
		}
		return false
	}
	return false
}

// isAlphaSpaceOnly reports whether value contains nothing but ASCII
// letters and spaces. Such a value is dictionary-word material (a phrase,
// an identifier, a camelCase name like "URLPatternComponentResult" or
// "originalReviewGithubToken"), never a credential worth reporting: real
// secrets that survive the other checks always carry at least one digit
// or symbol. All three generic assignment validators use this.
func isAlphaSpaceOnly(value []byte) bool {
	for _, c := range value {
		if c != ' ' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// isProseValue recognizes captured quoted values that are sentence
// fragments rather than passwords: a leading or trailing space, or
// punctuation-then-space sequences (", ", "; ", ". ") that essentially
// never appear in a real password but always appear in prose that
// happened to sit inside quotes after a "password"-like keyword.
func isProseValue(value []byte) bool {
	if len(value) > 0 && (value[0] == ' ' || value[len(value)-1] == ' ') {
		return true
	}
	for i := 0; i+1 < len(value); i++ {
		if value[i+1] != ' ' {
			continue
		}
		if c := value[i]; c == ',' || c == ';' || c == '.' {
			return true
		}
	}
	return false
}

func startsFold(value []byte, prefix string) bool {
	return len(value) >= len(prefix) && asciiEqualFold(value[:len(prefix)], prefix)
}

func endsFold(value []byte, suffix string) bool {
	return len(value) >= len(suffix) && asciiEqualFold(value[len(value)-len(suffix):], suffix)
}

// GenericPasswordAssignment confirms a password-shaped assignment: one of
// this rule's triggers (password, passwd, pwd), not itself a suffix of a
// longer identifier, followed by an assignment separator and a value.
// It uses entropy.PresetAssignmentValue with MinLen lowered to 8 (password
// values run shorter than typical API keys) and additionally rejects any
// value entropy.Classify buckets as ClassWordlike — a plain dictionary
// word is never an acceptable password value, and this is checked
// explicitly here (on top of entropy.Secretlike's own unconditional
// word-like rejection) because password fields are exactly the position
// where a bare dictionary word is most likely to show up in real fixtures
// and logs. This validator's separator requirement also guards against
// the `pwd`/`passwd` shell commands and utilities: bare "pwd" or
// "passwd: files systemd" (an /etc/nsswitch.conf-style line) never parse
// past the separator/value step and so never match. Only the value is
// reported for redaction.
func GenericPasswordAssignment(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !isTriggerBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	valStart, valEnd, ok := parseAssignmentValue(window, trigEnd)
	if !ok {
		return 0, 0, false
	}
	value := window[valStart:valEnd]
	if isIndirectAssignmentValue(value) {
		return 0, 0, false
	}
	if entropy.Classify(value) == entropy.ClassWordlike {
		return 0, 0, false
	}
	if isAlphaSpaceOnly(value) || isProseValue(value) {
		return 0, 0, false
	}
	opts := entropy.PresetAssignmentValue
	opts.MinLen = 8
	if !entropy.Secretlike(value, opts) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

// GenericBearerLikeTokenAssignment confirms a bearer-token-shaped
// assignment behind the weak, single "token" trigger. Because "token"
// alone is much weaker evidence of a secret position than api_key or
// password (it also matches ordinary code like "token = csv.next()" or a
// documentation placeholder like "token: <YOUR_TOKEN>"), this validator
// demands more of the value than the other two: it must be at least
// bearerLikeTokenMinLen (20) bytes long, and must pass
// entropy.Secretlike under entropy.PresetLooseToken with that same
// stricter MinLen. Only the value is reported for redaction.
func GenericBearerLikeTokenAssignment(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !isTriggerBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	if isEmptyInlineAssignment(window, trigStart, trigEnd) {
		return 0, 0, false
	}
	valStart, valEnd, ok := parseAssignmentValue(window, trigEnd)
	if !ok {
		return 0, 0, false
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
	if len(value) < bearerLikeTokenMinLen {
		return 0, 0, false
	}
	opts := entropy.PresetLooseToken
	if opts.MinLen < bearerLikeTokenMinLen {
		opts.MinLen = bearerLikeTokenMinLen
	}
	if !entropy.Secretlike(value, opts) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}
