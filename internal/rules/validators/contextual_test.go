package validators

import "testing"

// contextualCase is the table-row shape for the contextual
// validator tests: the trigger is located by literal (first occurrence,
// ASCII case-insensitive, via findTrigger), and on a match the redacted
// span is compared as the substring it covers rather than raw offsets, so
// each case documents exactly which bytes get redacted.
type contextualCase struct {
	name    string
	window  string
	trig    string
	wantOK  bool
	wantVal string
}

func runContextualCases(t *testing.T, fn validateFunc, cases []contextualCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, te := findTrigger(t, tc.window, tc.trig)
			start, end, ok := fn([]byte(tc.window), ts, te)
			if ok != tc.wantOK {
				t.Fatalf("(%q, trig %q) ok = %v, want %v", tc.window, tc.trig, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got := tc.window[start:end]; got != tc.wantVal {
				t.Errorf("(%q, trig %q) redacts %q, want %q", tc.window, tc.trig, got, tc.wantVal)
			}
		})
	}
}

const (
	ctxToken32 = "kJ8vQ2mZ7xW4pL9sN3tYbF6hR0cD5gU1" // 32 mixed alnum
	ctxToken24 = "aK9mQ2vR7wL4mN8pX1sTbF3j"         // 24 mixed alnum
	ctxSig64   = "7f3a92c1e8b4d06f5a2c9e17b3d84f60a1c5e29b7d4f18a3c6e05b92d7f41a8c"
)

func TestAuthorizationHeader(t *testing.T) {
	cases := []contextualCase{
		{
			name:    "bearer value redacted, header and scheme preserved",
			window:  "Authorization: Bearer " + ctxToken32,
			trig:    "authorization:",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "lowercase header and token scheme",
			window:  "authorization: token " + ctxToken32 + "\r\n",
			trig:    "authorization:",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "proxy-authorization trigger",
			window:  "Proxy-Authorization: Bearer " + ctxToken32 + " HTTP/1.1",
			trig:    "proxy-authorization:",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "JWT with base64url bytes captured whole",
			window:  "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3In0.Qk3v_R7wL-mN4xB8",
			trig:    "authorization:",
			wantOK:  true,
			wantVal: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3In0.Qk3v_R7wL-mN4xB8",
		},
		{
			name:    "escaped JSON header line terminates at backslash",
			window:  `{"line":"\"authorization: bearer ` + ctxToken32 + `\""}`,
			trig:    "authorization:",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "extra horizontal whitespace tolerated",
			window:  "Authorization:\t Bearer  \t" + ctxToken32,
			trig:    "authorization:",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "basic base64 blob redacted",
			window:  "Authorization: Basic c3ZjLXVzZXI6a0o4dlEybVo3eFc0cEw5cw==",
			trig:    "authorization:",
			wantOK:  true,
			wantVal: "c3ZjLXVzZXI6a0o4dlEybVo3eFc0cEw5cw==",
		},
		{
			name:    "AWS4 redacts only the Signature value",
			window:  "Authorization: AWS4-HMAC-SHA256 Credential=AKIAUJZDEGXDNCF32EPF/20260810/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=" + ctxSig64 + "\nHost: s3.amazonaws.com",
			trig:    "authorization:",
			wantOK:  true,
			wantVal: ctxSig64,
		},
		{
			name:    "unknown scheme mentioning password redacts the parameter blob to EOL",
			window:  "Authorization: CustomAuth password=hunter2aa realm=x\nnext",
			trig:    "authorization:",
			wantOK:  true,
			wantVal: "password=hunter2aa realm=x",
		},
		{
			name:   "bearer angle-bracket placeholder never parses",
			window: "Authorization: Bearer <token>",
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "bearer template ref never parses",
			window: "Authorization: Bearer ${API_TOKEN}",
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "bearer placeholder value rejected",
			window: "Authorization: Bearer XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "bearer value too short",
			window: "Authorization: Bearer abc",
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "no space between scheme and value",
			window: "Authorization: Bearer" + ctxToken32 + "x", // one long non-scheme word
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "basic blob too short",
			window: "Authorization: Basic dXNlcjE=",
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "digest without Signature= or password never matches",
			window: `Authorization: Digest username="user1", realm="api", nonce="dcd98b7102dd2f0e", response="6629fae49393a05397450978507c4ef1"`,
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "AWS4 without a Signature parameter never matches",
			window: "Authorization: AWS4-HMAC-SHA256 Credential=AKIAUJZDEGXDNCF32EPF/20260810, SignedHeaders=host",
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "trigger as suffix of a longer identifier rejected",
			window: "xauthorization: Bearer " + ctxToken32,
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "window truncated right after trigger",
			window: "Authorization:",
			trig:   "authorization:",
			wantOK: false,
		},
		{
			name:   "window truncated inside scheme word",
			window: "Authorization: Bea",
			trig:   "authorization:",
			wantOK: false,
		},
	}
	runContextualCases(t, AuthorizationHeader, cases)
}

func TestCookieSessionTokenHeader(t *testing.T) {
	cases := []contextualCase{
		{
			name:    "first qualifying pair value redacted, names preserved",
			window:  "Cookie: theme=dark; sessionid=" + ctxToken24 + "; token=" + ctxToken32,
			trig:    "cookie:",
			wantOK:  true,
			wantVal: ctxToken24,
		},
		{
			name:    "set-cookie with attributes",
			window:  "Set-Cookie: sid=" + ctxToken32 + "; Path=/; HttpOnly; Secure",
			trig:    "set-cookie:",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "short qualifying value skipped, later pair confirmed",
			window:  "Cookie: sid=short1; auth=" + ctxToken32 + "; lang=en",
			trig:    "cookie:",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "valueless attribute and expires resynced over",
			window:  "Set-Cookie: lang=en; Expires=Wed, 21 Oct 2026 07:28:00 GMT; session=" + ctxToken24,
			trig:    "set-cookie:",
			wantOK:  true,
			wantVal: ctxToken24,
		},
		{
			name:    "escaped JSON header terminates value at backslash",
			window:  `{"line":"\"cookie: jwt=` + ctxToken32 + `\""}`,
			trig:    "cookie:",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:   "benign pairs only",
			window: "Cookie: theme=dark; lang=en; tz=UTC",
			trig:   "cookie:",
			wantOK: false,
		},
		{
			name:   "csrf-named token pair vetoed",
			window: "Set-Cookie: csrftoken=" + ctxToken32 + "; Path=/",
			trig:   "set-cookie:",
			wantOK: false,
		},
		{
			name:   "placeholder value rejected",
			window: "Cookie: auth=xxxxxxxxxxxxxxxxxxxx",
			trig:   "cookie:",
			wantOK: false,
		},
		{
			name:   "low-entropy wordlike value rejected",
			window: "Cookie: session=thisisjustaconfigword",
			trig:   "cookie:",
			wantOK: false,
		},
		{
			name:   "qualifying pair on the NEXT line is out of scope",
			window: "Cookie: theme=dark\nsession=" + ctxToken32,
			trig:   "cookie:",
			wantOK: false,
		},
		{
			name:   "window truncated right after trigger",
			window: "Cookie:",
			trig:   "cookie:",
			wantOK: false,
		},
	}
	runContextualCases(t, CookieSessionToken, cases)
}

func TestCookieSessionTokenPairTriggers(t *testing.T) {
	cases := []contextualCase{
		{
			name:    "second qualifying pair caught via its own trigger",
			window:  "okie: sessionid=" + ctxToken24 + "; token=" + ctxToken32 + "; lang=en",
			trig:    "token=",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "extended name auth_token with ookie context",
			window:  `{"headers":{"cookie":"gw=blue; auth_token=` + ctxToken32 + `"}}`,
			trig:    "token=",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:    "semicolon pair boundary is sufficient context",
			window:  "gw=blue; session=" + ctxToken24 + "; lang=en",
			trig:    "session=",
			wantOK:  true,
			wantVal: ctxToken24,
		},
		{
			name:    "dotted cookie name extends backwards",
			window:  "okie: a=1;connect.sid=" + ctxToken32,
			trig:    "sid=",
			wantOK:  true,
			wantVal: ctxToken32,
		},
		{
			name:   "no cookie context: URL query pair rejected",
			window: "GET /cb?next=%2Fdash&token=" + ctxToken24 + " HTTP/1.1",
			trig:   "token=",
			wantOK: false,
		},
		{
			name:   "no cookie context: bare assignment rejected (generic rules own it)",
			window: "token=" + ctxToken32,
			trig:   "token=",
			wantOK: false,
		},
		{
			name:   "csrf prefix in extended name vetoed despite context",
			window: "okie: a=1; csrftoken=" + ctxToken32,
			trig:   "token=",
			wantOK: false,
		},
		{
			name:   "short value rejected despite context",
			window: "okie: a=1; jwt=short1",
			trig:   "jwt=",
			wantOK: false,
		},
		{
			name:   "value at end of window (truncated) too short",
			window: "okie: a=1; auth=",
			trig:   "auth=",
			wantOK: false,
		},
	}
	runContextualCases(t, CookieSessionToken, cases)
}

func TestURLCredentials(t *testing.T) {
	cases := []contextualCase{
		{
			name:    "password redacted, scheme user host path preserved",
			window:  "DATABASE_URL=postgres://svc_user:wZ8kQ3vR7pL4mN2x@db.internal:5432/app",
			trig:    "://",
			wantOK:  true,
			wantVal: "wZ8kQ3vR7pL4mN2x",
		},
		{
			name:    "empty username, password only",
			window:  "redis://:q8LmPz31vTk@cache.prod.svc:6379/0",
			trig:    "://",
			wantOK:  true,
			wantVal: "q8LmPz31vTk",
		},
		{
			name:    "JSON-embedded DSN",
			window:  `{"dsn":"mysql://root:Vt5xK8nQ2wZ7@10.0.0.12:3306/orders"}`,
			trig:    "://",
			wantOK:  true,
			wantVal: "Vt5xK8nQ2wZ7",
		},
		{
			name:    "percent-encoded bytes pass through",
			window:  "https://svc:p%40ssW9rd7@h.example.com/x",
			trig:    "://",
			wantOK:  true,
			wantVal: "p%40ssW9rd7",
		},
		{
			name:    "uppercase scheme accepted",
			window:  "HTTPS://deploy:kQ3vR7wLmX2@releases.example.com/v2",
			trig:    "://",
			wantOK:  true,
			wantVal: "kQ3vR7wLmX2",
		},
		{
			name:    "short real password above the 3-byte floor",
			window:  "postgres://app:hx7@db/app",
			trig:    "://",
			wantOK:  true,
			wantVal: "hx7",
		},
		{
			name:   "username-only URL is not a secret",
			window: "https://deploy@github.com/org/repo.git",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "empty password",
			window: "redis://:@cache.internal:6379",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "placeholder password word",
			window: "postgres://user:password@localhost:5432/db",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "local placeholder list: pass",
			window: "http://user:pass@host.example.com",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "local placeholder list: pwd (case-insensitive)",
			window: "http://user:PWD@host.example.com",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "token placeholder",
			window: "https://user:TOKEN@github.com/owner/repo.git",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "malformed percent encoding",
			window: "postgres://user:unterminated%zz@localhost/db",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "word-like development password",
			window: "postgres://user:content@localhost:5432/db",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "password below the 3-byte floor",
			window: "ftp://u:ab@h.example.com",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "no userinfo: path reached before @",
			window: "https://status.example.com/healthz",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "no userinfo: port then path",
			window: "http://host.example.com:8080/x",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "prose separator has no scheme",
			window: `note: the "://" separator splits scheme from authority`,
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "scheme must start with a letter",
			window: "12://u:abcdef@h",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "one-byte scheme rejected",
			window: "x://u:abcdef@h",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "window truncated inside userinfo",
			window: "postgres://svc_user:wZ8k",
			trig:   "://",
			wantOK: false,
		},
		{
			name:   "window truncated right after trigger",
			window: "postgres://",
			trig:   "://",
			wantOK: false,
		},
	}
	runContextualCases(t, URLCredentials, cases)
}

func TestCommandLinePasswordFlag(t *testing.T) {
	cases := []contextualCase{
		{
			name:    "equals form",
			window:  "mysql -h db --password=tR8kW3nQ7zXm2 app_db",
			trig:    "--password",
			wantOK:  true,
			wantVal: "tR8kW3nQ7zXm2",
		},
		{
			name:    "space-separated form",
			window:  "mysql --password tR8kW3nQ7zXm2",
			trig:    "--password",
			wantOK:  true,
			wantVal: "tR8kW3nQ7zXm2",
		},
		{
			name:    "case-folded flag",
			window:  "MYSQL --PASSWORD=tR8kW3nQ7zXm2",
			trig:    "--password",
			wantOK:  true,
			wantVal: "tR8kW3nQ7zXm2",
		},
		{
			name:    "single-quoted api key",
			window:  "deploy --api-key 'Zp8kQ3vR7wL4mN2xT6bF9jH0' --env prod",
			trig:    "--api-key",
			wantOK:  true,
			wantVal: "Zp8kQ3vR7wL4mN2xT6bF9jH0",
		},
		{
			name:    "escaped double quote in JSON-embedded command",
			window:  `{"cmd":"vault --token=\"hvs.9kQ3vR7wL4mN2xT6bF0jH5cD\""}`,
			trig:    "--token",
			wantOK:  true,
			wantVal: "hvs.9kQ3vR7wL4mN2xT6bF0jH5cD",
		},
		{
			name:    "passwd variant",
			window:  "pg_restore --passwd=Xq7Lm2Vt9zR4 -d app",
			trig:    "--passwd",
			wantOK:  true,
			wantVal: "Xq7Lm2Vt9zR4",
		},
		{
			name:    "secret flag with random value",
			window:  "svc register --secret " + ctxToken24,
			trig:    "--secret",
			wantOK:  true,
			wantVal: ctxToken24,
		},
		{
			name:   "flag name continues: --password-file",
			window: "pg_dump --password-file /run/secrets/pgpass",
			trig:   "--password",
			wantOK: false,
		},
		{
			name:   "flag name continues: --token-url",
			window: "fetch --token-url https://auth.example.com/token",
			trig:   "--token",
			wantOK: false,
		},
		{
			name:   "empty value before next flag",
			window: "mysql --password= --host db",
			trig:   "--password",
			wantOK: false,
		},
		{
			name:   "bare value that is the next flag",
			window: "mysql --password --skip-ssl",
			trig:   "--password",
			wantOK: false,
		},
		{
			name:   "template ref value",
			window: "run.sh --password ${DB_PASSWORD}",
			trig:   "--password",
			wantOK: false,
		},
		{
			name:   "angle-bracket placeholder",
			window: "docs: use --api-key <your-key> to authenticate",
			trig:   "--api-key",
			wantOK: false,
		},
		{
			name:   "placeholder password",
			window: "login --secret changeme --user svc",
			trig:   "--secret",
			wantOK: false,
		},
		{
			name:   "password too short",
			window: "mysql --password=abc12",
			trig:   "--password",
			wantOK: false,
		},
		{
			name:   "token too short",
			window: "vault --token=Zp8kQ3vR7wL",
			trig:   "--token",
			wantOK: false,
		},
		{
			name:   "low-entropy token value rejected",
			window: "vault --token=aaaabbbbccccdddd",
			trig:   "--token",
			wantOK: false,
		},
		{
			name:   "triple dash is not a flag",
			window: "run ---password=tR8kW3nQ7zXm2",
			trig:   "--password",
			wantOK: false,
		},
		{
			name:   "four dashes at a line start are not a flag",
			window: "x\n----password=tR8kW3nQ7zXm2",
			trig:   "--password",
			wantOK: false,
		},
		{
			name:    "flag opening a removed diff line",
			window:  "@@ -1 +1 @@\n---password=tR8kW3nQ7zXm2\n+--password-file=/run/secrets/db",
			trig:    "--password",
			wantOK:  true,
			wantVal: "tR8kW3nQ7zXm2",
		},
		{
			name:    "flag opening an added diff line",
			window:  "@@ -0,0 +1 @@\n+--password=tR8kW3nQ7zXm2",
			trig:    "--password",
			wantOK:  true,
			wantVal: "tR8kW3nQ7zXm2",
		},
		{
			name:   "window truncated right after trigger",
			window: "mysql --password",
			trig:   "--password",
			wantOK: false,
		},
		{
			name:   "unterminated quoted value",
			window: "deploy --api-key 'Zp8kQ3vR7wL4mN2x",
			trig:   "--api-key",
			wantOK: false,
		},
	}
	runContextualCases(t, CommandLinePasswordFlag, cases)
}

// TestContextualValidatorsNeverPanic brute-forces every (trigStart,
// trigEnd) pair over a set of nasty windows — truncations, escapes,
// multi-byte structure — for all four validators.
func TestContextualValidatorsNeverPanic(t *testing.T) {
	windows := []string{
		"",
		":",
		"://",
		"=",
		";",
		"Authorization: Bearer " + ctxToken32,
		"Authorization: Basic",
		"Authorization: AWS4-HMAC-SHA256 Signature=",
		"Cookie: a=1; session=" + ctxToken24 + "; b=2",
		"cookie:",
		"set-cookie: sid=",
		"postgres://svc_user:wZ8kQ3vR7pL4mN2x@db.internal:5432/app",
		"x://:@",
		"--password=" + ctxToken24,
		"--password '",
		`{"line":"\"authorization: bearer ` + ctxToken32 + `\""}`,
		`{"cmd":"vault --token=\"hvs.9kQ3vR7wL4mN2xT6bF0jH5cD\""}`,
	}
	aiRunNeverPanics(t, "AuthorizationHeader", AuthorizationHeader, windows)
	aiRunNeverPanics(t, "CookieSessionToken", CookieSessionToken, windows)
	aiRunNeverPanics(t, "URLCredentials", URLCredentials, windows)
	aiRunNeverPanics(t, "CommandLinePasswordFlag", CommandLinePasswordFlag, windows)
}
