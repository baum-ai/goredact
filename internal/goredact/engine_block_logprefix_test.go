package goredact

// Keys printed behind a literal per-line log prefix: docker compose's
// service column, kubectl logs --prefix, docker logs -t timestamps and
// syslog headers. The line frame grammar reads none of them (a frame is
// quotes, comments, line numbers and indentation), so before ENG-1415 such
// a key was not detected at all. The scans now skip the trigger line's
// prefix length on the following lines. The key material is synthetic.

import (
	"fmt"
	"strings"
	"testing"
)

// logPrefixes are per-line prefixes of real log formats; prefix(i) is the
// prefix of line i of the printed key.
var logPrefixes = []struct {
	name   string
	prefix func(i int) string
}{
	{"docker compose", func(int) string { return "api-1     | " }},
	{"docker compose, no padding", func(int) string { return "svc-1  | " }},
	{"kubectl logs --prefix", func(int) string { return "[pod/web-7d9f8b6c4-x2x9z/app] " }},
	{"docker logs -t", func(i int) string { return fmt.Sprintf("2026-10-21T12:00:%02d.%09dZ ", i%60, 123456789+i*1000) }},
	{"syslog", func(i int) string { return fmt.Sprintf("Oct 21 12:%02d:%02d host app[123]: ", i/60%60, i%60) }},
	{"syslog, padded day", func(i int) string { return fmt.Sprintf("Oct  1 09:00:%02d build-7 sshd[4021]: ", i%60) }},
}

// TestEngineKeyBehindLogPrefix: PEM, PGP and PuTTY keys behind each log
// prefix are masked whole, in every streaming configuration.
func TestEngineKeyBehindLogPrefix(t *testing.T) {
	body := blockTestLines(61, 30)
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----"
	encrypted := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0F1E2D3C4B5A69788796A5B4C3D2E1F0\n\n" +
		strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----"
	pgp, pgpBody := blockTestPGP(62, 40<<10)
	armored := strings.Replace(pgp, "BLOCK-----\n\n", "BLOCK-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\nComment: \"Alice\" <alice@example.com>\n\n", 1)
	ppk, _, priv := blockTestPPK(63, 20)
	ppk = strings.TrimSuffix(ppk, "\n")
	big, _, bigPriv := blockTestPPK(64, 600)
	big = strings.TrimSuffix(big, "\n")
	for _, lp := range logPrefixes {
		for _, tc := range []struct {
			name   string
			key    string
			secret []string
		}{
			{"PEM", pem, body},
			{"encrypted PEM", encrypted, body},
			{"40 KiB PGP key", pgp, pgpBody},
			{"PGP key with armor headers", armored, pgpBody},
			{"PuTTY", ppk, priv},
			{"PuTTY, 600 private lines", big, bigPriv},
		} {
			t.Run(lp.name+"/"+tc.name, func(t *testing.T) {
				input := lp.prefix(0) + "starting\n" + shapePrefix(tc.key, func(i int) string { return lp.prefix(i + 1) }) + "\n" +
					lp.prefix(100) + "listening on :8080\n"
				assertBlockMasked(t, input, tc.secret)
			})
		}
	}
}

// TestEngineKeyBehindLogPrefixKeepsOtherLines: the log lines after the END
// marker or the Private-MAC line keep their text, and those before the key
// too.
func TestEngineKeyBehindLogPrefixKeepsOtherLines(t *testing.T) {
	body := blockTestLines(65, 12)
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END OPENSSH PRIVATE KEY-----"
	ppk, _, _ := blockTestPPK(66, 8)
	ppk = strings.TrimSuffix(ppk, "\n")
	for _, lp := range logPrefixes {
		for name, key := range map[string]string{"PEM": pem, "PuTTY": ppk} {
			t.Run(lp.name+"/"+name, func(t *testing.T) {
				input := lp.prefix(0) + "loading the deploy key\n" +
					shapePrefix(key, func(i int) string { return lp.prefix(i + 1) }) + "\n" +
					lp.prefix(100) + "listening on port 8080 (pid 7)\n"
				out, _ := redactAll(t, mustEngine(t, Config{}), strings.NewReader(input))
				for _, keep := range []string{"loading the deploy key", "listening on port 8080 (pid 7)"} {
					if !strings.Contains(out, keep) {
						t.Fatalf("%q was masked:\n%s", keep, out)
					}
				}
			})
		}
	}
}

// TestEngineLogPrefixNoFalsePositive: a BEGIN line behind a log prefix
// that only names a key, followed by prose log lines, is not a key.
func TestEngineLogPrefixNoFalsePositive(t *testing.T) {
	for _, lp := range logPrefixes {
		t.Run(lp.name, func(t *testing.T) {
			lines := []string{
				"the file must start with -----BEGIN PRIVATE KEY----- and end with -----END PRIVATE KEY-----",
				"-----BEGIN PRIVATE KEY-----",
				"is the expected header; got an empty file instead.",
				"retrying in 5 seconds (attempt 2 of 10).",
				"-----END PRIVATE KEY-----",
				"done.",
			}
			input := shapePrefix(strings.Join(lines, "\n"), lp.prefix) + "\n"
			out, stats := redactAll(t, mustEngine(t, Config{}), strings.NewReader(input))
			if out != input {
				t.Fatalf("prose was masked (findings %v):\n%s", stats.ByRule, out)
			}
		})
	}
}
