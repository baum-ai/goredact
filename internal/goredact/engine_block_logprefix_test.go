package goredact

// Keys printed behind a literal per-line log prefix: docker compose's
// service column, kubectl logs --prefix, docker logs -t timestamps and
// syslog headers. The line frame grammar reads none of them (a frame is
// quotes, comments, line numbers and indentation), so before ENG-1415 such
// a key was not detected at all. The scans now skip the trigger line's
// prefix length on the following lines. The key material is synthetic.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rfc3339Nano is the prefix kubectl logs --timestamps prints before line i:
// an RFC 3339 timestamp whose nanoseconds drop trailing zeros, so its
// length changes from line to line, by up to ten bytes.
func rfc3339Nano(i int) string {
	ns := []int{123456789, 120000000, 100000000, 0, 123456780, 5}[i%6]
	return time.Date(2026, 10, 21, 12, 0, i%60, ns, time.UTC).Format(time.RFC3339Nano) + " "
}

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
	{"docker compose, colour reset after the separator", func(int) string { return "\x1b[36mapi-1  | \x1b[0m" }},
	{"kubectl logs --timestamps", rfc3339Nano},
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

// TestEngineKeyBehindLogPrefixAndText: text before BEGIN behind the log
// prefix ("api-1  | PRIVATE_KEY=-----BEGIN ...") is not part of the
// prefix the following lines have: the longest leading part of it that
// they have is.
func TestEngineKeyBehindLogPrefixAndText(t *testing.T) {
	body := blockTestLines(67, 20)
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----"
	encrypted := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0F1E2D3C4B5A69788796A5B4C3D2E1F0\n\n" +
		strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----"
	pgp, pgpBody := blockTestPGP(68, 2<<10)
	armored := strings.Replace(pgp, "BLOCK-----\n\n", "BLOCK-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\nComment: Alice Example <alice@example.com>\n\n", 1)
	ppk, _, priv := blockTestPPK(69, 12)
	ppk = strings.TrimSuffix(ppk, "\n")
	for _, lp := range logPrefixes {
		if lp.name == "kubectl logs --timestamps" {
			continue // a prefix whose length changes is only read whole (docs/THREAT_MODEL.md)
		}
		for _, text := range []string{"PRIVATE_KEY=", "key: ", "PGP key: ", "export KEY=", "deploy key loaded: "} {
			for _, tc := range []struct {
				name   string
				key    string
				secret []string
			}{
				{"PEM", pem, body},
				{"encrypted PEM", encrypted, body},
				{"PGP key with armor headers", armored, pgpBody},
				{"PuTTY", ppk, priv},
			} {
				t.Run(lp.name+"/"+text+"/"+tc.name, func(t *testing.T) {
					key := shapePrefix(tc.key, func(i int) string {
						if i == 0 {
							return lp.prefix(1) + text
						}
						return lp.prefix(i + 1)
					})
					input := lp.prefix(0) + "starting\n" + key + "\n" + lp.prefix(100) + "listening on :8080\n"
					assertBlockMasked(t, input, tc.secret)
					out, _ := redactAll(t, mustEngine(t, Config{}), strings.NewReader(input))
					if !strings.Contains(out, "listening on :8080") {
						t.Fatalf("the line after the key was masked:\n%s", out)
					}
				})
			}
		}
	}
}

// TestEngineLogPrefixLabelArmorHeaders is the ENG-1415 review's regression:
// a label before BEGIN ("PGP key: ") and armor header lines printed raw. A
// byte of a header line may match the label's last byte at its length
// (the ' ' after "Comment:"), and the header read behind that length then
// fails; the line must be read as v0.4.0 reads it, with the frame grammar,
// or the key is left unmasked, BEGIN line included. Every label length up
// to keyFrameMax, with ' ' and ':' separators, masks the key exactly as
// v0.4.0 does.
func TestEngineLogPrefixLabelArmorHeaders(t *testing.T) {
	body := blockTestLines(70, 12)
	headers := [][]string{
		{"Comment: Alice Example <alice@example.com>"},
		{"Version: GnuPG v1.4.11 (GNU/Linux)", `Comment: "Alice" <alice@example.com>`},
		{"Version: OpenPGP.js v4.10.10", "Comment: https://openpgpjs.org"},
		{"Comment: a:b:c:d:e:f:g:h:i:j:k:l:m:n:o:p:q:r:s:t:u:v:w:x:y:z (key)"},
	}
	key := func(label string, hdr []string) string {
		lines := append([]string{"gpg export", label + "-----BEGIN PGP PRIVATE KEY BLOCK-----"}, hdr...)
		lines = append(lines, "")
		lines = append(lines, body...)
		lines = append(lines, "=AbCd", "-----END PGP PRIVATE KEY BLOCK-----", "done")
		return strings.Join(lines, "\n") + "\n"
	}
	// The review's reproduction.
	assertBlockMasked(t, key("PGP key: ", headers[0]), body)

	e := mustEngine(t, Config{})
	small := mustEngine(t, Config{ChunkSize: e.rules.MinChunkSize()})
	for _, hdr := range headers {
		for _, sep := range []string{" ", ":"} {
			for k := 1; k <= keyFrameMaxForTest; k++ {
				label := strings.Repeat("k", k-1) + sep
				input := key(label, hdr)
				want := "gpg export\n" + label + DefaultMarker + "\ndone\n"
				for _, eng := range []*Engine{e, small} {
					out, _ := redactAll(t, eng, &chunkedReader{data: []byte(input), sizes: func(int) int { return 7 }})
					if out != want {
						t.Fatalf("label %q, headers %q: got\n%s", label, hdr, out)
					}
				}
			}
		}
	}
}

// keyFrameMaxForTest is the validators' keyFrameMax: the longest literal
// prefix.
const keyFrameMaxForTest = 64

// TestEngineLogPrefixNeverMasksLess: inputs on which the scans behind a
// literal prefix, as first written, masked less of the key than v0.4.0,
// found by a differential test against v0.4.0 (testdata/logprefix holds
// each input and v0.4.0's output under MaskLengthPreserving). A prefix
// shaped like an armor header ("worker: ", "x: ") reads every line as a
// header to v0.4.0, through output interleaved with the key; a label
// before BEGIN may match a byte of a raw header line. Every byte v0.4.0
// masks must be masked, but on the log line after the key, which v0.4.0
// may mask reading on past an END marker behind the prefix.
func TestEngineLogPrefixNeverMasksLess(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "logprefix", "v040.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name  string `json:"name"`
		Input string `json:"input"`
		V040  string `json:"v040"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	whole := mustEngine(t, Config{MaskStrategy: MaskLengthPreserving})
	small := mustEngine(t, Config{MaskStrategy: MaskLengthPreserving, ChunkSize: whole.rules.MinChunkSize()})
	for _, tc := range cases {
		for name, e := range map[string]*Engine{"whole": whole, "min chunk": small} {
			out, _ := redactAll(t, e, &chunkedReader{data: []byte(tc.Input), sizes: func(int) int { return 7 }})
			if len(out) != len(tc.Input) || len(tc.V040) != len(tc.Input) {
				t.Fatalf("%s: length changed", tc.Name)
			}
			last := strings.LastIndex(strings.TrimSuffix(tc.Input, "\n"), "\n")
			for i := range out[:last] {
				if tc.V040[i] == '*' && tc.Input[i] != '*' && out[i] != '*' {
					t.Fatalf("%s, %s: byte %d masked by v0.4.0 is not:\n%s", tc.Name, name, i, out)
				}
			}
		}
	}
}
