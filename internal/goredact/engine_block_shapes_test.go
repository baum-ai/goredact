package goredact

// Regression tests for private keys in the shapes they take in logs,
// agent transcripts, patches and sources, which v0.3.0 left (mostly)
// unmasked: string literals escaped by PHP and .NET JSON encoders, lines
// behind a prefix (a quote, a comment, a line number, an indentation),
// keys concatenated from one string literal per line, keys spanning two
// hunks of a patch, and PuTTY keys whose Private-Lines count is too low.
// Every case streams the input in every configuration assertBlockMasked
// covers. The key material is synthetic.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// shapeLines applies line to every line of s (split on "\n").
func shapeLines(s string, line func(i int, l string) string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = line(i, lines[i])
	}
	return strings.Join(lines, "\n")
}

// shapePrefix puts prefix(i) before line i of s.
func shapePrefix(s string, prefix func(i int) string) string {
	return shapeLines(s, func(i int, l string) string { return prefix(i) + l })
}

// shapeConst puts the same prefix before every line of s.
func shapeConst(prefix, s string) string {
	return shapePrefix(s, func(int) string { return prefix })
}

var (
	// phpJSON escapes a string as PHP's json_encode does: '/' as `\/`.
	phpJSON = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "/", `\/`, "\n", `\n`, "\t", `\t`).Replace
	// dotnetJSON escapes a string as .NET's System.Text.Json does by
	// default: '+' as `\u002B` and '"' as `\u0022`.
	dotnetJSON = strings.NewReplacer(`\`, `\\`, `"`, `\u0022`, "+", `\u002B`, "\n", `\n`, "\t", `\t`).Replace
)

// stdJSON escapes a string as encoding/json does, without HTML escaping
// (agent transcripts keep '→' as UTF-8); asciiJSON escapes everything
// outside ASCII too, as Python's json.dumps does by default.
func stdJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	out := string(b[1 : len(b)-1])
	return strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&").Replace(out)
}

func asciiJSON(s string) string {
	var b strings.Builder
	for _, r := range stdJSON(s) {
		if r > 0x7e {
			fmt.Fprintf(&b, `\u%04x`, r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// encodeLines returns the key lines as enc writes them.
func encodeLines(lines []string, enc func(string) string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = enc(l)
	}
	return out
}

func identity(s string) string { return s }

// TestEngineKeyShapes: keys in string literals, behind line prefixes,
// concatenated per line and across hunk boundaries are masked whole. v0.3.0
// masked at most their BEGIN line and first run, or nothing.
func TestEngineKeyShapes(t *testing.T) {
	body := blockTestLines(40, 30)
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----"
	pgp, pgpBody := blockTestPGP(41, 40<<10)
	numbered := func(s string) string {
		return shapePrefix(s, func(i int) string { return fmt.Sprintf("%6d→", i+1) })
	}
	goConcat := func(s string) string {
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = "\t\"" + lines[i] + `\n"`
			if i < len(lines)-1 {
				lines[i] += " +"
			}
		}
		return "var key = \"\" +\n" + strings.Join(lines, "\n") + "\n"
	}
	javaConcat := func(s string) string {
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = "    + \"" + lines[i] + `\n"`
		}
		return "String key = \"\"\n" + strings.Join(lines, "\n") + ";\n"
	}
	jsConcat := func(s string) string {
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = "  '" + lines[i] + "' +"
		}
		return "const key =\n" + strings.Join(lines, "\n") + "\n  '';\n"
	}
	// A patch whose second hunk resumes inside the key: git puts the last
	// line before the hunk that starts with a letter — a key line — in
	// the hunk header's section heading.
	hunks := func(marker, key string, lines []string) string {
		cut := strings.Index(key, lines[len(lines)/2])
		return "@@ -1,9 +1,9 @@\n" + blockTestDiff(marker, key[:cut-1]) +
			"@@ -40,7 +40,7 @@ " + lines[len(lines)/2-1] + "\n" + blockTestDiff(marker, key[cut:]) + " after\n"
	}

	for _, tc := range []struct {
		name   string
		input  string
		secret []string
		enc    func(string) string
	}{
		{"PHP json_encode", `{"key":"` + phpJSON(pem) + `"}` + "\n", body, phpJSON},
		{"PHP json_encode, 40 KiB PGP key", `{"key":"` + phpJSON(pgp) + `"}` + "\n", pgpBody, phpJSON},
		{".NET System.Text.Json", `{"key":"` + dotnetJSON(pem) + `"}` + "\n", body, dotnetJSON},
		{".NET System.Text.Json, 40 KiB PGP key", `{"key":"` + dotnetJSON(pgp) + `"}` + "\n", pgpBody, dotnetJSON},
		{"PHP json_encode inside JSON", `{"log":"` + stdJSON(`{"key":"`+phpJSON(pem)+`"}`) + `"}` + "\n",
			body, func(s string) string { return stdJSON(phpJSON(s)) }},
		{"email quote", "On Monday Bob wrote:\n" + shapeConst("> ", pem) + "\n> \n> Thanks\n", body, identity},
		{"nested email quote", shapeConst("> > ", pem) + "\n", body, identity},
		{"nested quote without spaces", shapeConst(">> ", pgp) + "\n", pgpBody, identity},
		{"shell comment", "# key for the test fixture\n" + shapeConst("# ", pem) + "\n", body, identity},
		{"block comment", "/*\n" + shapeConst(" * ", pem) + "\n */\n", body, identity},
		{"line numbers with an arrow", numbered(pem) + "\n", body, identity},
		{"line numbers with an arrow, 40 KiB PGP key", numbered(pgp) + "\n", pgpBody, identity},
		{"line numbers in a JSON transcript", `{"content":"` + stdJSON(numbered(pem)) + `"}` + "\n", body, stdJSON},
		{"line numbers in an ASCII JSON transcript", `{"content":"` + asciiJSON(numbered(pem)) + `"}` + "\n", body, asciiJSON},
		{"Go string concatenation", goConcat(pem), body, identity},
		{"Go string concatenation, 40 KiB PGP key", goConcat(pgp), pgpBody, identity},
		{"Go string concatenation in a patch", "@@ -0,0 +1,33 @@\n" + blockTestDiff("+", goConcat(pem)), body, identity},
		{"Java string concatenation", javaConcat(pem), body, identity},
		{"JavaScript string concatenation", jsConcat(pem), body, identity},
		{"quoted key in a patch", "@@ -0,0 +1,32 @@\n" + blockTestDiff("+", shapeConst("> ", pem)), body, identity},
		{"key across a hunk boundary", hunks(" ", pem, body), body, identity},
		{"added key across a hunk boundary", hunks("+", pem, body), body, identity},
		{"removed key across a hunk boundary", hunks("-", pem, body), body, identity},
		{"40 KiB PGP key across a hunk boundary", hunks(" ", pgp, pgpBody), pgpBody, identity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertBlockMasked(t, tc.input, encodeLines(tc.secret, tc.enc))
		})
	}
}

// TestEngineKeyShapesKept: shapes v0.3.0 already masked, through the
// grammar rather than by design — a "// " comment, `cat -n` and agent
// transcript line numbers followed by a tab, a key concatenated per line
// in a JSON-escaped source — stay masked now that line frames and quote
// tails are read explicitly.
func TestEngineKeyShapesKept(t *testing.T) {
	body := blockTestLines(53, 30)
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END OPENSSH PRIVATE KEY-----"
	tabbed := shapePrefix(pem, func(i int) string { return fmt.Sprintf("%d\t", i+1) })
	goConcat := "var key = " + shapeLines(pem, func(i int, l string) string { return "\t\"" + l + `\n" +` }) + "\n\t\"\"\n"
	for _, tc := range []struct {
		name   string
		input  string
		secret []string
		enc    func(string) string
	}{
		{"line comment", shapeConst("// ", pem) + "\n", body, identity},
		{"cat -n", shapePrefix(pem, func(i int) string { return fmt.Sprintf("%6d\t", i+1) }) + "\n", body, identity},
		{"line numbers in a JSON transcript", `{"content":"` + stdJSON(tabbed) + `"}` + "\n", body, stdJSON},
		{"Go string concatenation in a JSON transcript", `{"content":"` + stdJSON(goConcat) + `"}` + "\n", body, stdJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertBlockMasked(t, tc.input, encodeLines(tc.secret, tc.enc))
		})
	}
}

// TestEnginePuTTYKeyShapes: PuTTY keys JSON-escaped (also by PHP and .NET
// encoders), indented in a YAML block, quoted, line-numbered,
// concatenated per line, and spanning two hunks of a patch are masked.
// v0.3.0 detected none of them, and masked only the first hunk's lines.
func TestEnginePuTTYKeyShapes(t *testing.T) {
	ppk, _, priv := blockTestPPK(43, 20)
	ppk = strings.TrimSuffix(ppk, "\n")
	big, _, bigPriv := blockTestPPK(44, 600)
	big = strings.TrimSuffix(big, "\n")
	goConcat := func(s string) string {
		return "var key = " + shapeLines(s, func(i int, l string) string {
			return "\t\"" + l + `\n" +`
		}) + "\n\t\"\"\n"
	}
	hunks := func(marker, key string, lines []string) string {
		cut := strings.Index(key, lines[len(lines)/2])
		return "@@ -1,9 +1,9 @@\n" + blockTestDiff(marker, key[:cut-1]) +
			"@@ -40,7 +40,7 @@ " + lines[len(lines)/2-1] + "\n" + blockTestDiff(marker, key[cut:])
	}
	for _, tc := range []struct {
		name   string
		input  string
		secret []string
		enc    func(string) string
	}{
		{"JSON-escaped", `{"key":"` + stdJSON(ppk) + `"}` + "\n", priv, stdJSON},
		{"JSON-escaped, 600 private lines", `{"key":"` + stdJSON(big) + `"}` + "\n", bigPriv, stdJSON},
		{"PHP json_encode", `{"key":"` + phpJSON(ppk) + `"}` + "\n", priv, phpJSON},
		{".NET System.Text.Json", `{"key":"` + dotnetJSON(ppk) + `"}` + "\n", priv, dotnetJSON},
		{"JSON inside JSON", `{"log":"` + stdJSON(`{"key":"`+stdJSON(ppk)+`"}`) + `"}` + "\n", priv,
			func(s string) string { return stdJSON(stdJSON(s)) }},
		{"YAML block, 2 spaces", "key: |\n" + shapeConst("  ", ppk) + "\nnext: 1\n", priv, identity},
		{"YAML block, 4 spaces", "keys:\n  ppk: |\n" + shapeConst("    ", ppk) + "\n", priv, identity},
		{"YAML block, 4 spaces, 600 private lines", "keys:\n  ppk: |\n" + shapeConst("    ", big) + "\n", bigPriv, identity},
		{"tab-indented", shapeConst("\t", ppk) + "\n", priv, identity},
		{"email quote", shapeConst("> ", ppk) + "\n", priv, identity},
		{"line numbers with an arrow", shapePrefix(ppk, func(i int) string { return fmt.Sprintf("%6d→", i+1) }) + "\n", priv, identity},
		{"Go string concatenation", goConcat(ppk), priv, identity},
		{"key across a hunk boundary", hunks(" ", ppk, priv), priv, identity},
		{"added key across a hunk boundary", hunks("+", ppk, priv), priv, identity},
		{"600 private lines across a hunk boundary", hunks(" ", big, bigPriv), bigPriv, identity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertBlockMasked(t, tc.input, encodeLines(tc.secret, tc.enc))
		})
	}
}

// TestEnginePuTTYPrivateLinesUndercount: base64 lines past a Private-Lines
// count that is too low are masked up to the Private-MAC line (at most
// ppkMaxOverflow of them). v0.3.0 masked only the counted lines.
func TestEnginePuTTYPrivateLinesUndercount(t *testing.T) {
	recount := func(ppk string, from, to int) string {
		return strings.Replace(ppk, fmt.Sprintf("Private-Lines: %d\n", from), fmt.Sprintf("Private-Lines: %d\n", to), 1)
	}
	ppk, _, priv := blockTestPPK(45, 20)
	big, _, bigPriv := blockTestPPK(46, 400)
	short := strings.Replace(ppk, priv[19]+"\n", priv[19][:10]+"\n", 1) // a short last line
	for _, tc := range []struct {
		name   string
		input  string
		secret []string
	}{
		{"5 of 20 lines counted", recount(ppk, 20, 5), priv},
		{"1 of 20 lines counted", recount(ppk, 20, 1), priv},
		{"short last line", recount(short, 20, 5), priv[:19]},
		{"300 of 400 lines counted", recount(big, 400, 300), bigPriv},
		{"JSON-escaped", `{"key":"` + stdJSON(recount(ppk, 20, 5)) + `"}` + "\n", priv},
		{"YAML block", "k: |\n" + shapeConst("  ", strings.TrimSuffix(recount(ppk, 20, 5), "\n")) + "\n", priv},
	} {
		t.Run(tc.name, func(t *testing.T) { assertBlockMasked(t, tc.input, tc.secret) })
	}

	// The short last line, followed by the Private-MAC line, is masked too.
	in := recount(short, 20, 5)
	out, _ := redactAll(t, mustEngine(t, Config{}), strings.NewReader(in))
	if strings.Contains(out, priv[19][:10]+"\n") || !strings.Contains(out, "\nPrivate-MAC: ") {
		t.Fatalf("short last line: %q", out)
	}
}

// assertSpan redacts input with the default marker and wants exactly
// input[start:end] replaced: the text around a key stays.
func assertSpan(t *testing.T, input string, start, end int) {
	t.Helper()
	want := input[:start] + DefaultMarker + input[end:]
	for name, sizes := range blockTestReadSizes() {
		out, _ := redactAll(t, mustEngine(t, Config{}), &chunkedReader{data: []byte(input), sizes: sizes})
		if out != want {
			t.Fatalf("%s: output\n%q\nwant\n%q", name, out, want)
		}
	}
}

// TestEngineKeyShapesBounded: the new shapes mask the key and nothing
// around it — quoted text after a quoted key, code after a concatenated
// one, a hunk header after an END line, a PuTTY file's MAC line and the
// lines after it — and prose behind a quoted BEGIN line is no key.
func TestEngineKeyShapesBounded(t *testing.T) {
	body := blockTestLines(47, 12)
	pem := "-----BEGIN EC PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END EC PRIVATE KEY-----"
	span := func(in, from, through string) (int, int) {
		s := strings.Index(in, from)
		e := strings.LastIndex(in, through) + len(through)
		return s, e
	}

	t.Run("quoted key, quoted reply", func(t *testing.T) {
		in := "> " + strings.ReplaceAll(pem, "\n", "\n> ") + "\n> Thanks, that works.\n> Bob\n"
		s, e := span(in, "-----BEGIN", "KEY-----")
		assertSpan(t, in, s, e)
	})
	t.Run("Go concatenation, code after", func(t *testing.T) {
		in := "var key = \"" + strings.ReplaceAll(pem, "\n", "\\n\" +\n\t\"") + "\\n\"\n\nfunc main() {}\n"
		s, e := span(in, "-----BEGIN", `KEY-----\n`)
		assertSpan(t, in, s, e)
	})
	t.Run("hunk header after the END line", func(t *testing.T) {
		in := "@@ -1,14 +1,14 @@\n" + blockTestDiff(" ", pem) + "@@ -30,2 +30,2 @@ func x\n-old\n+new\n"
		s, e := span(in, "-----BEGIN", "KEY-----")
		assertSpan(t, in, s, e)
	})
	t.Run("PuTTY key, MAC and text after", func(t *testing.T) {
		ppk, _, priv := blockTestPPK(48, 6)
		in := strings.Replace(ppk, "Private-Lines: 6\n", "Private-Lines: 2\n", 1) + "Thanks\n" + blockTestLines(49, 1)[0] + "\n"
		s, e := strings.Index(in, "Private-Lines:"), strings.Index(in, priv[5])+len(priv[5])
		assertSpan(t, in, s, e)
	})
	t.Run("well-formed PuTTY key, base64 after the MAC line", func(t *testing.T) {
		ppk, _, priv := blockTestPPK(50, 6)
		in := ppk + blockTestLines(51, 1)[0] + "\n"
		s, e := strings.Index(in, "Private-Lines:"), strings.Index(in, priv[5])+len(priv[5])
		assertSpan(t, in, s, e)
	})
	t.Run("undercounted PuTTY key, a short word after it", func(t *testing.T) {
		ppk, _, priv := blockTestPPK(52, 6)
		in := strings.Replace(ppk[:strings.Index(ppk, "Private-MAC")], "Private-Lines: 6\n", "Private-Lines: 4\n", 1) + "Thanks\n"
		s, e := strings.Index(in, "Private-Lines:"), strings.Index(in, priv[5])+len(priv[5])
		assertSpan(t, in, s, e)
	})
	for _, prose := range []string{
		"> -----BEGIN PRIVATE KEY----- is the header line\n> of a PKCS #8 key file.\n",
		"> -----BEGIN PRIVATE KEY-----\n> -----END PRIVATE KEY-----\n",
		"     1→-----BEGIN PRIVATE KEY-----\n     2→(paste the key here)\n",
		"\t\"-----BEGIN PRIVATE KEY-----\\n\" +\n\t\"-----END PRIVATE KEY-----\\n\"\n",
	} {
		out, stats := redactAll(t, mustEngine(t, Config{}), strings.NewReader(prose))
		if out != prose {
			t.Errorf("%q: redacted to %q (findings %v)", prose, out, stats.ByRule)
		}
	}
}

// TestEngineKeyShapesReview covers what an adversarial review of the shapes
// found: a key concatenated per line on the removed side of a patch, a
// PuTTY key whose trigger line alone is indented or quoted, a PuTTY count
// that is too low in a patch, and overflow lines after a hunk header.
func TestEngineKeyShapesReview(t *testing.T) {
	body := blockTestLines(54, 6)
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----"
	goConcat := "var key = \"" + strings.ReplaceAll(pem, "\n", "\\n\" +\n\t\"") + "\\n\"\n"
	t.Run("Go concatenation on removed lines", func(t *testing.T) {
		assertBlockMasked(t, "@@ -1,8 +0,0 @@\n"+blockTestDiff("-", goConcat), body)
	})
	t.Run("quoted key on removed lines", func(t *testing.T) {
		assertBlockMasked(t, "@@ -1,8 +0,0 @@\n-Bob wrote: "+blockTestDiff("-", shapeConst("> ", pem))[1:], body)
	})

	ppk, _, priv := blockTestPPK(55, 6)
	for _, prefix := range []string{"  ", "  > ", "     1→", "+> "} {
		t.Run(fmt.Sprintf("PuTTY trigger line behind %q only", prefix), func(t *testing.T) {
			assertBlockMasked(t, "key:\n"+prefix+ppk, priv)
		})
	}

	under := strings.Replace(ppk, "Private-Lines: 6\n", "Private-Lines: 2\n", 1)
	goPPK := "var ppk = \"" + strings.ReplaceAll(strings.TrimSuffix(under, "\n"), "\n", "\\n\" +\n\t\"") + "\\n\"\n"
	t.Run("PuTTY count too low, Go concatenation in a patch", func(t *testing.T) {
		assertBlockMasked(t, "@@ -0,0 +1,14 @@\n"+blockTestDiff("+", goPPK), priv)
	})
	t.Run("PuTTY count too low, lines after a hunk header", func(t *testing.T) {
		cut := strings.Index(under, priv[4])
		patch := "@@ -1,9 +1,9 @@\n" + blockTestDiff(" ", under[:cut-1]) + "@@ -20,4 +20,4 @@ " + priv[3] + "\n" + blockTestDiff(" ", under[cut:])
		assertBlockMasked(t, patch, priv)
	})
}
