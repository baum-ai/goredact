package goredact

// Regression tests for keys the first block-rule version under-masked:
// PuTTY keys rotated in real `git diff --no-index` patches, keys nested in
// a key whose scan ends first, separator gaps, long PPK lines, keys on the
// other side of a diff, and armor headers. Every test streams the input
// with assorted chunk sizes, mask strategies and reads.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// blockLeaks reports how many of lines survive in out (by a 24-byte middle
// slice, so masking either end of a line does not hide a survivor).
func blockLeaks(out string, lines []string) int {
	n := 0
	for _, l := range lines {
		if len(l) >= 44 && strings.Contains(out, l[20:44]) {
			n++
		}
	}
	return n
}

// assertBlockMasked streams input through the balanced built-ins in every
// configuration and fails if any of secret survives.
func assertBlockMasked(t *testing.T, input string, secret []string) {
	t.Helper()
	minChunk := mustEngine(t, Config{}).rules.MinChunkSize()
	for _, chunk := range []int{0, minChunk} {
		for _, strategy := range []MaskStrategy{MaskFixedMarker, MaskLengthPreserving, MaskFormatPreserving} {
			for _, aligned := range []bool{false, true} {
				for name, sizes := range blockTestReadSizes() {
					e := mustEngine(t, Config{ChunkSize: chunk, MaskStrategy: strategy, RecordAligned: aligned})
					out, stats := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: sizes})
					if n := blockLeaks(out, secret); n > 0 {
						t.Fatalf("chunk %d, %v, record-aligned %v, %s: %d of %d secret lines survive (findings %v)",
							chunk, strategy, aligned, name, n, len(secret), stats.ByRule)
					}
				}
			}
		}
	}
}

// ppkPrivate returns the private lines of a PPK file.
func ppkPrivate(t *testing.T, ppk string) []string {
	t.Helper()
	var out []string
	in := false
	for _, line := range strings.Split(ppk, "\n") {
		switch {
		case strings.HasPrefix(line, "Private-Lines:"):
			in = true
		case strings.HasPrefix(line, "Private-MAC:"):
			in = false
		case in:
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatal("no private lines")
	}
	return out
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ppkdiff", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEnginePuTTYKeyRotationInGitDiff: replacing a PuTTY key with one of
// another type or size, as `git diff --no-index` shows it (the PPK files
// are synthetic, generated with random base64), masks the private lines
// of both versions. The rsa 6/14 key is replaced by an rsa 6/14 key, an
// ed25519 2/1 key, and an rsa-4096 12/28 key in PPK v2 and v3.
func TestEnginePuTTYKeyRotationInGitDiff(t *testing.T) {
	old := ppkPrivate(t, readTestdata(t, "old_rsa.ppk"))
	for _, name := range []string{"new_rsa", "new_ed", "new_rsa4k", "new_rsa4k_v2"} {
		t.Run(name, func(t *testing.T) {
			patch := readTestdata(t, "diff_"+name+".patch")
			fresh := ppkPrivate(t, readTestdata(t, name+".ppk"))
			assertBlockMasked(t, patch, append(append([]string{}, old...), fresh...))
		})
	}
}

// TestEngineNestedKeysMaskedToTheirOwnEnd: a key inside another key whose
// scan ends first is still masked to its own end.
func TestEngineNestedKeysMaskedToTheirOwnEnd(t *testing.T) {
	outer := blockTestLines(20, 320) // ~20 KiB, no END
	inner := blockTestLines(21, 640) // ~41 KiB
	pgp := func(headers string) string {
		return "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + headers + "\n" + strings.Join(inner, "\n") +
			"\n=Tx4q\n-----END PGP PRIVATE KEY BLOCK-----\n"
	}
	open := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(outer, "\n") + "\n"
	secret := append(append([]string{}, outer...), inner...)

	t.Run("outer gives up on the inner key's comment", func(t *testing.T) {
		// The outer scan reads the inner armor's 20-word comment as prose
		// and stops; the inner key's own scan takes it as an armor header.
		assertBlockMasked(t, open+pgp("Comment: "+strings.Repeat("word ", 20)+"\n")+"tail\n", secret)
	})
	t.Run("300 newlines after the inner header", func(t *testing.T) {
		gap := "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + strings.Repeat("\n", 300) + strings.Join(inner, "\n") +
			"\n-----END PGP PRIVATE KEY BLOCK-----\ntail\n"
		assertBlockMasked(t, open+gap, secret)
	})
	t.Run("PuTTY key counting the next trigger line", func(t *testing.T) {
		// The first key, longer than the window, declares more private
		// lines than it has, so its scan counts the "PuTTY" of the next
		// key's first line and stops; the second key's long private
		// section is still masked whole.
		first, _, firstPriv := blockTestPPK(22, 300)
		first = strings.Replace(first, "Private-Lines: 300", "Private-Lines: 400", 1)
		first = first[:strings.Index(first, "Private-MAC")]
		second, _, secondPriv := blockTestPPK(23, 600)
		assertBlockMasked(t, first+second, append(append([]string{}, firstPriv...), secondPriv...))
	})
}

// TestEngineSeparatorGapInsideKey: a run of separators inside a key body,
// such as 300 spaces, does not end the key.
func TestEngineSeparatorGapInsideKey(t *testing.T) {
	for _, n := range []int{60, 700} {
		t.Run(fmt.Sprint(n, " lines"), func(t *testing.T) {
			body := blockTestLines(24, n)
			key := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(body[:10], "\n") + "\n" + strings.Repeat(" ", 300) +
				strings.Join(body[10:], "\n") + "\n-----END RSA PRIVATE KEY-----\nafter\n"
			assertBlockMasked(t, key, body)
		})
	}
}

// TestEngineLongPuTTYLines: a private line longer than the window is masked
// as far as it goes.
func TestEngineLongPuTTYLines(t *testing.T) {
	lines := blockTestLines(29, 3)
	long := strings.Join(blockTestLines(25, 400), "") // one 25 KiB line
	var pieces []string
	for i := 0; i+64 <= len(long); i += 64 {
		pieces = append(pieces, long[i:i+64])
	}
	head := "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: c\nPublic-Lines: 1\n" + lines[0] + "\n"
	t.Run("single private line", func(t *testing.T) {
		assertBlockMasked(t, head+"Private-Lines: 1\n"+long+"\nPrivate-MAC: 00\n", pieces)
	})
	t.Run("long middle private line", func(t *testing.T) {
		assertBlockMasked(t, head+"Private-Lines: 3\n"+lines[1]+"\n"+long+"\n"+lines[2]+"\nPrivate-MAC: 00\n", append(pieces, lines[2]))
	})
	t.Run("long line on + lines", func(t *testing.T) {
		assertBlockMasked(t, blockTestDiff("+", head+"Private-Lines: 2\n"+long+"\n"+lines[2]+"\nPrivate-MAC: 00\n"), append(pieces, lines[2]))
	})
}

// TestEngineDiffSidesKeepTheirOwnEnd: in a patch, the END line of a removed
// key does not close a key added around it, and the reverse.
func TestEngineDiffSidesKeepTheirOwnEnd(t *testing.T) {
	added := blockTestLines(26, 400)
	removed := blockTestLines(27, 10)
	var d strings.Builder
	d.WriteString("@@ -1,12 +1,402 @@\n+-----BEGIN RSA PRIVATE KEY-----\n")
	for _, l := range added[:20] {
		d.WriteString("+" + l + "\n")
	}
	d.WriteString("------BEGIN EC PRIVATE KEY-----\n")
	for _, l := range removed {
		d.WriteString("-" + l + "\n")
	}
	d.WriteString("------END EC PRIVATE KEY-----\n")
	for _, l := range added[20:] {
		d.WriteString("+" + l + "\n")
	}
	d.WriteString("+-----END RSA PRIVATE KEY-----\n context after\n")
	assertBlockMasked(t, d.String(), append(append([]string{}, added...), removed...))

	// The same with the sides swapped: a removed key around an added one.
	swapped := strings.NewReplacer("\n+", "\n\x00", "\n-", "\n+").Replace(d.String())
	swapped = strings.ReplaceAll(swapped, "\n\x00", "\n-")
	assertBlockMasked(t, swapped, append(append([]string{}, added...), removed...))

	// A context END closes a context BEGIN whichever version's lines it
	// holds.
	ctx := "@@ -1,5 +1,5 @@\n -----BEGIN RSA PRIVATE KEY-----\n-" + removed[0] + "\n+" + added[0] + "\n " + added[1] +
		"\n -----END RSA PRIVATE KEY-----\n after\n"
	out, _ := redactAll(t, mustEngine(t, Config{MaskStrategy: MaskLengthPreserving}), strings.NewReader(ctx))
	if !strings.HasSuffix(out, "\n after\n") || blockLeaks(out, []string{removed[0], added[0], added[1]}) > 0 {
		t.Fatalf("context key: %q", out)
	}
}

// TestEngineDiffEndAtWindowStart: a "+-----END" line of an added key does
// not close a removed (or context) key around it even when a continuation
// window starts between the "+", which is base64, and the END marker. The
// sweep moves the key across every alignment of the 4 KiB window grid.
func TestEngineDiffEndAtWindowStart(t *testing.T) {
	body := blockTestLines(30, 400)
	tail := blockTestLines(31, 100)
	e := mustEngine(t, Config{})
	for _, trigger := range []string{"-", " "} {
		for pad := 0; pad < 4400; pad++ {
			var b strings.Builder
			b.WriteString(strings.Repeat("x", pad) + "\n@@ -1,500 +1,1 @@\n" + trigger + "-----BEGIN RSA PRIVATE KEY-----\n")
			for _, l := range body {
				b.WriteString("-" + l + "\n")
			}
			b.WriteString("+-----END RSA PRIVATE KEY-----\n")
			for _, l := range tail {
				b.WriteString("-" + l + "\n")
			}
			b.WriteString("------END RSA PRIVATE KEY-----\n")
			out, _ := redactAll(t, e, strings.NewReader(b.String()))
			if n := blockLeaks(out, append(append([]string{}, body...), tail...)); n > 0 {
				t.Fatalf("trigger %q, pad %d: %d key lines survive", trigger, pad, n)
			}
		}
	}
}

// TestEngineArmorHeaders: RFC 4880 armor headers with bytes the body
// grammar refuses do not hide the key.
func TestEngineArmorHeaders(t *testing.T) {
	for _, size := range []int{20, 640} {
		body := blockTestLines(28, size)
		for _, headers := range []string{
			"Version: GnuPG v1.4.11 (GNU/Linux)\n",
			"Version: GnuPG/MacGPG2 v2\nComment: GPGTools - https://gpgtools.org\n",
			"Comment: Alice <alice@example.com>\n",
		} {
			key := "x\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + headers + "\n" + strings.Join(body, "\n") +
				"\n=Tx4q\n-----END PGP PRIVATE KEY BLOCK-----\nafter\n"
			t.Run(fmt.Sprintf("%d lines, %q", size, headers), func(t *testing.T) {
				assertBlockMasked(t, key, body)
				assertBlockMasked(t, `{"key":"`+strings.ReplaceAll(key, "\n", `\n`)+`"}`+"\n", body)
				assertBlockMasked(t, blockTestDiff("+", key), body)
			})
		}
	}

	body := blockTestLines(32, 300)
	armored := func(headers []string, indent, marker string) string {
		lines := append([]string{"-----BEGIN PGP PRIVATE KEY BLOCK-----"}, headers...)
		lines = append(append(append(lines, ""), body...), "=Tx4q", "-----END PGP PRIVATE KEY BLOCK-----")
		for i := range lines {
			lines[i] = marker + indent + lines[i]
		}
		return strings.Join(lines, "\n") + "\n"
	}
	version := "Version: GnuPG v1.4.11 (GNU/Linux)"
	many := []string{version}
	for i := 1; i < 32; i++ {
		many = append(many, fmt.Sprintf("Comment: line %d (see https://example.org/x.y)", i))
	}
	quoted := armored([]string{`Comment: "Alice Smith" <alice@example.com>`}, "", "")
	for name, input := range map[string]string{
		"yaml indented":              "k: |\n" + armored([]string{version}, "  ", "") + "other: 1\n",
		"yaml indented on + lines":   "@@ -0,0 +1,400 @@\n+k: |\n" + armored([]string{version}, "  ", "+"),
		"quoted raw value":           quoted,
		"quoted value, JSON-escaped": `{"k":"` + strings.ReplaceAll(strings.ReplaceAll(quoted, `"`, `\"`), "\n", `\n`) + `"}` + "\n",
		"tab after the colon":        armored([]string{"Comment:\tAlice (work)"}, "", ""),
		"no space after the colon":   armored([]string{"Comment:Alice (work)"}, "", ""),
		"32 headers":                 armored(many, "", ""),
		"1 KiB value":                armored([]string{"Comment: " + strings.Repeat("a.", 512)}, "", ""),
	} {
		t.Run(name, func(t *testing.T) { assertBlockMasked(t, input, body) })
	}
}
