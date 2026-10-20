package goredact

// Engine-level tests for block rules (the built-in private-key rules): a
// key is masked to its end marker however long it is, across reads,
// chunk sizes and mask strategies, in plain text and in diff patches,
// with bounded memory and linear work.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"runtime"
	"strings"
	"testing"

	"github.com/baum-ai/goredact/internal/rules"
)

// blockTestLines returns n synthetic 64-column base64 lines (invented data,
// not key material).
func blockTestLines(seed int64, n int) []string {
	rng := rand.New(rand.NewSource(seed))
	lines := make([]string, n)
	for i := range lines {
		lines[i] = pemTestSynthLine(rng, 64)
	}
	return lines
}

// blockTestPGP is an armored PGP private key block of at least size bytes,
// without a trailing newline.
func blockTestPGP(seed int64, size int) (block string, body []string) {
	body = blockTestLines(seed, size/65+1)
	return "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + strings.Join(body, "\n") +
		"\n=Tx4q\n-----END PGP PRIVATE KEY BLOCK-----", body
}

// blockTestPPK is a PuTTY key file with n private lines; it returns the
// file, its public lines and its private lines.
func blockTestPPK(seed int64, n int) (ppk string, pub, priv []string) {
	lines := blockTestLines(seed, n+2)
	pub, priv = lines[:2], lines[2:]
	ppk = "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: synthetic\n" +
		"Public-Lines: 2\n" + strings.Join(pub, "\n") + "\n" +
		fmt.Sprintf("Private-Lines: %d\n", n) + strings.Join(priv, "\n") + "\n" +
		"Private-MAC: 0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
	return ppk, pub, priv
}

// blockTestDiff prefixes every line of s with marker, as a unified diff
// hunk does.
func blockTestDiff(marker, s string) string {
	s = strings.TrimSuffix(s, "\n")
	return marker + strings.ReplaceAll(s, "\n", "\n"+marker) + "\n"
}

// blockTestReadSizes are the read patterns every block test streams with.
func blockTestReadSizes() map[string]func(int) int {
	rng := rand.New(rand.NewSource(11))
	return map[string]func(int) int{
		"one read":     func(int) int { return 1 << 30 },
		"4 KiB reads":  func(int) int { return 4096 },
		"random reads": func(int) int { return 1 + rng.Intn(9000) },
		"7-byte reads": func(int) int { return 7 },
	}
}

func assertNoLineSurvives(t *testing.T, where, out string, lines []string) {
	t.Helper()
	for _, line := range lines {
		if strings.Contains(out, line[8:40]) {
			t.Fatalf("%s: key material survived redaction", where)
		}
	}
}

// TestEngineLongPGPKeyFullyMasked is the acceptance case: a 40 KiB PGP
// private key, well past the rule's 16 KiB lookahead, is masked from BEGIN
// through END as one finding, however the input is read and buffered.
func TestEngineLongPGPKeyFullyMasked(t *testing.T) {
	block, body := blockTestPGP(1, 40<<10)
	prefix := pemTestFiller(3000)
	suffix := "\nkey ends here, and so does the redaction\n"
	input := prefix + block + suffix
	minChunk := mustEngine(t, Config{}).rules.MinChunkSize()

	for _, chunk := range []int{0, minChunk, 64 << 10} {
		for name, sizes := range blockTestReadSizes() {
			where := fmt.Sprintf("chunk %d, %s", chunk, name)
			e := mustEngine(t, Config{ChunkSize: chunk})
			out, stats := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: sizes})
			if want := prefix + DefaultMarker + suffix; out != want {
				t.Fatalf("%s: output diverges (len got %d, want %d)", where, len(out), len(want))
			}
			if stats.Findings != 1 || stats.ByRule["pem-private-key"] != 1 || stats.RedactedBytes != int64(len(block)) {
				t.Fatalf("%s: stats %+v, want one pem-private-key finding of %d bytes", where, stats, len(block))
			}
		}
	}

	// Per-byte strategies keep the length and mask every byte of the block.
	for _, strategy := range []MaskStrategy{MaskLengthPreserving, MaskFormatPreserving} {
		var first string
		for name, sizes := range blockTestReadSizes() {
			out, _ := redactAll(t, mustEngine(t, Config{MaskStrategy: strategy}), &chunkedReader{data: []byte(input), sizes: sizes})
			where := fmt.Sprintf("%v, %s", strategy, name)
			if len(out) != len(input) || !strings.HasPrefix(out, prefix) || !strings.HasSuffix(out, suffix) {
				t.Fatalf("%s: text around the block changed", where)
			}
			assertNoLineSurvives(t, where, out, body)
			if strings.Contains(out, "PRIVATE KEY") {
				t.Fatalf("%s: the armor header survived", where)
			}
			if first == "" {
				first = out
			} else if out != first {
				t.Fatalf("%s: output depends on how the input is read", where)
			}
		}
	}
}

// TestEngineUnterminatedBlockMasksToEndOfInput: with no END marker, the
// block is masked through its last body byte at the end of input, however
// long it is.
func TestEngineUnterminatedBlockMasksToEndOfInput(t *testing.T) {
	block, body := blockTestPGP(2, 100<<10)
	open := block[:strings.Index(block, "\n=")]
	prefix := "log line before\n"
	for _, tail := range []string{"", "\n"} {
		input := prefix + open + tail
		for name, sizes := range blockTestReadSizes() {
			out, stats := redactAll(t, mustEngine(t, Config{}), &chunkedReader{data: []byte(input), sizes: sizes})
			if want := prefix + DefaultMarker + tail; out != want {
				t.Fatalf("tail %q, %s: output %q..., want %q", tail, name, out[:min(len(out), 80)], want)
			}
			if stats.RedactedBytes != int64(len(open)) {
				t.Fatalf("tail %q, %s: RedactedBytes %d, want %d", tail, name, stats.RedactedBytes, len(open))
			}
		}
		out, _ := redactAll(t, mustEngine(t, Config{MaskStrategy: MaskFormatPreserving}), strings.NewReader(input))
		assertNoLineSurvives(t, "format-preserving", out, body)
	}
}

// TestEngineKeysInDiffPatch is the acceptance case for patches: a PuTTY
// key added on "+" lines is detected and only its private section masked,
// and a long PEM key and a long PuTTY section on diff lines are masked to
// their ends.
func TestEngineKeysInDiffPatch(t *testing.T) {
	ppk, pub, priv := blockTestPPK(3, 4)
	bigPPK, bigPub, bigPriv := blockTestPPK(4, 600) // ~39 KiB private section
	pgp, pgpBody := blockTestPGP(5, 40<<10)
	patch := "diff --git a/id.ppk b/id.ppk\nnew file mode 100644\n--- /dev/null\n+++ b/id.ppk\n" +
		"@@ -0,0 +1,11 @@\n" + blockTestDiff("+", ppk) +
		"diff --git a/big.ppk b/big.ppk\n@@ -0,0 +1,607 @@\n" + blockTestDiff("+", bigPPK) +
		"diff --git a/key.asc b/key.asc\n@@ -1,3 +1,700 @@\n context line\n" + blockTestDiff("+", pgp) + " last context line\n"

	for name, sizes := range blockTestReadSizes() {
		for _, strategy := range []MaskStrategy{MaskFixedMarker, MaskFormatPreserving} {
			where := fmt.Sprintf("%v, %s", strategy, name)
			out, stats := redactAll(t, mustEngine(t, Config{MaskStrategy: strategy}), &chunkedReader{data: []byte(patch), sizes: sizes})
			assertNoLineSurvives(t, where+" ppk", out, priv)
			assertNoLineSurvives(t, where+" big ppk", out, bigPriv)
			assertNoLineSurvives(t, where+" pgp", out, pgpBody)
			for _, line := range append(append([]string{}, pub...), bigPub...) {
				if !strings.Contains(out, "+"+line+"\n") {
					t.Fatalf("%s: a public PPK line was masked", where)
				}
			}
			for _, kept := range []string{"+Private-MAC: 0a1b", "+Public-Lines: 2", " last context line\n", "diff --git a/key.asc"} {
				if !strings.Contains(out, kept) {
					t.Fatalf("%s: %q was masked", where, kept)
				}
			}
			if stats.ByRule["putty-private-key"] != 2 || stats.ByRule["pem-private-key"] != 1 {
				t.Fatalf("%s: findings %v, want 2 putty-private-key and 1 pem-private-key", where, stats.ByRule)
			}
		}
	}
}

// TestEngineBlockOutputIndependentOfBuffering streams a mix of long keys,
// nested markers and an unterminated tail with assorted chunk sizes and
// reads: the output must not depend on either.
func TestEngineBlockOutputIndependentOfBuffering(t *testing.T) {
	pgp, _ := blockTestPGP(6, 50<<10)
	ppk, _, _ := blockTestPPK(7, 400)
	escaped := strings.ReplaceAll(pemTestSynthKey("OPENSSH PRIVATE KEY", 8, 30<<10), "\n", `\n`)
	nested := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("-----BEGIN RSA PRIVATE KEY-----\n"+strings.Join(blockTestLines(9, 3), "\n")+"\n", 200) +
		"-----END RSA PRIVATE KEY-----\n"
	open, _ := blockTestPGP(10, 30<<10)
	input := "start " + testGHToken + "\n" + pgp + "\n" + ppk + `{"key":"` + escaped + `"}` + "\n" +
		blockTestDiff("+", pgp) + nested + "middle " + testSlackToken + "\n" + open[:strings.Index(open, "\n=")]

	minChunk := mustEngine(t, Config{}).rules.MinChunkSize()
	var want string
	for _, chunk := range []int{0, minChunk, minChunk + 4097, 100 << 10} {
		for name, sizes := range blockTestReadSizes() {
			out, _ := redactAll(t, mustEngine(t, Config{ChunkSize: chunk}), &chunkedReader{data: []byte(input), sizes: sizes})
			if want == "" {
				want = out
				if strings.Count(out, DefaultMarker) != 8 {
					t.Fatalf("got %d markers, want 8 (two tokens, five keys, one unterminated key)", strings.Count(out, DefaultMarker))
				}
				continue
			}
			if out != want {
				t.Fatalf("chunk %d, %s: output differs from the reference", chunk, name)
			}
		}
	}
}

// countingBlocks wraps the engine's block rules to count the bytes their
// Begin and Extend functions are handed.
func countingBlocks(e *Engine) (beginBytes, extendBytes *int64) {
	beginBytes, extendBytes = new(int64), new(int64)
	for i := range e.rules.Rules {
		r := &e.rules.Rules[i]
		if r.Block == nil {
			continue
		}
		inner := *r.Block
		r.Block = &rules.Block{
			Begin: func(window []byte, ts, te int, final bool) (int, int, uint64, bool, bool) {
				*beginBytes += int64(len(window))
				return inner.Begin(window, ts, te, final)
			},
			Extend: func(window []byte, state uint64, final bool) (int, uint64, bool) {
				*extendBytes += int64(len(window))
				return inner.Extend(window, state, final)
			},
		}
	}
	return beginBytes, extendBytes
}

// TestEngineBlockWorkIsLinear checks the work bound: a long block costs
// about one pass of Extend over its length, and BEGIN markers nested in an
// open block do not start chains of their own, so they cannot multiply it.
func TestEngineBlockWorkIsLinear(t *testing.T) {
	lines := blockTestLines(12, 64)
	var nested strings.Builder
	nested.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	for nested.Len() < 4<<20 {
		nested.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
		for _, line := range lines[:4] {
			nested.WriteString(line + "\n")
		}
	}
	nested.WriteString("-----END RSA PRIVATE KEY-----\n")
	pgp, _ := blockTestPGP(13, 4<<20)

	rng := rand.New(rand.NewSource(15))
	reads := map[string]func(int) int{
		"large reads":  func(int) int { return 1 << 30 },
		"4 KiB reads":  func(int) int { return 4096 },
		"random reads": func(int) int { return 1 + rng.Intn(20000) },
	}
	for name, input := range map[string]string{"long key": pgp, "nested markers": nested.String()} {
		for readName, sizes := range reads {
			where := name + ", " + readName
			e := mustEngine(t, Config{})
			beginBytes, extendBytes := countingBlocks(e)
			out, stats := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: sizes})
			if strings.Count(out, DefaultMarker) != 1 || strings.Contains(out, lines[0]) {
				t.Fatalf("%s: want one marker for the whole block, got %d", where, strings.Count(out, DefaultMarker))
			}
			// Extend reads each byte about once (windows overlap by at most
			// the resume reserve); each trigger's Begin reads one window, as
			// any rule's validator does.
			if limit := int64(len(input)) * 11 / 10; *extendBytes > limit {
				t.Fatalf("%s: Extend read %d bytes for a %d-byte input", where, *extendBytes, len(input))
			}
			if limit := (stats.Candidates + 1) * int64(e.window); *beginBytes > limit {
				t.Fatalf("%s: Begin read %d bytes for %d candidates", where, *beginBytes, stats.Candidates)
			}
		}
	}
}

// blockStreamReader serves a PEM block of total bytes generated on the fly:
// the header, 64-column body lines cycled from lines, and the footer.
type blockStreamReader struct {
	head, body, foot []byte
	total, off       int64
}

func (r *blockStreamReader) Read(p []byte) (int, error) {
	if r.off >= r.total {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.off < r.total {
		var b byte
		switch footStart := r.total - int64(len(r.foot)); {
		case r.off < int64(len(r.head)):
			b = r.head[r.off]
		case r.off >= footStart:
			b = r.foot[r.off-footStart]
		default:
			b = r.body[(r.off-int64(len(r.head)))%int64(len(r.body))]
		}
		p[n] = b
		n++
		r.off++
	}
	return n, nil
}

// TestEngineHugeBlockBoundedMemory masks a 64 MiB key block with the
// smallest chunk size: the block outgrows the buffer many times over, the
// engine discards its interior, and the heap stays flat.
func TestEngineHugeBlockBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("64 MiB block skipped in -short mode")
	}
	lines := blockTestLines(14, 16)
	newReader := func() *blockStreamReader {
		return &blockStreamReader{
			head:  []byte("before\n-----BEGIN RSA PRIVATE KEY-----\n"),
			body:  []byte(strings.Join(lines, "\n") + "\n"),
			foot:  []byte("-----END RSA PRIVATE KEY-----\nafter\n"),
			total: 64 << 20,
		}
	}
	e := mustEngine(t, Config{})
	e = mustEngine(t, Config{ChunkSize: e.rules.MinChunkSize()})
	if _, err := e.Redact(context.Background(), io.Discard, newReader()); err != nil {
		t.Fatalf("warm-up Redact: %v", err)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var out bytes.Buffer
	stats, err := e.Redact(context.Background(), &out, newReader())
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if got, want := out.String(), "before\n"+DefaultMarker+"\nafter\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if stats.Findings != 1 {
		t.Fatalf("findings = %d, want 1", stats.Findings)
	}
	if delta := int64(after.HeapAlloc) - int64(before.HeapAlloc); delta > 8<<20 {
		t.Errorf("HeapAlloc grew by %d bytes masking a 64 MiB block; want <= 8 MiB", delta)
	}
}
