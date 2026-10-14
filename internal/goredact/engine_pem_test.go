package goredact

// Engine-level tests for the private-key validators, wired through
// Config.CustomRules (the identical engine path the generated built-in rules
// take). These tests import the validators directly to exercise that path.

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/baum-ai/goredact/internal/rules/validators"
)

// pemTestConfig wires validators.PEMPrivateKey as a custom rule. Builtins
// are restricted to a stable rule so the byte-exact output assertions do not
// receive duplicate findings from an equivalent built-in validator.
func pemTestConfig() Config {
	return Config{
		EnableRules: []string{"github-pat"},
		CustomRules: []CustomRule{{
			ID:           "test-pem",
			Triggers:     []string{"-----BEGIN "},
			Confidence:   ConfidenceHigh,
			MaxLookahead: 16384,
			Validate:     validators.PEMPrivateKey,
		}},
	}
}

// pemTestSynthLine returns n synthetic random-looking base64 bytes. This is
// invented data, not real key material.
func pemTestSynthLine(rng *rand.Rand, n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

// pemTestSynthKey builds a synthetic PEM block of at least minBodySize
// bytes of body, with 64-char base64 lines, ending in "-----END <label>-----\n".
func pemTestSynthKey(label string, seed int64, minBodySize int) string {
	rng := rand.New(rand.NewSource(seed))
	var sb strings.Builder
	sb.WriteString("-----BEGIN " + label + "-----\n")
	for body := 0; body < minBodySize; body += 65 {
		sb.WriteString(pemTestSynthLine(rng, 64))
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END " + label + "-----\n")
	return sb.String()
}

// pemTestExpect is the exact expected output for prefix+pem+suffix: the
// validator's span runs from the BEGIN trigger through the END marker's
// closing dashes, so the block's real trailing newline survives.
func pemTestExpect(prefix, pem, suffix string) string {
	if !strings.HasSuffix(pem, "-----\n") {
		panic("pemTestExpect: pem must end with the END marker and a newline")
	}
	return prefix + DefaultMarker + "\n" + suffix
}

func pemTestFiller(size int) string {
	var sb strings.Builder
	for i := 0; sb.Len() < size; i++ {
		fmt.Fprintf(&sb, "log entry %d: routine payload without any secret material\n", i)
	}
	return sb.String()
}

// TestEnginePEMFullRedaction512ByteReads embeds an 8 KiB synthetic PEM
// after ~300 KiB of filler (forcing buffer compaction across the default
// 256 KiB chunk) and streams it in fixed 512-byte reads: the whole block,
// every body byte included, must collapse to a single marker.
func TestEnginePEMFullRedaction512ByteReads(t *testing.T) {
	pem := pemTestSynthKey("OPENSSH PRIVATE KEY", 1, 8*1024)
	prefix := pemTestFiller(300 * 1024)
	suffix := "tail after the key\n"
	input := prefix + pem + suffix
	want := pemTestExpect(prefix, pem, suffix)

	e := mustEngine(t, pemTestConfig())
	out, stats := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: func(int) int { return 512 }})
	if out != want {
		t.Fatalf("512-byte reads: output diverges (len got %d, want %d)", len(out), len(want))
	}
	if stats.ByRule["test-pem"] != 1 || stats.Findings != 1 {
		t.Errorf("stats = %+v, want exactly one test-pem finding", stats)
	}
	if stats.RedactedBytes != int64(len(pem)-1) {
		t.Errorf("RedactedBytes = %d, want %d", stats.RedactedBytes, len(pem)-1)
	}
}

// TestEnginePEMFullRedactionRandomSmallReads streams the same shape with
// seeded random 1-7 byte reads.
func TestEnginePEMFullRedactionRandomSmallReads(t *testing.T) {
	pem := pemTestSynthKey("RSA PRIVATE KEY", 2, 8*1024)
	prefix := pemTestFiller(2 * 1024)
	suffix := "after\n"
	input := prefix + pem + suffix
	want := pemTestExpect(prefix, pem, suffix)

	rng := rand.New(rand.NewSource(7))
	e := mustEngine(t, pemTestConfig())
	out, stats := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: func(int) int { return 1 + rng.Intn(7) }})
	if out != want {
		t.Fatalf("random small reads: output diverges (len got %d, want %d)", len(out), len(want))
	}
	if stats.ByRule["test-pem"] != 1 {
		t.Errorf("ByRule = %v, want one test-pem finding", stats.ByRule)
	}
}

// TestEnginePEMJSONEscaped redacts a JSON-escaped single-line key inside a
// structured log line; the span consumes the trailing `\n` escape so the
// closing quote hugs the marker.
func TestEnginePEMJSONEscaped(t *testing.T) {
	raw := pemTestSynthKey("OPENSSH PRIVATE KEY", 3, 200)
	escaped := strings.ReplaceAll(raw, "\n", `\n`)
	input := `{"level":"info","key":"` + escaped + `"}` + "\n"
	want := `{"level":"info","key":"` + DefaultMarker + `"}` + "\n"

	e := mustEngine(t, pemTestConfig())
	for _, size := range []int{1 << 20, 3} {
		size := size
		out, _ := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: func(int) int { return size }})
		if out != want {
			t.Fatalf("read size %d: output = %q, want %q", size, out, want)
		}
	}
}

// TestEnginePEMSplitInsideMarkers splits the stream into exactly two reads
// at every offset within the BEGIN marker region and within the END marker
// region: output must be identical regardless of where the boundary falls.
func TestEnginePEMSplitInsideMarkers(t *testing.T) {
	pem := pemTestSynthKey("EC PRIVATE KEY", 4, 180)
	prefix := "pre "
	suffix := " post"
	input := prefix + pem + suffix
	want := pemTestExpect(prefix, pem, suffix)

	beginStart := len(prefix)
	beginEnd := beginStart + len("-----BEGIN EC PRIVATE KEY-----\n")
	endStart := len(prefix) + strings.Index(pem, "-----END ")
	endEnd := endStart + len("-----END EC PRIVATE KEY-----\n")

	e := mustEngine(t, pemTestConfig())
	trySplit := func(split int) {
		t.Helper()
		src := io.MultiReader(strings.NewReader(input[:split]), strings.NewReader(input[split:]))
		out, stats := redactAll(t, e, src)
		if out != want {
			t.Fatalf("split at %d: output = %q, want %q", split, out, want)
		}
		if stats.Findings != 1 {
			t.Fatalf("split at %d: findings = %d, want 1", split, stats.Findings)
		}
	}
	for split := beginStart - 1; split <= beginEnd+1; split++ {
		trySplit(split)
	}
	for split := endStart - 1; split <= endEnd+1 && split <= len(input); split++ {
		trySplit(split)
	}
}

// TestEnginePEMTruncatedAtEOF cuts the stream in the middle of the key body
// with no END marker: the truncation fail-safe must redact from BEGIN
// through the last body byte at EOF.
func TestEnginePEMTruncatedAtEOF(t *testing.T) {
	full := pemTestSynthKey("PRIVATE KEY", 5, 400)
	headerAndBody := full[:strings.Index(full, "-----END ")]
	truncated := strings.TrimRight(headerAndBody, "\n")
	truncated = truncated[:len(truncated)-13] // cut mid body line
	prefix := "before the key\n"
	input := prefix + truncated
	want := prefix + DefaultMarker

	e := mustEngine(t, pemTestConfig())
	for _, size := range []int{1 << 20, 512, 5} {
		size := size
		out, stats := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: func(int) int { return size }})
		if out != want {
			t.Fatalf("read size %d: output = %q, want %q", size, out, want)
		}
		if stats.RedactedBytes != int64(len(truncated)) {
			t.Fatalf("read size %d: RedactedBytes = %d, want %d (BEGIN through last body byte)", size, stats.RedactedBytes, len(truncated))
		}
	}
}

// TestEnginePEMTriggerFlood streams 100 MB (10 MB with -short) of prose
// containing "-----BEGIN " triggers with no key bodies: nothing may be
// redacted and the scan must stay far away from the pathological
// O(triggers x lookahead-window) regime.
func TestEnginePEMTriggerFlood(t *testing.T) {
	unit := "-----BEGIN transaction 4021 for the billing batch job\n" +
		"-----BEGIN PRIVATE KEY----- appears here only as prose, then. \n"
	var block []byte
	for len(block) < 64*1024 {
		block = append(block, unit...)
	}
	total := int64(100 << 20)
	if testing.Short() {
		total = 10 << 20
	}

	e := mustEngine(t, pemTestConfig())
	start := time.Now()
	stats, err := e.Redact(context.Background(), io.Discard, &repeatReader{block: block, total: total})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	elapsed := time.Since(start)
	if stats.Findings != 0 || stats.RedactedBytes != 0 {
		t.Fatalf("flood produced findings: %+v", stats)
	}
	if stats.BytesRead != total || stats.BytesWritten != total {
		t.Fatalf("BytesRead/Written = %d/%d, want %d", stats.BytesRead, stats.BytesWritten, total)
	}
	t.Logf("flood: %d MiB in %v", total>>20, elapsed)
	if elapsed > 2*time.Minute {
		t.Fatalf("flood took %v for %d bytes; pathological per-trigger scanning suspected", elapsed, total)
	}
}

// TestEnginePuTTYPrivateKeyCustomRule wires validators.PuTTYPrivateKey and
// checks that only the Private-Lines section of a PPK file is redacted (the
// public portion survives).
func TestEnginePuTTYPrivateKeyCustomRule(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	pub := pemTestSynthLine(rng, 64)
	priv1 := pemTestSynthLine(rng, 64)
	priv2 := pemTestSynthLine(rng, 64)
	ppk := "PuTTY-User-Key-File-2: ssh-rsa\n" +
		"Encryption: none\n" +
		"Comment: synthetic-engine-test\n" +
		"Public-Lines: 1\n" + pub + "\n" +
		"Private-Lines: 2\n" + priv1 + "\n" + priv2 + "\n" +
		"Private-MAC: 6f1c2b3a4d5e6f708192a3b4c5d6e7f8091a2b3c\n"
	input := "== ppk dump ==\n" + ppk

	secStart := strings.Index(input, "Private-Lines:")
	secEnd := strings.Index(input, "\nPrivate-MAC:")
	want := input[:secStart] + DefaultMarker + input[secEnd:]

	cfg := Config{
		EnableRules: []string{"github-pat"},
		CustomRules: []CustomRule{{
			ID:           "test-ppk",
			Triggers:     []string{"PuTTY-User-Key-File-"},
			Confidence:   ConfidenceHigh,
			MaxLookahead: 16384,
			Validate:     validators.PuTTYPrivateKey,
		}},
	}
	e := mustEngine(t, cfg)
	for _, size := range []int{1 << 20, 3} {
		size := size
		out, stats := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: func(int) int { return size }})
		if out != want {
			t.Fatalf("read size %d: output = %q, want %q", size, out, want)
		}
		if !strings.Contains(out, pub) {
			t.Errorf("read size %d: public line was redacted; span should cover only Private-Lines", size)
		}
		if strings.Contains(out, priv1) || strings.Contains(out, priv2) {
			t.Errorf("read size %d: private line survived redaction", size)
		}
		if stats.ByRule["test-ppk"] != 1 {
			t.Errorf("read size %d: ByRule = %v, want one test-ppk finding", size, stats.ByRule)
		}
	}
}
