package goredact

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/baum-ai/goredact/internal/rules/validators"
)

var blockFuzzLines = blockTestLines(77, 300)

// blockFuzzMax bounds a FuzzEngineBlocks input: several windows and chunks
// long, short enough that one execution (four engine runs and a whole-input
// scan per checked trigger) stays well inside the fuzzer's deadline.
const blockFuzzMax = 160 << 10

// blockFuzzTriggers bounds the triggers per rule whose whole-input span
// FuzzEngineBlocks checks, spread evenly over the input.
const blockFuzzTriggers = 48

// blockFuzzInput expands fuzz bytes into private-key-shaped text: BEGIN and
// END lines, PPK headers, runs of body lines, prose, separators, gaps and
// diff markers, so the engine sees nested, interleaved, unterminated and
// window-straddling blocks.
func blockFuzzInput(data []byte) []byte {
	var b bytes.Buffer
	li := 0
	line := func() string { li++; return blockFuzzLines[li%len(blockFuzzLines)] }
	for _, c := range data {
		switch c % 22 {
		case 0:
			b.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
		case 1:
			b.WriteString("-----BEGIN PGP PRIVATE KEY BLOCK-----\n")
		case 2:
			b.WriteString("-----END RSA PRIVATE KEY-----\n")
		case 3:
			b.WriteString(line() + "\n")
		case 4:
			for range 64 {
				b.WriteString(line() + "\n")
			}
		case 5:
			for range 256 {
				b.WriteString(line() + "\n")
			}
		case 6:
			b.WriteString("word ")
		case 7:
			b.WriteString("!")
		case 8:
			b.WriteString(strings.Repeat(" ", 100))
		case 9:
			b.WriteString(`\n`)
		case 10:
			b.WriteString("+")
		case 11:
			b.WriteString("PuTTY-User-Key-File-2: ssh-rsa\n")
		case 12:
			b.WriteString("Private-Lines: 3\n")
		case 13:
			b.WriteString("\n")
		case 14:
			b.WriteString(strings.Repeat("\n", 300))
		case 15:
			b.WriteString("Comment: a b c d e f g h i j\n")
		case 16:
			b.WriteString("Private-Lines: 400\n")
		case 17:
			b.WriteString("-")
		case 18:
			b.WriteString(" ")
		case 19:
			b.WriteString("+" + line() + "\n")
		case 20:
			b.WriteString("+Private-Lines: 300\n")
		case 21:
			b.WriteString(line())
		}
		if b.Len() > blockFuzzMax {
			break
		}
	}
	return b.Bytes()
}

// FuzzEngineBlocks checks the engine's block rules end to end: the output
// does not depend on chunk or read sizes, and every key a trigger window
// confirms is masked at least as far as one scan of the whole input from
// that trigger reaches.
func FuzzEngineBlocks(f *testing.F) {
	f.Add([]byte{0, 5, 5, 1, 15, 15, 13, 5, 5, 2})
	f.Add([]byte{0, 5, 5, 1, 14, 5, 5, 5, 2})
	f.Add([]byte{11, 13, 12, 3, 3, 3, 16, 5, 5})
	f.Add([]byte{10, 11, 10, 20, 19, 19, 19})
	f.Add([]byte("7&17&1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		checkEngineBlocks(t, blockFuzzInput(data))
	})
}

// FuzzEngineKeyShapes runs FuzzEngineBlocks' checks on key-shaped text in
// the shapes keys take in logs and sources: every line behind a prefix (a
// quote, a comment, a line number, an indentation), each line a string
// literal concatenated with the next, the whole JSON-escaped as PHP and
// .NET encoders write it, and hunk headers between lines.
func FuzzEngineKeyShapes(f *testing.F) {
	f.Add([]byte{0, 5, 5, 2}, uint8(1))
	f.Add([]byte{1, 15, 5, 5, 2}, uint8(3|1<<3))
	f.Add([]byte{11, 13, 12, 5, 5}, uint8(2|2<<3))
	f.Add([]byte{0, 4, 4, 4, 2}, uint8(4|1<<6))
	f.Add([]byte{10, 11, 10, 20, 19, 19, 19}, uint8(5|3<<3|1<<6))
	f.Add([]byte{11, 13, 12, 3, 3, 3, 3}, uint8(6|1<<5))
	f.Fuzz(func(t *testing.T, data []byte, shape uint8) {
		checkEngineBlocks(t, keyShape(blockFuzzInput(data), shape))
	})
}

// keyShape reshapes text: bits 0-2 pick a per-line prefix, bits 3-4 an
// escaping, bit 5 a string-literal concatenation of the lines, bit 6 a hunk
// header after every 7th line.
func keyShape(text []byte, shape uint8) []byte {
	prefixes := []func(int) string{
		func(int) string { return "" },
		func(int) string { return "> " },
		func(int) string { return "> > " },
		func(int) string { return "# " },
		func(i int) string { return fmt.Sprintf("%6d\u2192", i+1) },
		func(i int) string { return fmt.Sprintf("%d\t", i+1) },
		func(int) string { return "    " },
		func(int) string { return "\t\"" },
	}
	lines := strings.Split(string(text), "\n")
	var b strings.Builder
	for i, line := range lines {
		b.WriteString(prefixes[shape&7](i))
		b.WriteString(line)
		if i == len(lines)-1 {
			break
		}
		if shape&(1<<5) != 0 {
			b.WriteString(`\n" +`)
		}
		b.WriteString("\n")
		if shape&(1<<6) != 0 && i%7 == 6 {
			fmt.Fprintf(&b, "@@ -%d,7 +%d,7 @@ %s\n", i, i, blockFuzzLines[i%len(blockFuzzLines)][:20])
		}
	}
	out := b.String()
	switch shape >> 3 & 3 {
	case 1: // PHP json_encode
		out = strings.NewReplacer("\\", `\\`, `"`, `\"`, "/", `\/`, "\n", `\n`).Replace(out)
	case 2: // .NET System.Text.Json
		out = strings.NewReplacer("\\", `\\`, `"`, `\u0022`, "+", `\u002B`, "\n", `\n`).Replace(out)
	case 3: // JSON inside JSON
		out = strings.NewReplacer("\\", `\\`, `"`, `\"`, "\n", `\n`).Replace(out)
		out = strings.NewReplacer("\\", `\\`, `"`, `\"`).Replace(out)
	}
	return []byte(out)
}

// checkEngineBlocks checks the engine's block rules end to end on in: the
// output does not depend on chunk or read sizes, and every key a trigger
// window confirms is masked at least as far as one scan of the whole input
// from that trigger reaches.
func checkEngineBlocks(t *testing.T, in []byte) {
	if len(in) == 0 {
		return
	}
	ref := mustEngine(t, Config{MaskStrategy: MaskLengthPreserving, ChunkSize: 4 << 20})
	refOut, _ := redactAll(t, ref, bytes.NewReader(in))
	if len(refOut) != len(in) {
		t.Fatalf("length changed")
	}
	rng := rand.New(rand.NewSource(int64(len(in))))
	small := mustEngine(t, Config{MaskStrategy: MaskLengthPreserving, ChunkSize: ref.rules.MinChunkSize()})
	smallOut, _ := redactAll(t, small, &chunkedReader{data: in, sizes: func(int) int { return 1 + rng.Intn(20000) }})
	if smallOut != refOut {
		i := 0
		for i < len(in) && smallOut[i] == refOut[i] {
			i++
		}
		t.Fatalf("output depends on chunking at byte %d", i)
	}

	lookbehind, lookahead := ref.rules.Rules[0].MaxLookbehind, 16384
	for _, r := range ref.rules.Rules {
		if r.ID == "pem-private-key" {
			lookbehind, lookahead = r.MaxLookbehind, r.MaxLookahead
		}
	}
	for _, rule := range []struct {
		trigger string
		begin   func([]byte, int, int, bool) (int, int, uint64, bool, bool)
	}{
		{"-----BEGIN ", validators.PEMPrivateKeyBegin},
		{"PuTTY-User-Key-File-", validators.PuTTYPrivateKeyBegin},
	} {
		var starts []int
		for off := 0; ; {
			i := bytes.Index(in[off:], []byte(rule.trigger))
			if i < 0 {
				break
			}
			starts = append(starts, off+i)
			off += i + len(rule.trigger)
		}
		step := max(1, (len(starts)+blockFuzzTriggers-1)/blockFuzzTriggers)
		for k := 0; k < len(starts); k += step {
			ts := starts[k]
			te := ts + len(rule.trigger)
			ws := max(ts-lookbehind, 0)
			wEnd := min(te+lookahead, len(in))
			if _, _, _, _, ok := rule.begin(in[ws:wEnd], ts-ws, te-ws, wEnd < te+lookahead); !ok {
				continue
			}
			s, e, _, _, ok := rule.begin(in[ws:], ts-ws, te-ws, true)
			if !ok {
				continue
			}
			for k := ws + s; k < ws+e; k++ {
				if refOut[k] != '*' {
					t.Fatalf("%q trigger at %d: whole-input span [%d,%d) but byte %d (%q) unmasked; input len %d",
						rule.trigger, ts, ws+s, ws+e, k, in[k], len(in))
				}
			}
		}
	}
}
