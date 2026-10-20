package goredact

import (
	"bytes"
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
		in := blockFuzzInput(data)
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

		const lookbehind, lookahead = 2, 16384
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
	})
}
