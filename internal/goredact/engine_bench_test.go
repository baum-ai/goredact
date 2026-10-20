package goredact

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"testing"
)

// benchQuietInput builds size bytes of realistic log text containing no
// trigger literals at all: the automaton stays cold and the emit path
// dominates alongside the scan.
func benchQuietInput(size int) []byte {
	line := []byte("2026-08-14T12:00:00Z info http request served remote=10.0.0.7 method=GET path=/api/v1/items status=200 bytes=5120 dur=2.31ms\n")
	buf := make([]byte, 0, size+len(line))
	for len(buf) < size {
		buf = append(buf, line...)
	}
	return buf[:size]
}

// benchNoisyInput salts quiet text with trigger literals — some confirming
// as real findings, most rejected by validators — roughly every 2 KiB.
func benchNoisyInput(size int) []byte {
	rng := rand.New(rand.NewSource(1))
	base := benchQuietInput(size)
	buf := make([]byte, 0, size+size/16)
	salts := []string{
		" " + testGHToken + " ",
		" " + testSlackToken + " ",
		" ghp_notreallyatoken ",
		" xoxb-12-34 ",
		" ghp_ ",
	}
	for off := 0; off < len(base); {
		n := 1024 + rng.Intn(2048)
		if off+n > len(base) {
			n = len(base) - off
		}
		buf = append(buf, base[off:off+n]...)
		buf = append(buf, salts[rng.Intn(len(salts))]...)
		off += n
	}
	return buf
}

func benchRedact(b *testing.B, data []byte) {
	e, err := New(Config{})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	rd := bytes.NewReader(data)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rd.Reset(data)
		if _, err := e.Redact(ctx, io.Discard, rd); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedactQuiet(b *testing.B) {
	benchRedact(b, benchQuietInput(4<<20))
}

func BenchmarkRedactNoisy(b *testing.B) {
	benchRedact(b, benchNoisyInput(4<<20))
}

// benchKeyBlockInput interleaves quiet log text with PEM private-key blocks
// of keySize bytes, so most of the input lies inside blocks that run past
// the rule's lookahead and are followed window by window.
func benchKeyBlockInput(size, keySize int) []byte {
	rng := rand.New(rand.NewSource(2))
	quiet := benchQuietInput(4 << 10)
	buf := make([]byte, 0, size+keySize)
	for len(buf) < size {
		buf = append(buf, quiet...)
		buf = append(buf, "-----BEGIN RSA PRIVATE KEY-----\n"...)
		for body := 0; body < keySize; body += 65 {
			buf = append(buf, pemTestSynthLine(rng, 64)...)
			buf = append(buf, '\n')
		}
		buf = append(buf, "-----END RSA PRIVATE KEY-----\n"...)
	}
	return buf
}

func BenchmarkRedactLongKeyBlocks(b *testing.B) {
	benchRedact(b, benchKeyBlockInput(4<<20, 64<<10))
}
