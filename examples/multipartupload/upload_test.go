package multipartupload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/baum-ai/goredact"
	"github.com/klauspost/compress/zstd"
)

type fakeClient struct {
	data                   bytes.Buffer
	begin, complete, abort int
	failPart, failComplete bool
	partSizes              []int64
}

func (c *fakeClient) Begin(context.Context) (Upload, error) {
	c.begin++
	return "upload", nil
}
func (c *fakeClient) UploadPart(_ context.Context, _ Upload, n int, body io.Reader, size int64) (Part, error) {
	if c.failPart {
		return nil, errors.New("remote failure")
	}
	got, err := io.Copy(&c.data, body)
	if err != nil || got != size {
		return nil, errors.New("body failure")
	}
	c.partSizes = append(c.partSizes, size)
	return n, nil
}
func (c *fakeClient) Complete(context.Context, Upload, []Part) error {
	c.complete++
	if c.failComplete {
		return errors.New("remote failure")
	}
	return nil
}
func (c *fakeClient) Abort(context.Context, Upload) error { c.abort++; return nil }

func TestRedactCompressUploadCompletesBoundedParts(t *testing.T) {
	engine, err := goredact.New(goredact.Config{Profile: goredact.ProfileFast})
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Repeat("prefix AWS_ACCESS_KEY_ID=AKIAUJZDEGXDNCF32EPF suffix\n", 200)
	client := new(fakeClient)
	var progress []Progress
	stats, err := RedactCompressUpload(context.Background(), client, engine, strings.NewReader(input), Options{
		PartSize: 257,
		Progress: func(p Progress) { progress = append(progress, p) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Findings != 200 || client.complete != 1 || client.abort != 0 {
		t.Fatalf("stats/completion = %+v, complete=%d abort=%d", stats, client.complete, client.abort)
	}
	for _, size := range client.partSizes {
		if size > 257 {
			t.Fatalf("part exceeded bound: %d", size)
		}
	}
	if len(progress) == 0 || progress[len(progress)-1].BytesRead != int64(len(input)) {
		t.Fatalf("progress = %+v", progress)
	}
	decoder, err := zstd.NewReader(bytes.NewReader(client.data.Bytes()), zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(decoder)
	decoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(decoded, []byte("AKIAUJZDEGXDNCF32EPF")) || !bytes.Contains(decoded, []byte("[REDACTED]")) {
		t.Fatal("uploaded object did not contain only redacted content")
	}
}

func TestRedactCompressUploadAbortsEveryFailure(t *testing.T) {
	tests := []struct {
		name   string
		client *fakeClient
		src    io.Reader
		cancel bool
	}{
		{name: "upload", client: &fakeClient{failPart: true}, src: strings.NewReader("data")},
		{name: "complete", client: &fakeClient{failComplete: true}, src: strings.NewReader("data")},
		{name: "scan", client: new(fakeClient), src: io.MultiReader(strings.NewReader("data"), errorReader{})},
		{name: "canceled", client: new(fakeClient), src: strings.NewReader("data"), cancel: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := goredact.New(goredact.Config{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if tt.cancel {
				cancel()
			} else {
				defer cancel()
			}
			_, err = RedactCompressUpload(ctx, tt.client, engine, tt.src, Options{PartSize: 4})
			if err == nil {
				t.Fatal("expected failure")
			}
			if tt.client.complete > 0 && tt.name != "complete" {
				t.Fatal("partial object completed")
			}
			if tt.client.abort != 1 {
				t.Fatalf("abort calls = %d", tt.client.abort)
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("source failure") }

// secretLeakingReader simulates a caller-supplied reader whose error text
// itself contains matched secret material, the scenario a mid-stream read
// failure must never propagate verbatim.
type secretLeakingReader struct{}

func (secretLeakingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed near token AKIAUJZDEGXDNCF32EPF")
}

func TestRedactCompressUploadSanitizesMidStreamReaderError(t *testing.T) {
	engine, err := goredact.New(goredact.Config{Profile: goredact.ProfileFast})
	if err != nil {
		t.Fatal(err)
	}
	client := new(fakeClient)
	src := io.MultiReader(strings.NewReader("data"), secretLeakingReader{})
	_, err = RedactCompressUpload(context.Background(), client, engine, src, Options{PartSize: 4})
	if err == nil {
		t.Fatal("expected failure")
	}
	if strings.Contains(err.Error(), "AKIAUJZDEGXDNCF32EPF") || strings.Contains(err.Error(), "read failed near token") {
		t.Fatalf("error leaked reader text: %v", err)
	}
}

// TestRedactCompressUploadMaxPartsBoundary pins the off-by-one fix: the
// part-count limit must only reject a part that actually carries data, not
// the trailing empty read at EOF that follows a stream whose compressed
// size exactly fills every allowed part. It uses the MaxParts override
// (rather than the package's real 10,000-part limit) so both directions
// are cheap and independent of zstd's compression ratio.
func TestRedactCompressUploadMaxPartsBoundary(t *testing.T) {
	engine, err := goredact.New(goredact.Config{Profile: goredact.ProfileFast})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("content fitting in exactly MaxParts succeeds", func(t *testing.T) {
		client := new(fakeClient)
		_, err := RedactCompressUpload(context.Background(), client, engine, strings.NewReader("small payload"), Options{PartSize: 1 << 20, MaxParts: 1})
		if err != nil {
			t.Fatalf("content fitting in exactly one part failed: %v", err)
		}
		if len(client.partSizes) != 1 {
			t.Fatalf("parts uploaded = %d, want 1", len(client.partSizes))
		}
	})

	t.Run("content exceeding MaxParts fails", func(t *testing.T) {
		client := new(fakeClient)
		input := strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz", 100)
		_, err := RedactCompressUpload(context.Background(), client, engine, strings.NewReader(input), Options{PartSize: 8, MaxParts: 1})
		if err == nil || !strings.Contains(err.Error(), "part limit exceeded") {
			t.Fatalf("error = %v, want part limit exceeded", err)
		}
	})
}
