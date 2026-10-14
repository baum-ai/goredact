// Package multipartupload demonstrates a bounded-memory redact, Zstandard,
// and multipart-upload pipeline. Plaintext flows directly from src into the
// redactor; it is never written to an intermediate file.
package multipartupload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/baum-ai/goredact"
	"github.com/klauspost/compress/zstd"
)

const (
	DefaultPartSize = 8 * 1024 * 1024
	// MaxParts matches the common S3 multipart limit and also bounds retained
	// part metadata independently of input size.
	MaxParts     = 10_000
	abortTimeout = 30 * time.Second
)

// Client is the storage-specific multipart adapter. Implementations should
// make UploadPart consume body before returning.
type Client interface {
	Begin(context.Context) (Upload, error)
	UploadPart(context.Context, Upload, int, io.Reader, int64) (Part, error)
	Complete(context.Context, Upload, []Part) error
	Abort(context.Context, Upload) error
}

// Upload and Part are opaque values owned by Client.
type Upload any
type Part any

// Progress contains counts only and is safe to log. It never contains input
// or matched bytes.
type Progress struct{ BytesRead int64 }

type Options struct {
	PartSize int
	Progress func(Progress)

	// MaxParts overrides the package-level MaxParts limit when non-zero.
	// Tests use this to exercise the part-count boundary without
	// depending on zstd's compression ratio to hit an exact byte count.
	MaxParts int
}

// RedactCompressUpload streams src through engine and a Zstandard writer into
// multipart upload. At most PartSize plus the engine's fixed buffers are held
// in memory. Any scan, compression, upload, completion, or cancellation error
// causes Abort to be attempted with a fresh bounded context.
func RedactCompressUpload(ctx context.Context, client Client, engine *goredact.Engine, src io.Reader, opts Options) (goredact.Stats, error) {
	if client == nil || engine == nil || src == nil {
		return goredact.Stats{}, errors.New("multipartupload: nil dependency")
	}
	partSize := opts.PartSize
	if partSize == 0 {
		partSize = DefaultPartSize
	}
	if partSize < 1 {
		return goredact.Stats{}, errors.New("multipartupload: invalid part size")
	}
	maxParts := opts.MaxParts
	if maxParts == 0 {
		maxParts = MaxParts
	}
	if maxParts < 1 {
		return goredact.Stats{}, errors.New("multipartupload: invalid part limit")
	}

	upload, err := client.Begin(ctx)
	if err != nil {
		return goredact.Stats{}, errors.New("multipartupload: begin failed")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	type result struct {
		stats goredact.Stats
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		reader := io.Reader(src)
		if opts.Progress != nil {
			reader = &countingReader{src: src, report: opts.Progress}
		}
		zw, zerr := zstd.NewWriter(pw, zstd.WithEncoderConcurrency(1))
		if zerr != nil {
			_ = pw.CloseWithError(zerr)
			resultCh <- result{err: zerr}
			return
		}
		stats, scanErr := engine.Redact(ctx, zw, reader)
		if scanErr == nil {
			scanErr = zw.Close()
			_ = pw.CloseWithError(scanErr)
		} else {
			// The scan failed; close the pipe first so the encoder's
			// flush cannot block on a consumer that stopped reading, then
			// still close the encoder to release its workspace
			// (klauspost/compress documents Close as required), keeping
			// the scan error as the reported failure.
			_ = pw.CloseWithError(scanErr)
			_ = zw.Close()
		}
		resultCh <- result{stats: stats, err: scanErr}
	}()

	abort := func() {
		abortCtx, abortCancel := context.WithTimeout(context.WithoutCancel(ctx), abortTimeout)
		defer abortCancel()
		_ = client.Abort(abortCtx, upload)
	}
	fail := func(uploadErr error) (goredact.Stats, error) {
		cancel()
		_ = pr.CloseWithError(uploadErr)
		res := <-resultCh
		abort()
		if uploadErr != nil {
			return res.stats, uploadErr
		}
		return res.stats, sanitizedScanError(res.err)
	}

	buf := make([]byte, partSize)
	parts := make([]Part, 0, 8)
	for number := 1; ; number++ {
		n, readErr := io.ReadFull(pr, buf)
		if n > 0 {
			if number > maxParts {
				return fail(errors.New("multipartupload: part limit exceeded"))
			}
			part, uploadErr := client.UploadPart(ctx, upload, number, bytes.NewReader(buf[:n]), int64(n))
			if uploadErr != nil {
				return fail(errors.New("multipartupload: part upload failed"))
			}
			parts = append(parts, part)
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			// readErr originates from the source reader (via the pipe),
			// not from this package: sanitize it the same way as every
			// other failure path below rather than propagating it, which
			// could embed matched secret material from a foreign Read
			// error string.
			return fail(nil)
		}
	}
	res := <-resultCh
	if res.err != nil {
		abort()
		return res.stats, sanitizedScanError(res.err)
	}
	if err := client.Complete(ctx, upload, parts); err != nil {
		abort()
		return res.stats, errors.New("multipartupload: completion failed")
	}
	return res.stats, nil
}

// sanitizedScanError converts an error surfaced by the engine, the
// compressor, or (via the pipe) the caller's own source reader into a
// fixed message, so free-text from a foreign reader's error (which may
// itself embed matched secret material — see docs/CLI_AND_UPLOAD.md's
// error-sanitization guidance) is never propagated to the caller. Context
// cancellation and deadline sentinels are preserved via %w so callers can
// still detect them with errors.Is.
func sanitizedScanError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("multipartupload: scan canceled: %w", context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("multipartupload: scan canceled: %w", context.DeadlineExceeded)
	}
	return errors.New("multipartupload: scan or compression failed")
}

type countingReader struct {
	src    io.Reader
	report func(Progress)
	total  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.total += int64(n)
	if n > 0 {
		r.report(Progress{BytesRead: r.total})
	}
	return n, err
}
