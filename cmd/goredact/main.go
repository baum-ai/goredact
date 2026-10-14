// Command goredact is a reference streaming integration for the goredact
// library. It never creates plaintext temporary files.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/baum-ai/goredact"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/cobra"
)

type options struct {
	input, output, profile, mask, stats string
	zstd                                bool
	progressEvery                       int64
}

var errUsage = errors.New("goredact: invalid arguments")

// version may be set by release builds with
// -ldflags "-X main.version=v1.2.3". Development builds fall back to the
// module version recorded by the Go toolchain.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, err)
		var findings findingsError
		if errors.As(err, &findings) {
			os.Exit(findings.code)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := newRootCommand(ctx, stdin, stdout, stderr)
	cmd.SetArgs(normalizeLegacyFlags(args))
	return cmd.Execute()
}

// Go's flag package historically accepted long options with one dash. Keep
// those invocations working while Cobra presents conventional --long flags.
func normalizeLegacyFlags(args []string) []string {
	known := []string{"input", "output", "profile", "mask", "stats", "zstd", "progress-bytes", "report-format", "report-path", "exit-code", "show-secrets", "help", "version"}
	normalized := append([]string(nil), args...)
	for i, arg := range normalized {
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		name := strings.TrimPrefix(strings.SplitN(arg, "=", 2)[0], "-")
		for _, candidate := range known {
			if name == candidate {
				normalized[i] = "-" + arg
				break
			}
		}
	}
	return normalized
}

func newRootCommand(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "goredact",
		Short:         "Detect and redact secrets",
		Long:          "goredact detects and redacts secrets in streams, files, and directory trees.",
		Version:       buildVersion(),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		fmt.Fprint(cmd.ErrOrStderr(), cmd.UsageString())
		return err
	})
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)

	stream := &cobra.Command{
		Use:   "stream",
		Short: "Redact a stream or file",
		Long:  "Read bytes from standard input or a file, redact detected secrets, and write the sanitized stream without creating plaintext temporary files.",
		Example: `  goredact stream < input.log > output.log
  goredact stream --input input.log --output output.log --profile deep
  goredact stream --zstd --stats stats.json < input.log > output.log.zst`,
		Args: usageOnArgError(cobra.NoArgs),
	}
	var so options
	stream.Flags().StringVarP(&so.input, "input", "i", "-", "input file ('-' for stdin)")
	stream.Flags().StringVarP(&so.output, "output", "o", "-", "output file ('-' for stdout)")
	stream.Flags().StringVarP(&so.profile, "profile", "p", "balanced", "detection profile: fast, balanced, or deep")
	stream.Flags().StringVarP(&so.mask, "mask", "m", "fixed-marker", "mask strategy: fixed-marker, length-preserving, or format-preserving")
	stream.Flags().StringVar(&so.stats, "stats", "", "write JSON statistics to this file ('-' for stderr)")
	stream.Flags().BoolVar(&so.zstd, "zstd", false, "stream output as a Zstandard frame")
	stream.Flags().Int64Var(&so.progressEvery, "progress-bytes", 0, "report bytes read at this interval to stderr (0 disables)")
	stream.RunE = func(_ *cobra.Command, _ []string) error { return runStream(ctx, streamArgs(so), stdin, stdout, stderr) }

	dir := &cobra.Command{
		Use:   "dir [flags] <path>",
		Short: "Scan a file or directory",
		Long:  "Recursively scan a file or directory and write a JSON, CSV, JUnit, or SARIF findings report.",
		Example: `  goredact dir ./workspace
  goredact dir --report-format sarif --report-path findings.sarif ./workspace
  goredact dir --exit-code 0 ./workspace`,
		Args: usageOnArgError(cobra.ExactArgs(1)),
	}
	var d dirOptions
	dir.Flags().StringVarP(&d.profile, "profile", "p", "balanced", "detection profile: fast, balanced, or deep")
	dir.Flags().StringVarP(&d.reportFormat, "report-format", "f", "json", "report format: json, csv, junit, or sarif")
	dir.Flags().StringVarP(&d.reportPath, "report-path", "o", "-", "report file ('-' for stdout)")
	dir.Flags().IntVar(&d.exitCode, "exit-code", 1, "exit code when findings are present (0 disables)")
	dir.Flags().BoolVar(&d.showSecrets, "show-secrets", false, "include matched secret values in the report (unsafe)")
	dir.RunE = func(_ *cobra.Command, args []string) error { return runDir(ctx, dirArgs(d, args[0]), stdout, stderr) }

	root.AddCommand(stream, dir)
	return root
}

func usageOnArgError(validate cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := validate(cmd, args); err != nil {
			fmt.Fprint(cmd.ErrOrStderr(), cmd.UsageString())
			return err
		}
		return nil
	}
}

func streamArgs(o options) []string {
	return []string{"-input=" + o.input, "-output=" + o.output, "-profile=" + o.profile, "-mask=" + o.mask,
		"-stats=" + o.stats, "-zstd=" + strconv.FormatBool(o.zstd), "-progress-bytes=" + strconv.FormatInt(o.progressEvery, 10)}
}

func dirArgs(o dirOptions, path string) []string {
	return []string{"-profile=" + o.profile, "-report-format=" + o.reportFormat, "-report-path=" + o.reportPath,
		"-exit-code=" + strconv.Itoa(o.exitCode), "-show-secrets=" + strconv.FormatBool(o.showSecrets), path}
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func runStream(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("goredact stream", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.input, "input", "-", "input file ('-' for stdin)")
	fs.StringVar(&o.output, "output", "-", "output file ('-' for stdout)")
	fs.StringVar(&o.profile, "profile", "balanced", "detection profile: fast, balanced, or deep")
	fs.StringVar(&o.mask, "mask", "fixed-marker", "mask strategy: fixed-marker, length-preserving, or format-preserving")
	fs.StringVar(&o.stats, "stats", "", "write JSON statistics to this file ('-' for stderr)")
	fs.BoolVar(&o.zstd, "zstd", false, "stream output as a Zstandard frame")
	fs.Int64Var(&o.progressEvery, "progress-bytes", 0, "report bytes read at this interval to stderr (0 disables)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() != 0 {
		return errors.New("goredact: unexpected positional arguments")
	}
	if o.progressEvery < 0 {
		return errors.New("goredact: -progress-bytes must be non-negative")
	}
	if sameFileName(o.input, o.output) {
		return errors.New("goredact: input and output files must differ")
	}
	// -stats must not alias the input (it would clobber the file being
	// scanned) or the output (it would clobber the redacted result).
	if o.stats != "" && o.stats != "-" {
		if sameFileName(o.stats, o.input) || sameFileName(o.stats, o.output) {
			return errors.New("goredact: -stats must differ from input and output files")
		}
	}

	profile, err := parseProfile(o.profile)
	if err != nil {
		return err
	}
	mask, err := parseMask(o.mask)
	if err != nil {
		return err
	}
	engine, err := goredact.New(goredact.Config{Profile: profile, MaskStrategy: mask})
	if err != nil {
		return fmt.Errorf("goredact: configure engine: %w", err)
	}

	src, closeInput, err := openInput(o.input, stdin)
	if err != nil {
		// err is an *os.PathError: operation, user-supplied path, and
		// errno — never scanned content — so surfacing it is safe and
		// tells the user whether the problem is absence or permissions.
		return fmt.Errorf("goredact: cannot open input: %w", err)
	}
	defer closeInput()
	dst, outFile, err := openOutput(o.output, stdout)
	if err != nil {
		return fmt.Errorf("goredact: cannot open output: %w", err)
	}
	succeeded := false
	defer func() {
		if outFile == nil {
			return
		}
		if !succeeded {
			// Empty the file before unlinking the name: when o.output is
			// a symlink, os.Remove only removes the link, so truncating
			// first also honors the "removed on failure" contract for the
			// link's target instead of leaving partial output behind.
			_ = outFile.Truncate(0)
		}
		_ = outFile.Close()
		if !succeeded {
			_ = os.Remove(o.output)
		}
	}()

	reader := io.Reader(src)
	if o.progressEvery > 0 {
		reader = &progressReader{src: src, dst: stderr, every: o.progressEvery, next: o.progressEvery}
	}
	redactedDst := dst
	var compressor *zstd.Encoder
	if o.zstd {
		compressor, err = zstd.NewWriter(dst, zstd.WithEncoderConcurrency(1))
		if err != nil {
			return errors.New("goredact: cannot start compressed output")
		}
		redactedDst = compressor
	}
	stats, err := engine.Redact(ctx, redactedDst, reader)
	if err != nil {
		return safeScanError(err)
	}
	if compressor != nil {
		if err := compressor.Close(); err != nil {
			return errors.New("goredact: cannot finish compressed output")
		}
	}
	// Close the output before declaring success: a deferred write that
	// only fails at close (quota, NFS) must count as a failed scan, not
	// exit 0 with a silently incomplete file. The deferred cleanup treats
	// the already-closed file as failed and removes it.
	if outFile != nil {
		f := outFile
		outFile = nil
		if err := f.Close(); err != nil {
			// Empty the underlying file by path before unlinking the
			// name: when -output is a symlink or hard link, os.Remove
			// only detaches this name, and the closed fd can no longer
			// truncate, so a path-based truncate is what keeps the
			// incomplete result from remaining reachable through the
			// target or another link.
			_ = os.Truncate(o.output, 0)
			_ = os.Remove(o.output)
			return errors.New("goredact: cannot finalize output")
		}
	}
	// The redacted output is already complete and correct at this point:
	// a failure writing the optional stats sidecar below must not delete
	// it, so succeeded is set before attempting that write.
	succeeded = true
	if err := writeStats(o.stats, stats, stderr); err != nil {
		return err
	}
	return nil
}

func parseProfile(s string) (goredact.Profile, error) {
	switch strings.ToLower(s) {
	case "fast":
		return goredact.ProfileFast, nil
	case "balanced":
		return goredact.ProfileBalanced, nil
	case "deep":
		return goredact.ProfileDeep, nil
	default:
		return 0, errors.New("goredact: unknown profile (use fast, balanced, or deep)")
	}
}

func parseMask(s string) (goredact.MaskStrategy, error) {
	switch strings.ToLower(s) {
	case "fixed-marker":
		return goredact.MaskFixedMarker, nil
	case "length-preserving":
		return goredact.MaskLengthPreserving, nil
	case "format-preserving":
		return goredact.MaskFormatPreserving, nil
	default:
		return 0, errors.New("goredact: unknown mask strategy (use fixed-marker, length-preserving, or format-preserving)")
	}
}

func openInput(name string, fallback io.Reader) (io.Reader, func(), error) {
	if name == "-" {
		return fallback, func() {}, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, func() {}, err
	}
	return f, func() { _ = f.Close() }, nil
}

// openOutput opens name for writing, or returns fallback (with a nil
// *os.File) when name is "-". The caller owns closing the returned file.
func openOutput(name string, fallback io.Writer) (io.Writer, *os.File, error) {
	if name == "-" {
		return fallback, nil, nil
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}

func sameFileName(a, b string) bool {
	if a == "-" || b == "-" {
		return false
	}
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil && errB == nil && aa == bb {
		return true
	}
	aInfo, err := os.Stat(a)
	if err != nil {
		return false
	}
	bInfo, err := os.Stat(b)
	if err != nil {
		// The output file need not exist yet; absence means it cannot alias.
		return false
	}
	return os.SameFile(aInfo, bInfo)
}

type progressReader struct {
	src         io.Reader
	dst         io.Writer
	every, next int64
	total       int64
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.total += int64(n)
	if r.total >= r.next {
		fmt.Fprintf(r.dst, "goredact: bytes_read=%d\n", r.total)
		for r.next <= r.total {
			r.next += r.every
		}
	}
	return n, err
}

func writeStats(name string, stats goredact.Stats, stderr io.Writer) error {
	if name == "" {
		return nil
	}
	dst := stderr
	var f *os.File
	if name != "-" {
		var err error
		f, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("goredact: cannot open statistics output: %w", err)
		}
		defer f.Close()
		dst = f
	}
	if err := json.NewEncoder(dst).Encode(stats); err != nil {
		return errors.New("goredact: cannot write statistics")
	}
	return nil
}

func safeScanError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.New("goredact: scan canceled")
	}
	var readErr *goredact.ReadError
	if errors.As(err, &readErr) {
		return errors.New("goredact: input read failed")
	}
	var writeErr *goredact.WriteError
	if errors.As(err, &writeErr) {
		return errors.New("goredact: output write failed")
	}
	return errors.New("goredact: scan failed")
}
