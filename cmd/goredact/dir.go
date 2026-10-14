package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/baum-ai/goredact"
)

type dirOptions struct {
	profile      string
	reportFormat string
	reportPath   string
	exitCode     int
	showSecrets  bool
}

type reportFinding struct {
	RuleID     string `json:"rule_id"`
	Confidence string `json:"confidence"`
	File       string `json:"file"`
	StartByte  int64  `json:"start_byte"`
	EndByte    int64  `json:"end_byte"`
	Secret     string `json:"secret,omitempty"`
}

type scanReport struct {
	Schema       string          `json:"schema"`
	Profile      string          `json:"profile"`
	FilesScanned int             `json:"files_scanned"`
	BytesRead    int64           `json:"bytes_read"`
	Findings     []reportFinding `json:"findings"`
	ShowsSecrets bool            `json:"shows_secrets"`
}

type findingsError struct{ code int }

func (e findingsError) Error() string { return "goredact: findings detected" }

type fileScanResult struct {
	index      int
	bytesRead  int64
	findings   []reportFinding
	err        error
	canceled   bool
	skipped    bool // not scanned: binary content or unreadable
	unreadable bool
}

func runDir(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("goredact dir", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o dirOptions
	fs.StringVar(&o.profile, "profile", "balanced", "detection profile: fast, balanced, or deep")
	fs.StringVar(&o.reportFormat, "report-format", "json", "report format: json, csv, junit, or sarif")
	fs.StringVar(&o.reportPath, "report-path", "-", "report file ('-' for stdout)")
	fs.IntVar(&o.exitCode, "exit-code", 1, "exit code when findings are present (0 disables)")
	fs.BoolVar(&o.showSecrets, "show-secrets", false, "include matched secret values in the report (unsafe)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() != 1 {
		return errors.New("goredact dir: exactly one path is required")
	}
	if o.exitCode < 0 || o.exitCode > 125 {
		return errors.New("goredact dir: -exit-code must be between 0 and 125")
	}
	format := strings.ToLower(o.reportFormat)
	if !validReportFormat(format) {
		return errors.New("goredact dir: unknown report format (use json, csv, junit, or sarif)")
	}
	profile, err := parseProfile(o.profile)
	if err != nil {
		return err
	}

	root, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return errors.New("goredact dir: cannot resolve scan path")
	}
	// Resolve a symlinked root (e.g. a "current -> release-N" layout) to
	// its real target so it can be walked; symlinks nested inside the
	// tree are deliberately left unresolved and not followed.
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("goredact dir: cannot enumerate scan path: %w", err)
	}
	paths, skippedPaths, err := regularFiles(root)
	if err != nil {
		return fmt.Errorf("goredact dir: cannot enumerate scan path: %w", err)
	}
	var conflicts []string
	if o.reportPath != "-" {
		reportPath, resolveErr := filepath.Abs(o.reportPath)
		if resolveErr != nil {
			return errors.New("goredact dir: cannot resolve report path")
		}
		reportPath, resolveErr = canonicalizeReportPath(reportPath)
		if resolveErr != nil {
			return errors.New("goredact dir: cannot resolve report path")
		}
		paths, conflicts = excludeReportPath(paths, reportPath)
		if len(conflicts) > 0 {
			return fmt.Errorf("goredact dir: report path aliases scanned input file(s): %s", strings.Join(conflicts, ", "))
		}
	}
	report := scanReport{Schema: "goredact/v1", Profile: profile.String(), Findings: []reportFinding{}, ShowsSecrets: o.showSecrets}
	results, err := scanFiles(ctx, root, paths, profile, o.showSecrets)
	if err != nil {
		return err
	}
	unreadable := 0
	for _, result := range results {
		if result.skipped {
			if result.unreadable {
				unreadable++
			}
			continue
		}
		report.FilesScanned++
		report.BytesRead += result.bytesRead
		report.Findings = append(report.Findings, result.findings...)
	}

	if err := writeReport(o.reportPath, format, report, paths, stdout); err != nil {
		return err
	}
	if unreadable > 0 {
		fmt.Fprintf(stderr, "goredact: skipped %d unreadable file(s)\n", unreadable)
	}
	if skippedPaths > 0 {
		fmt.Fprintf(stderr, "goredact: skipped %d unreadable path(s) while enumerating\n", skippedPaths)
	}
	fmt.Fprintf(stderr, "goredact: secrets_found=%d\n", len(report.Findings))
	if len(report.Findings) > 0 && o.exitCode != 0 {
		return findingsError{code: o.exitCode}
	}
	return nil
}

func scanFiles(ctx context.Context, root string, paths []string, profile goredact.Profile, showSecrets bool) ([]fileScanResult, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	workerCount := min(len(paths), runtime.GOMAXPROCS(0))
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	completed := make(chan fileScanResult, len(paths))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			var findings []reportFinding
			var rel string
			engine, err := goredact.New(goredact.Config{Profile: profile, OnFinding: func(f goredact.Finding) {
				findings = append(findings, reportFinding{
					RuleID: f.RuleID, Confidence: f.Confidence.String(), File: rel,
					StartByte: f.Start, EndByte: f.End,
				})
			}})
			if err != nil {
				completed <- fileScanResult{err: fmt.Errorf("goredact dir: configure engine: %w", err)}
				cancel()
				return
			}
			for index := range jobs {
				rel = relativeScanPath(root, paths[index])
				findings = make([]reportFinding, 0)
				result := scanFile(scanCtx, engine, paths[index], index, &findings, showSecrets)
				result.findings = findings
				completed <- result
				if result.err != nil {
					cancel()
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range paths {
			select {
			case jobs <- index:
			case <-scanCtx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(completed)
	}()

	results := make([]fileScanResult, len(paths))
	completedCount := 0
	var firstErr error
	var canceledErr error
	for result := range completed {
		if result.err != nil {
			if result.canceled && canceledErr == nil {
				canceledErr = result.err
			} else if !result.canceled && firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		results[result.index] = result
		completedCount++
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if canceledErr != nil {
		return nil, canceledErr
	}
	if completedCount != len(paths) {
		return nil, safeScanError(scanCtx.Err())
	}
	return results, nil
}

func relativeScanPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		rel = filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}

func scanFile(ctx context.Context, engine *goredact.Engine, path string, index int, findings *[]reportFinding, showSecrets bool) fileScanResult {
	result := fileScanResult{index: index}
	file, err := os.Open(path)
	if err != nil {
		// Unreadable files (permissions, deletion races) are skipped and
		// counted rather than failing the whole scan, matching the
		// behavior of other directory scanners.
		result.skipped = true
		result.unreadable = true
		return result
	}
	binary, err := isBinaryFile(file)
	if err != nil {
		_ = file.Close()
		result.skipped = true
		result.unreadable = true
		return result
	}
	if binary {
		*findings = (*findings)[:0]
		result.skipped = true
		if err := file.Close(); err != nil {
			result.err = errors.New("goredact dir: cannot close input file")
		}
		return result
	}
	stats, err := engine.Redact(ctx, io.Discard, file)
	if err != nil {
		_ = file.Close()
		result.canceled = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		result.err = safeScanError(err)
		return result
	}
	result.bytesRead = stats.BytesRead
	if showSecrets {
		if err := loadSecrets(file, *findings); err != nil {
			_ = file.Close()
			result.err = errors.New("goredact dir: cannot read matched secret")
			return result
		}
	}
	if err := file.Close(); err != nil {
		result.err = errors.New("goredact dir: cannot close input file")
	}
	return result
}

// isBinaryFile reports whether file starts with content that cannot be
// text: a NUL byte anywhere in the first 8 KiB (the same sniff git and
// grep use). Compiled binaries produce garbage matches from their string
// tables, not credentials in any recoverable form, so dir mode skips them.
// The read offset is rewound so a non-binary file scans from the start.
func isBinaryFile(file *os.File) (bool, error) {
	buf := make([]byte, 8192)
	n, err := file.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	return bytes.IndexByte(buf[:n], 0) >= 0, nil
}

func loadSecrets(file *os.File, findings []reportFinding) error {
	maxInt := int64(^uint(0) >> 1)
	for i := range findings {
		length := findings[i].EndByte - findings[i].StartByte
		if length < 0 || length > maxInt {
			return errors.New("invalid finding range")
		}
		secret := make([]byte, int(length))
		if _, err := io.ReadFull(io.NewSectionReader(file, findings[i].StartByte, length), secret); err != nil {
			return err
		}
		findings[i].Secret = string(secret)
	}
	return nil
}

// canonicalizeReportPath resolves symlinks in reportPath's directory so it
// compares equal to the canonicalized paths regularFiles returns even
// when the scan root is reached through a symlink (e.g. "current ->
// /releases/x", "-report-path current/findings.json"). It resolves the
// directory rather than the full path because the report file itself
// commonly does not exist yet on a first run — only its parent directory
// is guaranteed to. The report file itself is resolved by excludeReportPath
// instead: os.Stat follows a symlinked or hard-linked report file to its
// underlying inode, so an alias of a scanned input is caught even though
// the file component is left unresolved here.
func canonicalizeReportPath(reportPath string) (string, error) {
	dir, base := filepath.Split(reportPath)
	realDir, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		return "", err
	}
	return filepath.Join(realDir, base), nil
}

// excludeReportPath removes the report file itself from the scan list and
// detects aliases. The report file itself — an exact path match, reached
// directly or through ".." or a symlinked scan root, which
// canonicalizeReportPath normalizes — is silently excluded so a report
// living inside the scan root is never scanned and re-reported. Any other
// path that names the same underlying file, a symlink or hard link alias,
// is returned as a conflict: writing the report through the alias would
// truncate a scanned input file, so the caller must refuse to run. The
// identity check stats the report path, resolving a symlinked or
// hard-linked report file to its underlying inode even though
// canonicalizeReportPath leaves the file component unresolved.
func excludeReportPath(paths []string, reportPath string) (kept, conflicts []string) {
	reportInfo, reportErr := os.Stat(reportPath)
	kept = paths[:0]
	for _, path := range paths {
		if path == reportPath {
			continue // the report file itself: excluded from scanning, never a conflict
		}
		if reportErr == nil {
			if info, err := os.Stat(path); err == nil && os.SameFile(reportInfo, info) {
				conflicts = append(conflicts, path)
				continue
			}
		}
		kept = append(kept, path)
	}
	return kept, conflicts
}

// regularFiles enumerates the regular files under root eligible for
// scanning. A directory or file that cannot be read (permission denied, or
// deleted mid-walk) is skipped and counted rather than aborting the whole
// walk, matching docs/CLI_AND_UPLOAD.md's documented behavior for
// unreadable paths.
func regularFiles(root string) (paths []string, skipped int, err error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, 0, err
	}
	if info.Mode().IsRegular() {
		if info.Size() == 0 {
			return nil, 0, nil
		}
		return []string{root}, 0, nil
	}
	if !info.IsDir() {
		return nil, 0, errors.New("not a regular file or directory")
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == root {
				return walkErr
			}
			skipped++
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() && rel != "." && defaultExcludedDirectory(rel) {
			return filepath.SkipDir
		}
		if entry.Type().IsRegular() {
			if defaultExcludedFile(rel) {
				return nil
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				skipped++
				return nil
			}
			if info.Size() == 0 {
				return nil
			}
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, skipped, err
}

// These are Gitleaks' default dependency and repository metadata exclusions,
// plus .pnpm-store (pnpm's content-addressable package cache, third-party
// package content exactly like node_modules).
// Keep them narrow: directories such as dist, target, and vendor in general may
// contain first-party source or credentials and are intentionally scanned.
var defaultExcludedDirectoryPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|/)node_modules(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)\.pnpm-store(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)bower_components(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)\.git$`),
	regexp.MustCompile(`(?:^|/)vendor/(?:github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$`),
	regexp.MustCompile(`(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$`),
	regexp.MustCompile(`(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\.\d{1,2})+|python/[23](?:\.\d{1,2})+/lib(?:64)?)(?:/.*)?$`),
	regexp.MustCompile(`(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$`),
}

func defaultExcludedDirectory(path string) bool {
	for _, pattern := range defaultExcludedDirectoryPatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

var defaultExcludedFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`gitleaks\.toml`),
	regexp.MustCompile(`(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$`),
	regexp.MustCompile(`(?i)\.(?:eot|[ot]tf|woff2?)$`),
	regexp.MustCompile(`(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf)$`),
	regexp.MustCompile(`go\.(?:mod|sum|work(?:\.sum)?)$`),
	regexp.MustCompile(`(?:^|/)vendor/modules\.txt$`),
	regexp.MustCompile(`(?:^|/)gradlew(?:\.bat)?$`),
	regexp.MustCompile(`(?:^|/)gradle\.lockfile$`),
	regexp.MustCompile(`(?:^|/)mvnw(?:\.cmd)?$`),
	regexp.MustCompile(`(?:^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$`),
	regexp.MustCompile(`(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$`),
	regexp.MustCompile(`(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$`),
	regexp.MustCompile(`(?:^|/)javascript\.json$`),
	regexp.MustCompile(`(?:^|/)(?:Pipfile|poetry)\.lock$`),
	regexp.MustCompile(`\.gem$`),
	regexp.MustCompile(`verification-metadata\.xml`),
	regexp.MustCompile(`Database.refactorlog`),
}

func defaultExcludedFile(path string) bool {
	for _, pattern := range defaultExcludedFilePatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}
