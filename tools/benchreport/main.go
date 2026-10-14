// Command benchreport runs the reproducible large-corpus benchmark suite and
// emits machine-readable JSON. It is intentionally dependency-free.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	redact "github.com/baum-ai/goredact"
	"github.com/baum-ai/goredact/internal/ahocorasick"
	"github.com/baum-ai/goredact/internal/benchcorpus"
	"github.com/baum-ai/goredact/internal/rules"
)

type result struct {
	Scenario         string  `json:"scenario"`
	Size             int64   `json:"size_bytes"`
	Profile          string  `json:"profile"`
	Mode             string  `json:"mode"`
	Phase            string  `json:"phase"`
	WallSeconds      float64 `json:"wall_seconds"`
	CPUSeconds       float64 `json:"cpu_seconds"`
	MiBPerSecond     float64 `json:"mib_per_second"`
	AllocBytes       uint64  `json:"alloc_bytes"`
	Allocations      uint64  `json:"allocations"`
	PeakRSSBytes     uint64  `json:"peak_rss_bytes"`
	Candidates       int64   `json:"candidates"`
	Redactions       int64   `json:"redactions"`
	RedactedBytes    int64   `json:"redacted_bytes"`
	CompressionRatio float64 `json:"compression_ratio"`
}

type report struct {
	Schema     int      `json:"schema"`
	Generated  string   `json:"generated_at"`
	CorpusSeed uint64   `json:"corpus_seed"`
	GoVersion  string   `json:"go_version"`
	GOOS       string   `json:"goos"`
	GOARCH     string   `json:"goarch"`
	CPUs       int      `json:"cpus"`
	Results    []result `json:"results"`
}

type measurement struct {
	start         time.Time
	cpu           time.Duration
	alloc, malloc uint64
}

func begin() measurement {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return measurement{start: time.Now(), cpu: processCPU(), alloc: m.TotalAlloc, malloc: m.Mallocs}
}

func (m measurement) finish() (time.Duration, time.Duration, uint64, uint64, uint64) {
	wall := time.Since(m.start)
	cpu := processCPU() - m.cpu
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return wall, cpu, ms.TotalAlloc - m.alloc, ms.Mallocs - m.malloc, peakRSS()
}

func processCPU() time.Duration {
	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) != nil {
		return 0
	}
	return time.Duration(r.Utime.Sec+r.Stime.Sec)*time.Second + time.Duration(r.Utime.Usec+r.Stime.Usec)*time.Microsecond
}

func peakRSS() uint64 {
	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) != nil {
		return 0
	}
	v := uint64(r.Maxrss)
	if runtime.GOOS != "darwin" {
		v *= 1024
	}
	return v
}

func main() {
	sizesFlag := flag.String("sizes", "100MiB,500MiB,1GiB", "comma-separated corpus sizes")
	scenariosFlag := flag.String("scenarios", "quiet,keyword-dense,adversarial,confirmed-secret", "comma-separated scenarios")
	profilesFlag := flag.String("profiles", "fast,balanced,deep", "comma-separated profiles")
	modesFlag := flag.String("modes", "raw,record-aware", "comma-separated output modes")
	output := flag.String("output", "", "write JSON report to this path (default stdout)")
	baseline := flag.String("baseline", "", "compare against a previous report and fail regressions")
	maxRegression := flag.Float64("max-regression", 0.25, "maximum throughput regression versus baseline")
	minThroughput := flag.Float64("min-throughput", 0, "fail when any result is below this MiB/s (0 disables)")
	maxAllocRatio := flag.Float64("max-alloc-per-byte", 0, "fail when allocated/input bytes exceeds this ratio (0 disables)")
	flag.Parse()

	sizes, err := parseSizes(*sizesFlag)
	fatalIf(err)
	scenarios, err := parseScenarios(*scenariosFlag)
	fatalIf(err)
	profiles, err := parseProfiles(*profilesFlag)
	fatalIf(err)
	modes, err := parseModes(*modesFlag)
	fatalIf(err)
	r := report{Schema: 1, Generated: time.Now().UTC().Format(time.RFC3339), CorpusSeed: benchcorpus.Seed,
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUs: runtime.NumCPU()}
	debug.SetGCPercent(100)
	for _, size := range sizes {
		for _, scenario := range scenarios {
			for _, profile := range profiles {
				r.Results = append(r.Results, runMatch(scenario, size, profile))
				for _, mode := range modes {
					r.Results = append(r.Results, runRedact(scenario, size, profile, mode))
				}
			}
		}
	}
	data, err := json.MarshalIndent(r, "", "  ")
	fatalIf(err)
	data = append(data, '\n')
	if *output == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*output, data, 0o644)
	}
	fatalIf(err)
	fatalIf(checkBudgets(r, *minThroughput, *maxAllocRatio))
	if *baseline != "" {
		fatalIf(compare(*baseline, r, *maxRegression))
	}
}

func runRedact(s benchcorpus.Scenario, size int64, p redact.Profile, mode string) result {
	rd, err := benchcorpus.Reader(s, size)
	fatalIf(err)
	e, err := redact.New(redact.Config{Profile: p, RecordAligned: mode == "record-aware"})
	fatalIf(err)
	m := begin()
	stats, err := e.Redact(context.Background(), io.Discard, rd)
	fatalIf(err)
	wall, cpu, alloc, malloc, rss := m.finish()
	return makeResult(s, size, p.String(), mode, "validate+redact", wall, cpu, alloc, malloc, rss,
		stats.Candidates, stats.Findings, stats.RedactedBytes, float64(stats.BytesWritten)/float64(size))
}

func runMatch(s benchcorpus.Scenario, size int64, p redact.Profile) result {
	set, err := rules.Build(rules.BuildOptions{Profile: rules.Profile(p)})
	fatalIf(err)
	patterns := make([]ahocorasick.Pattern, 0)
	seen := map[string]bool{}
	for _, rule := range set.Rules {
		for _, t := range rule.Triggers {
			key := strconv.FormatBool(t.CaseFold) + ":" + t.Literal
			if t.CaseFold {
				key = "true:" + strings.ToLower(t.Literal)
			}
			if !seen[key] {
				seen[key] = true
				patterns = append(patterns, ahocorasick.Pattern{Literal: t.Literal, CaseFold: t.CaseFold})
			}
		}
	}
	a, err := ahocorasick.Compile(patterns)
	fatalIf(err)
	rd, err := benchcorpus.Reader(s, size)
	fatalIf(err)
	buf := make([]byte, 256<<10)
	var state ahocorasick.State
	var candidates int64
	m := begin()
	for {
		n, readErr := rd.Read(buf)
		if n > 0 {
			state = a.Scan(state, buf[:n], func(_, _ int) bool { candidates++; return true })
		}
		if readErr == io.EOF {
			break
		}
		fatalIf(readErr)
	}
	wall, cpu, alloc, malloc, rss := m.finish()
	return makeResult(s, size, p.String(), "raw", "match", wall, cpu, alloc, malloc, rss, candidates, 0, 0, 1)
}

func makeResult(s benchcorpus.Scenario, size int64, profile, mode, phase string, wall, cpu time.Duration, alloc, malloc, rss uint64, candidates int64, findings int64, redacted int64, ratio float64) result {
	throughput := float64(size) / (1024 * 1024) / wall.Seconds()
	return result{Scenario: string(s), Size: size, Profile: profile, Mode: mode, Phase: phase, WallSeconds: wall.Seconds(), CPUSeconds: cpu.Seconds(), MiBPerSecond: throughput, AllocBytes: alloc, Allocations: malloc, PeakRSSBytes: rss, Candidates: candidates, Redactions: findings, RedactedBytes: redacted, CompressionRatio: ratio}
}

func key(r result) string {
	return fmt.Sprintf("%s/%d/%s/%s/%s", r.Scenario, r.Size, r.Profile, r.Mode, r.Phase)
}
func compare(path string, current report, max float64) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var old report
	if err := json.Unmarshal(data, &old); err != nil {
		return err
	}
	if old.GOOS != current.GOOS || old.GOARCH != current.GOARCH {
		return fmt.Errorf("baseline platform %s/%s does not match %s/%s", old.GOOS, old.GOARCH, current.GOOS, current.GOARCH)
	}
	base := map[string]result{}
	for _, r := range old.Results {
		base[key(r)] = r
	}
	var failures []string
	for _, got := range current.Results {
		if want, ok := base[key(got)]; ok && want.MiBPerSecond > 0 && got.MiBPerSecond < want.MiBPerSecond*(1-max) {
			failures = append(failures, fmt.Sprintf("%s: %.1f MiB/s, baseline %.1f", key(got), got.MiBPerSecond, want.MiBPerSecond))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("benchmark regression (>%.0f%%):\n%s", max*100, strings.Join(failures, "\n"))
	}
	return nil
}

func checkBudgets(r report, minThroughput, maxAllocRatio float64) error {
	var failures []string
	for _, got := range r.Results {
		if minThroughput > 0 && got.MiBPerSecond < minThroughput {
			failures = append(failures, fmt.Sprintf("%s: %.1f MiB/s below %.1f", key(got), got.MiBPerSecond, minThroughput))
		}
		if maxAllocRatio > 0 && float64(got.AllocBytes)/float64(got.Size) > maxAllocRatio {
			failures = append(failures, fmt.Sprintf("%s: %.3f allocated bytes/input byte above %.3f", key(got), float64(got.AllocBytes)/float64(got.Size), maxAllocRatio))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("benchmark budget exceeded:\n%s", strings.Join(failures, "\n"))
	}
	return nil
}

func parseSizes(s string) ([]int64, error) {
	var out []int64
	for _, v := range strings.Split(s, ",") {
		n, err := parseSize(v)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
func parseSize(s string) (int64, error) {
	units := []struct {
		s string
		n int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}
	for _, u := range units {
		if strings.HasSuffix(s, u.s) {
			n, err := strconv.ParseInt(strings.TrimSuffix(s, u.s), 10, 64)
			return n * u.n, err
		}
	}
	return 0, fmt.Errorf("size %q must use B, KiB, MiB, or GiB", s)
}
func parseScenarios(s string) ([]benchcorpus.Scenario, error) {
	valid := map[string]bool{}
	for _, v := range benchcorpus.All {
		valid[string(v)] = true
	}
	var out []benchcorpus.Scenario
	for _, v := range strings.Split(s, ",") {
		if !valid[v] {
			return nil, fmt.Errorf("unknown scenario %q", v)
		}
		out = append(out, benchcorpus.Scenario(v))
	}
	return out, nil
}
func parseProfiles(s string) ([]redact.Profile, error) {
	m := map[string]redact.Profile{"fast": redact.ProfileFast, "balanced": redact.ProfileBalanced, "deep": redact.ProfileDeep}
	var out []redact.Profile
	for _, v := range strings.Split(s, ",") {
		p, ok := m[v]
		if !ok {
			return nil, fmt.Errorf("unknown profile %q", v)
		}
		out = append(out, p)
	}
	return out, nil
}
func parseModes(s string) ([]string, error) {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v != "raw" && v != "record-aware" {
			return nil, fmt.Errorf("unknown mode %q", v)
		}
		out = append(out, v)
	}
	return out, nil
}
func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchreport:", err)
		os.Exit(1)
	}
}
