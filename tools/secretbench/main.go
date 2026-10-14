// Command secretbench evaluates goredact against a local SecretBench export.
//
// It never downloads the access-controlled corpus and never reads or emits the
// dataset's secret field. Reports contain only aggregate metrics and source
// coordinates.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/baum-ai/goredact"
)

type options struct {
	annotations  string
	files        string
	format       string
	output       string
	policy       string
	profile      string
	columnBase   int
	endInclusive bool
}

func main() {
	var o options
	flag.StringVar(&o.annotations, "annotations", "", "SecretBench BigQuery JSON or JSONL export")
	flag.StringVar(&o.files, "files", "", "extracted SecretBench Files directory")
	flag.StringVar(&o.format, "format", "json", "report format: json or markdown")
	flag.StringVar(&o.output, "output", "-", "report path ('-' for stdout)")
	flag.StringVar(&o.policy, "policy", "goredact", "scoring policy: full or goredact")
	flag.StringVar(&o.profile, "profile", "balanced", "goredact profile: fast, balanced, or deep")
	flag.IntVar(&o.columnBase, "column-base", 0, "annotation column base: 0 or 1")
	flag.BoolVar(&o.endInclusive, "end-inclusive", true, "treat annotation end_column as inclusive")
	flag.Parse()
	if err := run(context.Background(), o); err != nil {
		fmt.Fprintln(os.Stderr, "secretbench:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, o options) error {
	if o.annotations == "" || o.files == "" {
		return errors.New("-annotations and -files are required")
	}
	if o.columnBase != 0 && o.columnBase != 1 {
		return errors.New("-column-base must be 0 or 1")
	}
	if o.policy != "full" && o.policy != "goredact" {
		return errors.New("-policy must be full or goredact")
	}
	if o.format != "json" && o.format != "markdown" {
		return errors.New("-format must be json or markdown")
	}
	profile, err := parseProfile(o.profile)
	if err != nil {
		return err
	}
	f, err := os.Open(o.annotations)
	if err != nil {
		return fmt.Errorf("open annotations: %w", err)
	}
	h := sha256.New()
	annotations, err := decodeAnnotations(io.TeeReader(f, h))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return fmt.Errorf("close annotations: %w", closeErr)
	}
	report, err := evaluate(ctx, annotations, o.files, evalOptions{
		Policy: o.policy, Profile: profile, ColumnBase: o.columnBase, EndInclusive: o.endInclusive,
	})
	if err != nil {
		return err
	}
	report.AnnotationSHA256 = fmt.Sprintf("%x", h.Sum(nil))
	var data []byte
	if o.format == "json" {
		data, err = json.MarshalIndent(report, "", "  ")
		data = append(data, '\n')
	} else {
		data = []byte(markdown(report))
	}
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	if o.output == "-" {
		_, err = os.Stdout.Write(data)
	} else {
		err = writePrivate(o.output, data)
	}
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func parseProfile(s string) (goredact.Profile, error) {
	switch s {
	case "fast":
		return goredact.ProfileFast, nil
	case "balanced":
		return goredact.ProfileBalanced, nil
	case "deep":
		return goredact.ProfileDeep, nil
	default:
		return 0, errors.New("-profile must be fast, balanced, or deep")
	}
}

type annotation struct {
	ID             string `json:"id"`
	FileIdentifier string `json:"file_identifier"`
	StartLine      int    `json:"start_line"`
	EndLine        int    `json:"end_line"`
	StartColumn    int    `json:"start_column"`
	EndColumn      int    `json:"end_column"`
	Label          bool   `json:"-"`
	Category       string `json:"category"`
}

func (a *annotation) UnmarshalJSON(data []byte) error {
	var w struct {
		ID             string          `json:"id"`
		FileIdentifier string          `json:"file_identifier"`
		StartLine      json.RawMessage `json:"start_line"`
		EndLine        json.RawMessage `json:"end_line"`
		StartColumn    json.RawMessage `json:"start_column"`
		EndColumn      json.RawMessage `json:"end_column"`
		Label          json.RawMessage `json:"label"`
		Category       string          `json:"category"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	values := []*int{&a.StartLine, &a.EndLine, &a.StartColumn, &a.EndColumn}
	raw := []json.RawMessage{w.StartLine, w.EndLine, w.StartColumn, w.EndColumn}
	for i := range raw {
		v, err := flexibleInt(raw[i])
		if err != nil {
			return fmt.Errorf("invalid source coordinate: %w", err)
		}
		*values[i] = v
	}
	a.ID, a.FileIdentifier, a.Category = w.ID, w.FileIdentifier, w.Category
	if len(w.Label) == 0 {
		return errors.New("missing label")
	}
	if err := json.Unmarshal(w.Label, &a.Label); err == nil {
		return nil
	}
	var s string
	if err := json.Unmarshal(w.Label, &s); err != nil {
		return errors.New("label must be a boolean or True/False string")
	}
	switch strings.ToLower(s) {
	case "true":
		a.Label = true
	case "false":
		a.Label = false
	default:
		return errors.New("label must be True or False")
	}
	return nil
}

func flexibleInt(raw json.RawMessage) (int, error) {
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, errors.New("expected integer or integer string")
	}
	n64, err := strconv.ParseInt(s, 10, 0)
	if err != nil {
		return 0, errors.New("expected integer or integer string")
	}
	return int(n64), nil
}

func decodeAnnotations(r io.Reader) ([]annotation, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read annotations: %w", err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("annotations are empty")
	}
	var out []annotation
	if data[0] == '[' {
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("decode annotation array: %w", err)
		}
	} else {
		dec := json.NewDecoder(bytes.NewReader(data))
		for {
			var a annotation
			if err := dec.Decode(&a); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, fmt.Errorf("decode annotation JSONL: %w", err)
			}
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("annotations contain no rows")
	}
	for i, a := range out {
		if a.FileIdentifier == "" || a.Category == "" || a.StartLine < 1 || a.EndLine < a.StartLine {
			return nil, fmt.Errorf("annotation row %d has invalid required fields", i+1)
		}
	}
	return out, nil
}

func markdown(r report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# SecretBench accuracy report\n\nPolicy: `%s`; profile: `%s`; column base: `%d`; end column: `%s`.\n\n", r.Policy, r.Profile, r.Coordinates.ColumnBase, map[bool]string{true: "inclusive", false: "exclusive"}[r.Coordinates.EndInclusive])
	fmt.Fprintf(&b, "Rule set: `%s`; annotations SHA-256: `%s`; corpus SHA-256: `%s`.\n\n", r.RuleSetVersion, r.AnnotationSHA256, r.CorpusSHA256)
	fmt.Fprintf(&b, "| Category | TP | FP | FN | TN | Precision | Recall | F1 |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
	write := func(name string, m metrics) {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %.4f | %.4f | %.4f |\n", name, m.TP, m.FP, m.FN, m.TN, m.Precision, m.Recall, m.F1)
	}
	write("Overall (micro)", r.Overall)
	for _, c := range r.Categories {
		write(c.Category, c.Metrics)
	}
	fmt.Fprintf(&b, "\nMacro precision: %.4f; macro recall: %.4f; macro F1: %.4f.\n", r.Macro.Precision, r.Macro.Recall, r.Macro.F1)
	fmt.Fprintf(&b, "\nUnmatched scanner findings: %d. Excluded annotations: %d. Files scanned: %d.\n", r.UnmatchedFindings, r.ExcludedAnnotations, r.FilesScanned)
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
