package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baum-ai/goredact"
)

func TestDecodeAnnotationsArrayAndJSONL(t *testing.T) {
	row := `{"id":"one","file_identifier":"f.txt","start_line":"1","end_line":"1","start_column":"0","end_column":"2","label":"True","category":"Password"}`
	for _, input := range []string{"[" + row + "]", row + "\n" + strings.Replace(row, `"one"`, `"two"`, 1) + "\n"} {
		got, err := decodeAnnotations(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 || !got[0].Label || got[0].FileIdentifier != "f.txt" {
			t.Fatalf("unexpected annotations: %+v", got)
		}
	}
}

func TestEvaluateMetricsAndSanitizedOutput(t *testing.T) {
	dir := t.TempDir()
	const token1 = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
	const token2 = "ghp_26C7e42F292c6912E7710c838347Ae178B4b"
	data := "a=" + token1 + "\nb=" + token2 + "\nc=ordinary-value\n"
	if err := os.WriteFile(filepath.Join(dir, "sample.txt"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	as := []annotation{
		{ID: "tp", FileIdentifier: "sample.txt", StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 2 + len(token1) - 1, Label: true, Category: "Authentication Key and Token"},
		{ID: "fp", FileIdentifier: "sample.txt", StartLine: 2, EndLine: 2, StartColumn: 2, EndColumn: 2 + len(token2) - 1, Label: false, Category: "Authentication Key and Token"},
		{ID: "tn", FileIdentifier: "sample.txt", StartLine: 3, EndLine: 3, StartColumn: 2, EndColumn: 15, Label: false, Category: "Authentication Key and Token"},
		{ID: "excluded", FileIdentifier: "missing.txt", StartLine: 1, EndLine: 1, StartColumn: 0, EndColumn: 1, Label: true, Category: "Username"},
	}
	r, err := evaluate(context.Background(), as, dir, evalOptions{Policy: "goredact", Profile: goredact.ProfileBalanced, EndInclusive: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Overall.TP != 1 || r.Overall.FP != 1 || r.Overall.FN != 0 || r.Overall.TN != 1 || r.ExcludedAnnotations != 1 {
		t.Fatalf("unexpected report: %+v", r)
	}
	if r.RuleSetVersion == "" || r.CorpusSHA256 == "" {
		t.Fatalf("missing reproducibility metadata: %+v", r)
	}
	if r.Overall.Precision != .5 || r.Overall.Recall != 1 || r.Overall.F1 < .66 || r.Overall.F1 > .67 {
		t.Fatalf("unexpected metrics: %+v", r.Overall)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), token1) || strings.Contains(string(b), token2) {
		t.Fatal("report leaked a secret value")
	}
}

func TestUnmatchedFindingIsNotFalsePositive(t *testing.T) {
	dir := t.TempDir()
	const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
	if err := os.WriteFile(filepath.Join(dir, "sample.txt"), []byte("prefix="+token+"\nnot-a-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	as := []annotation{{ID: "fn", FileIdentifier: "sample.txt", StartLine: 2, EndLine: 2, StartColumn: 0, EndColumn: 11, Label: true, Category: "Password"}}
	r, err := evaluate(context.Background(), as, dir, evalOptions{Policy: "full", Profile: goredact.ProfileBalanced, EndInclusive: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.UnmatchedFindings != 1 || r.Overall.FP != 0 || r.Overall.FN != 1 {
		t.Fatalf("unexpected report: %+v", r)
	}
}

func TestTrueCandidateWinsAmbiguousFinding(t *testing.T) {
	candidates := []candidate{
		{annotation: annotation{ID: "false", Label: false}, start: 0, end: 20},
		{annotation: annotation{ID: "true", Label: true}, start: 5, end: 15},
	}
	findings := []goredact.Finding{{RuleID: "test", Start: 7, End: 10}}
	if got := matchOneToOne(candidates, findings); got != 1 {
		t.Fatalf("matched %d findings, want 1", got)
	}
	if !candidates[1].detected || candidates[0].detected {
		t.Fatalf("true candidate did not receive priority: %+v", candidates)
	}
}

func TestRunWritesPrivateReport(t *testing.T) {
	dir := t.TempDir()
	annotations := filepath.Join(dir, "annotations.jsonl")
	reportPath := filepath.Join(dir, "report.json")
	row := `{"id":"excluded","file_identifier":"unused","start_line":1,"end_line":1,"start_column":0,"end_column":1,"label":false,"category":"Username"}`
	if err := os.WriteFile(annotations, []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), options{annotations: annotations, files: dir, format: "json", output: reportPath, policy: "goredact", profile: "balanced", endInclusive: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %o, want 600", info.Mode().Perm())
	}
}

func TestDuplicateSpanGetsOneCredit(t *testing.T) {
	dir := t.TempDir()
	const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	a := annotation{ID: "a", FileIdentifier: "f", StartLine: 1, EndLine: 1, StartColumn: 0, EndColumn: len(token) - 1, Label: true, Category: "API Key and Secret"}
	b := a
	b.ID = "b"
	r, err := evaluate(context.Background(), []annotation{a, b}, dir, evalOptions{Policy: "full", Profile: goredact.ProfileBalanced, EndInclusive: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.AnnotationsScored != 1 || r.Overall.TP != 1 {
		t.Fatalf("duplicates were double counted: %+v", r)
	}
}

func TestSafeFileRejectsTraversalAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if _, err := safeFile(dir, "../outside"); err == nil {
		t.Fatal("traversal accepted")
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := safeFile(dir, "link"); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestPosition(t *testing.T) {
	data := []byte("abc\ndef\n")
	for _, tc := range []struct {
		line, column int
		want         int64
	}{{1, 0, 0}, {1, 3, 3}, {2, 1, 5}} {
		got, err := position(data, tc.line, tc.column)
		if err != nil || got != tc.want {
			t.Fatalf("position(%d,%d) = %d, %v; want %d", tc.line, tc.column, got, err, tc.want)
		}
	}
}
