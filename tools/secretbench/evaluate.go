package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/baum-ai/goredact"
)

type evalOptions struct {
	Policy       string
	Profile      goredact.Profile
	ColumnBase   int
	EndInclusive bool
}

type metrics struct {
	TP        int     `json:"true_positives"`
	FP        int     `json:"false_positives"`
	FN        int     `json:"false_negatives"`
	TN        int     `json:"true_negatives"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

type categoryMetrics struct {
	Category string  `json:"category"`
	Metrics  metrics `json:"metrics"`
}

type scores struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

type coordinates struct {
	ColumnBase   int  `json:"column_base"`
	EndInclusive bool `json:"end_inclusive"`
}

type sourceAnnotation struct {
	ID             string `json:"id,omitempty"`
	FileIdentifier string `json:"file_identifier"`
	StartLine      int    `json:"start_line"`
	EndLine        int    `json:"end_line"`
	StartColumn    int    `json:"start_column"`
	EndColumn      int    `json:"end_column"`
	Label          bool   `json:"label"`
	Category       string `json:"category"`
	RuleID         string `json:"rule_id,omitempty"`
}

type report struct {
	Schema              string             `json:"schema"`
	RuleSetVersion      string             `json:"rule_set_version"`
	AnnotationSHA256    string             `json:"annotation_sha256,omitempty"`
	CorpusSHA256        string             `json:"corpus_sha256"`
	Policy              string             `json:"policy"`
	Profile             string             `json:"profile"`
	Coordinates         coordinates        `json:"coordinates"`
	FilesScanned        int                `json:"files_scanned"`
	AnnotationsScored   int                `json:"annotations_scored"`
	ExcludedAnnotations int                `json:"excluded_annotations"`
	UnmatchedFindings   int                `json:"unmatched_findings"`
	Overall             metrics            `json:"overall"`
	Macro               scores             `json:"macro"`
	Categories          []categoryMetrics  `json:"categories"`
	FalsePositives      []sourceAnnotation `json:"false_positives"`
	FalseNegatives      []sourceAnnotation `json:"false_negatives"`
}

type candidate struct {
	annotation
	start, end int64
	detected   bool
	ruleID     string
}

func evaluate(ctx context.Context, annotations []annotation, root string, o evalOptions) (report, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return report{}, fmt.Errorf("resolve files directory: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil || !info.IsDir() {
		return report{}, errors.New("files path is not a directory")
	}
	groups := make(map[string][]annotation)
	excluded := 0
	for _, a := range annotations {
		if !inPolicy(o.Policy, a.Category) {
			excluded++
			continue
		}
		groups[a.FileIdentifier] = append(groups[a.FileIdentifier], a)
	}
	r := report{Schema: "goredact-secretbench/v1", Policy: o.Policy, Profile: o.Profile.String(),
		Coordinates: coordinates{o.ColumnBase, o.EndInclusive}, ExcludedAnnotations: excluded,
		Categories: []categoryMetrics{}, FalsePositives: []sourceAnnotation{}, FalseNegatives: []sourceAnnotation{}}
	findings := make([]goredact.Finding, 0)
	engine, err := goredact.New(goredact.Config{Profile: o.Profile, OnFinding: func(f goredact.Finding) {
		findings = append(findings, f)
	}})
	if err != nil {
		return report{}, err
	}
	r.RuleSetVersion = engine.RuleSetVersion()
	all := make([]candidate, 0)
	corpusHash := sha256.New()
	for _, fileID := range sortedKeys(groups) {
		if err := ctx.Err(); err != nil {
			return report{}, err
		}
		path, err := safeFile(absRoot, fileID)
		if err != nil {
			return report{}, fmt.Errorf("file_identifier %q: %w", fileID, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return report{}, fmt.Errorf("read file_identifier %q: %w", fileID, err)
		}
		writeHashPart(corpusHash, []byte(fileID))
		writeHashPart(corpusHash, data)
		cs, err := makeCandidates(groups[fileID], data, o)
		if err != nil {
			return report{}, fmt.Errorf("file_identifier %q: %w", fileID, err)
		}
		findings = findings[:0]
		if _, err := engine.Redact(ctx, io.Discard, bytes.NewReader(data)); err != nil {
			return report{}, fmt.Errorf("scan file_identifier %q: %w", fileID, err)
		}
		matched := matchOneToOne(cs, findings)
		r.UnmatchedFindings += len(findings) - matched
		all = append(all, cs...)
		r.FilesScanned++
	}
	r.CorpusSHA256 = fmt.Sprintf("%x", corpusHash.Sum(nil))
	r.AnnotationsScored = len(all)
	byCategory := make(map[string]*metrics)
	for _, c := range all {
		m := byCategory[c.Category]
		if m == nil {
			m = &metrics{}
			byCategory[c.Category] = m
		}
		switch {
		case c.Label && c.detected:
			m.TP++
		case c.Label:
			m.FN++
			r.FalseNegatives = append(r.FalseNegatives, sanitize(c))
		case c.detected:
			m.FP++
			r.FalsePositives = append(r.FalsePositives, sanitize(c))
		default:
			m.TN++
		}
	}
	precisionCategories, recallCategories, f1Categories := 0, 0, 0
	for _, category := range sortedKeys(byCategory) {
		finalize(byCategory[category])
		r.Categories = append(r.Categories, categoryMetrics{category, *byCategory[category]})
		r.Overall.TP += byCategory[category].TP
		r.Overall.FP += byCategory[category].FP
		r.Overall.FN += byCategory[category].FN
		r.Overall.TN += byCategory[category].TN
		if byCategory[category].TP+byCategory[category].FP > 0 {
			r.Macro.Precision += byCategory[category].Precision
			precisionCategories++
		}
		if byCategory[category].TP+byCategory[category].FN > 0 {
			r.Macro.Recall += byCategory[category].Recall
			recallCategories++
		}
		if byCategory[category].TP+byCategory[category].FP+byCategory[category].FN > 0 {
			r.Macro.F1 += byCategory[category].F1
			f1Categories++
		}
	}
	finalize(&r.Overall)
	if precisionCategories > 0 {
		r.Macro.Precision /= float64(precisionCategories)
	}
	if recallCategories > 0 {
		r.Macro.Recall /= float64(recallCategories)
	}
	if f1Categories > 0 {
		r.Macro.F1 /= float64(f1Categories)
	}
	return r, nil
}

func writeHashPart(w io.Writer, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = w.Write(size[:])
	_, _ = w.Write(value)
}

func inPolicy(policy, category string) bool {
	if policy == "full" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "private key", "api key and secret", "authentication key and token", "generic secret", "database and server url", "password":
		return true
	default:
		return false
	}
}

func safeFile(root, identifier string) (string, error) {
	if identifier == "" || filepath.IsAbs(identifier) {
		return "", errors.New("invalid path")
	}
	clean := filepath.Clean(filepath.FromSlash(identifier))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes files directory")
	}
	path := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes files directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file (symlinks are refused)")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if real != path {
		return "", errors.New("symlinks are refused")
	}
	return path, nil
}

func makeCandidates(as []annotation, data []byte, o evalOptions) ([]candidate, error) {
	seen := make(map[string]annotation)
	out := make([]candidate, 0, len(as))
	for _, a := range as {
		start, err := position(data, a.StartLine, a.StartColumn-o.ColumnBase)
		if err != nil {
			return nil, fmt.Errorf("annotation %q start: %w", a.ID, err)
		}
		endColumn := a.EndColumn - o.ColumnBase
		if o.EndInclusive {
			endColumn++
		}
		end, err := position(data, a.EndLine, endColumn)
		if err != nil {
			return nil, fmt.Errorf("annotation %q end: %w", a.ID, err)
		}
		if end <= start {
			return nil, fmt.Errorf("annotation %q has an empty or reversed span", a.ID)
		}
		key := fmt.Sprintf("%d:%d", start, end)
		if old, ok := seen[key]; ok {
			if old.Label != a.Label || old.Category != a.Category {
				return nil, fmt.Errorf("annotations %q and %q conflict at the same span", old.ID, a.ID)
			}
			continue
		}
		seen[key] = a
		out = append(out, candidate{annotation: a, start: start, end: end})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out, nil
}

// position converts a one-based line and zero-based byte column to an offset.
func position(data []byte, line, column int) (int64, error) {
	if line < 1 || column < 0 {
		return 0, errors.New("line or column is out of range")
	}
	start := 0
	for n := 1; n < line; n++ {
		i := bytes.IndexByte(data[start:], '\n')
		if i < 0 {
			return 0, errors.New("line is out of range")
		}
		start += i + 1
	}
	lineEnd := len(data)
	if i := bytes.IndexByte(data[start:], '\n'); i >= 0 {
		lineEnd = start + i
	}
	if column > lineEnd-start {
		return 0, errors.New("column is out of range")
	}
	return int64(start + column), nil
}

func matchOneToOne(candidates []candidate, findings []goredact.Finding) int {
	// Maximum bipartite matching avoids ordering-dependent credit where spans
	// overlap, while ensuring one scanner finding can credit only one row.
	assigned := make([]int, len(findings))
	for i := range assigned {
		assigned[i] = -1
	}
	matched := 0
	order := make([]int, 0, len(candidates))
	for ci := range candidates {
		if candidates[ci].Label {
			order = append(order, ci)
		}
	}
	for ci := range candidates {
		if !candidates[ci].Label {
			order = append(order, ci)
		}
	}
	for _, ci := range order {
		seen := make([]bool, len(findings))
		if assign(ci, candidates, findings, assigned, seen) {
			matched++
		}
	}
	for fi, ci := range assigned {
		if ci >= 0 {
			candidates[ci].detected = true
			candidates[ci].ruleID = findings[fi].RuleID
		}
	}
	return matched
}

func assign(ci int, candidates []candidate, findings []goredact.Finding, assigned []int, seen []bool) bool {
	for fi, f := range findings {
		if seen[fi] || f.End <= candidates[ci].start || f.Start >= candidates[ci].end {
			continue
		}
		seen[fi] = true
		if assigned[fi] < 0 || assign(assigned[fi], candidates, findings, assigned, seen) {
			assigned[fi] = ci
			return true
		}
	}
	return false
}

func sanitize(c candidate) sourceAnnotation {
	return sourceAnnotation{ID: c.ID, FileIdentifier: c.FileIdentifier, StartLine: c.StartLine,
		EndLine: c.EndLine, StartColumn: c.StartColumn, EndColumn: c.EndColumn,
		Label: c.Label, Category: c.Category, RuleID: c.ruleID}
}

func finalize(m *metrics) {
	if d := m.TP + m.FP; d > 0 {
		m.Precision = float64(m.TP) / float64(d)
	}
	if d := m.TP + m.FN; d > 0 {
		m.Recall = float64(m.TP) / float64(d)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
}
