package accuracy_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	redact "github.com/baum-ai/goredact"
	"github.com/baum-ai/goredact/internal/accuracy"
)

const corpusChunkSize = 64 * 1024

type metric struct{ positive, found, negative, falsePositive int }

func TestCorpusAccuracyByRuleAndProfile(t *testing.T) {
	corpus := accuracy.All()
	rules := redact.BuiltinRules()
	byID := make(map[string]redact.RuleInfo, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	formats := map[accuracy.Format]bool{}
	counts := map[string][2]int{}
	for _, fixture := range corpus {
		formats[fixture.Format] = true
		c := counts[fixture.RuleID]
		if fixture.Positive {
			c[0]++
		} else {
			c[1]++
		}
		counts[fixture.RuleID] = c
	}
	if len(formats) != 10 {
		t.Fatalf("corpus format coverage = %d, want 10", len(formats))
	}
	for _, rule := range rules {
		c := counts[rule.ID]
		if c[0] == 0 || c[1] == 0 {
			t.Errorf("rule %s fixture coverage: positive=%d negative=%d", rule.ID, c[0], c[1])
		}
	}

	for _, profile := range []redact.Profile{redact.ProfileFast, redact.ProfileBalanced, redact.ProfileDeep} {
		profile := profile
		t.Run(profile.String(), func(t *testing.T) {
			metrics := map[string]*metric{}
			for _, rule := range rules {
				metrics[rule.ID] = &metric{}
			}
			for _, fixture := range corpus {
				rule, ok := byID[fixture.RuleID]
				if !ok {
					t.Fatalf("unknown corpus rule %s", fixture.RuleID)
				}
				active := profile >= rule.MinProfile
				m := metrics[fixture.RuleID]
				if fixture.Positive && active {
					m.positive++
				}
				if !fixture.Positive && active {
					m.negative++
				}
				for _, boundary := range []int{0, corpusChunkSize - 1, corpusChunkSize + 1} {
					found := scanFixture(t, profile, fixture, boundary)
					if fixture.Positive && active && found {
						m.found++
					}
					if !fixture.Positive && active && found {
						m.falsePositive++
					}
				}
			}
			for _, rule := range rules {
				m := metrics[rule.ID]
				// Each logical fixture runs at three chunk placements.
				wantFound := m.positive * 3
				t.Logf("accuracy profile=%s rule=%s recall=%d/%d false_positive=%d/%d", profile, rule.ID, m.found, wantFound, m.falsePositive, m.negative*3)
				// Fixtures are validator-positive; streaming recall is reported as
				// a metric rather than pinned to 100%, so this corpus can expose
				// boundary regressions and improvements without changing itself.
				if (m.positive > 0 && m.found == 0) || m.falsePositive != 0 {
					t.Errorf("accuracy mismatch profile=%s rule=%s recall=%d/%d false_positive=%d/%d", profile, rule.ID, m.found, wantFound, m.falsePositive, m.negative*3)
				}
			}
		})
	}
}

func scanFixture(t *testing.T, profile redact.Profile, fixture accuracy.Fixture, start int) bool {
	t.Helper()
	prefix := strings.Repeat(".", start)
	input := prefix + fixture.Value
	found := false
	e, err := redact.New(redact.Config{
		Profile:   profile,
		ChunkSize: corpusChunkSize,
		OnFinding: func(f redact.Finding) {
			if f.RuleID == fixture.RuleID {
				found = true
			}
		},
	})
	if err != nil {
		t.Fatalf("new engine profile=%s: %v", profile, err)
	}
	var output bytes.Buffer
	if _, err := e.Redact(context.Background(), &output, strings.NewReader(input)); err != nil {
		t.Fatalf("scan failed rule=%s fixture=%s/%d boundary=%d: %v", fixture.RuleID, fixture.Format, fixture.Ordinal, start, err)
	}
	// Failure diagnostics identify fixtures only; neither input nor output is
	// ever formatted into test output because both contain synthetic secrets.
	if fixture.Positive && found && bytes.Contains(output.Bytes(), []byte(fixture.Value)) {
		t.Errorf("confirmed fixture remained verbatim rule=%s fixture=%s/%d boundary=%d", fixture.RuleID, fixture.Format, fixture.Ordinal, start)
	}
	return found
}

func ExampleAll() {
	corpus := accuracy.All()
	positive, negative := 0, 0
	for _, fixture := range corpus {
		if fixture.Positive {
			positive++
		} else {
			negative++
		}
	}
	fmt.Printf("fixtures=%d positive=%d negative=%d\n", len(corpus), positive, negative)
	// Output:
	// fixtures=505 positive=196 negative=309
}
