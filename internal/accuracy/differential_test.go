package accuracy_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/baum-ai/goredact/internal/accuracy"
)

// runScannerDifferential is the shared offline oracle harness. CI opts into
// the intentionally overlapping subset with rulesEnv (comma-separated goredact
// rule IDs). It never downloads the scanner and never prints fixture or report
// contents.
func runScannerDifferential(t *testing.T, scanner, binEnv, rulesEnv string, args func(fixtureDir, reportPath string) []string) {
	t.Helper()
	bin := os.Getenv(binEnv)
	if bin == "" {
		var err error
		bin, err = exec.LookPath(scanner)
		if err != nil {
			t.Skipf("%s binary not installed; offline differential skipped", scanner)
		}
	}
	supported := csvSet(os.Getenv(rulesEnv))
	if len(supported) == 0 {
		t.Skipf("set %s to the intentionally supported oracle subset", rulesEnv)
	}

	dir := t.TempDir()
	fixtureDir := filepath.Join(dir, "corpus")
	if err := os.Mkdir(fixtureDir, 0o700); err != nil {
		t.Fatal("create sanitized corpus directory")
	}
	type identity struct {
		rule     string
		positive bool
		ordinal  int
	}
	identities := map[string]identity{}
	logical := map[string]*metric{}
	for _, fixture := range accuracy.All() {
		if !supported[fixture.RuleID] {
			continue
		}
		name := fmt.Sprintf("%s__%t__%d.txt", fixture.RuleID, fixture.Positive, fixture.Ordinal)
		if err := os.WriteFile(filepath.Join(fixtureDir, name), []byte(fixture.Value), 0o600); err != nil {
			t.Fatalf("write fixture rule=%s ordinal=%d", fixture.RuleID, fixture.Ordinal)
		}
		identities[name] = identity{fixture.RuleID, fixture.Positive, fixture.Ordinal}
		if logical[fixture.RuleID] == nil {
			logical[fixture.RuleID] = &metric{}
		}
		if fixture.Positive {
			logical[fixture.RuleID].positive++
		} else {
			logical[fixture.RuleID].negative++
		}
	}
	for rule := range supported {
		if logical[rule] == nil {
			t.Fatalf("oracle subset contains unknown rule=%s", rule)
		}
	}
	report := filepath.Join(dir, "report.json")
	cmd := exec.Command(bin, args(fixtureDir, report)...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	// Combined output is intentionally discarded: scanner diagnostics may
	// include matched secret material.
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s oracle execution failed (output suppressed): %v", scanner, err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("%s did not produce its JSON report", scanner)
	}
	var findings []struct {
		File string `json:"File"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("%s report was not valid JSON", scanner)
	}
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[filepath.Base(finding.File)] = true
	}
	rules := make([]string, 0, len(logical))
	for rule := range logical {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	for _, rule := range rules {
		m := logical[rule]
		for name, id := range identities {
			if id.rule != rule || !seen[name] {
				continue
			}
			if id.positive {
				m.found++
			} else {
				m.falsePositive++
			}
		}
		t.Logf("%s rule=%s recall=%d/%d false_positive=%d/%d", scanner, rule, m.found, m.positive, m.falsePositive, m.negative)
		if m.found != m.positive || m.falsePositive != 0 {
			t.Errorf("%s differential mismatch rule=%s recall=%d/%d false_positive=%d/%d", scanner, rule, m.found, m.positive, m.falsePositive, m.negative)
		}
	}
}

func csvSet(value string) map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out[item] = true
		}
	}
	return out
}
