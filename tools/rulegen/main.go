// Command rulegen compiles declarative rule specs (internal/rules/specs/*.json)
// into the generated Go tables that internal/rules registers as built-ins.
//
// It is invoked via the //go:generate directive in internal/rules/generate.go:
//
//	go run github.com/baum-ai/goredact/tools/rulegen \
//	    -specs ./specs -out ./zz_generated_rules.go -fixtures ./zz_generated_fixtures_test.go
//
// # Spec schema
//
// Each specs/*.json file has the shape {"rules": [...]}. Each rule object:
//
//	{
//	  "id": "github-pat",                     // required, unique, stable kebab-case
//	  "name": "GitHub personal access token",  // required
//	  "triggers": [{"literal": "ghp_", "caseFold": false}], // >=1, non-empty literals
//	  "validator": "GitHubPAT",                // required; Go identifier in
//	                                            // internal/rules/validators
//	  "minProfile": "fast",                    // fast | balanced | deep
//	  "confidence": "high",                    // low | medium | high
//	  "maxLookbehind": 0,                      // >= 0
//	  "maxLookahead": 64,                      // >= 0
//	  "provenance": {"source": "...", "license": "..."}, // both required
//	  "fixtures": {
//	    "match":   ["..."],  // >=1 required; inputs the rule MUST confirm
//	    "nomatch": ["..."]   // optional; inputs it must NOT confirm
//	  }
//	}
//
// # Determinism
//
// Rules are sorted by ID before being emitted, regardless of which spec
// file declared them or their order within that file. This keeps the
// RegisterBuiltins table (and hence rule indices and rules.Version) stable
// when unrelated rules are added or spec files are reorganized. Output is
// byte-for-byte deterministic for a given set of spec files.
//
// # Duplicate triggers are allowed
//
// Multiple rules MAY share a trigger literal (e.g. two providers both
// keying off "Bearer "); this is not a validation error. Deduplication of
// the underlying automaton patterns happens at Aho-Corasick compile time
// (internal/ahocorasick), and dispatch fans a single trigger hit out to
// every rule that registered it. Rejecting shared triggers here would make
// that pattern impossible to express.
//
// # Errors
//
// Any schema violation (missing/invalid field, duplicate ID, missing match
// fixture, ...) is collected — every problem across every spec file is
// reported in one run — and rulegen exits non-zero listing them all.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	specsDir := flag.String("specs", "", "directory of *.json rule spec files")
	outPath := flag.String("out", "", "output path for the generated rules Go file")
	fixturesPath := flag.String("fixtures", "", "output path for the generated fixtures test file")
	flag.Parse()

	if *specsDir == "" || *outPath == "" || *fixturesPath == "" {
		fmt.Fprintln(os.Stderr, "rulegen: -specs, -out, and -fixtures are all required")
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*specsDir, *outPath, *fixturesPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run loads and validates the specs in specsDir, then writes the generated
// rules file to outPath and the generated fixtures test file to
// fixturesPath. On any validation problem it returns a single error
// listing every problem found, and writes neither output file.
func run(specsDir, outPath, fixturesPath string) error {
	specs, problems := loadSpecs(specsDir)
	problems = append(problems, validateRules(specs)...)
	if len(problems) > 0 {
		return formatProblems(problems)
	}

	rules := toGenRules(specs)

	version, err := computeVersion(rules)
	if err != nil {
		return err
	}

	rulesSrc, err := renderRulesFile(rules, version)
	if err != nil {
		return err
	}
	fixturesSrc, err := renderFixturesFile(rules)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outPath, rulesSrc, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}
	if err := os.WriteFile(fixturesPath, fixturesSrc, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", fixturesPath, err)
	}
	return nil
}

func formatProblems(problems []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "rulegen: %d problem(s) found in rule specs:\n", len(problems))
	for _, p := range problems {
		fmt.Fprintf(&b, "  - %s\n", p)
	}
	return fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
}
