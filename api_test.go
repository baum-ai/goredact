package goredact_test

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/baum-ai/goredact"
)

func TestModuleRootAPI(t *testing.T) {
	engine, err := goredact.New(goredact.Config{
		CustomRules: []goredact.CustomRule{{
			ID:         "test-token",
			Triggers:   []string{"secret"},
			Confidence: goredact.ConfidenceHigh,
			Validate: func(_ []byte, start, end int) (int, int, bool) {
				return start, end, true
			},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var output strings.Builder
	stats, err := engine.Redact(context.Background(), &output, strings.NewReader("a secret value"))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if got, want := output.String(), "a [REDACTED] value"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if stats.Findings != 1 {
		t.Fatalf("Findings = %d, want 1", stats.Findings)
	}

	if _, err := goredact.New(goredact.Config{Profile: goredact.Profile(99)}); !errors.Is(err, goredact.ErrInvalidConfig) {
		t.Fatalf("invalid profile error = %v, want ErrInvalidConfig", err)
	}
	if len(goredact.BuiltinRules()) == 0 {
		t.Fatal("BuiltinRules returned no rules")
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

// chunkedReader hands the engine at most size bytes per Read, forcing a
// mid-stream scan so output is emitted in several safe prefixes before a
// trigger in a later chunk is validated.
type chunkedReader struct {
	data string
	at   int
	size int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.at >= len(r.data) {
		return 0, io.EOF
	}
	n := r.size
	if rem := len(r.data) - r.at; n > rem {
		n = rem
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[r.at:r.at+n])
	r.at += n
	return n, nil
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// TestRedactWrapsIOErrors pins that Redact reports source and destination
// failures as the public *goredact.ReadError/*goredact.WriteError types
// (not merely values assignable to them): callers use errors.As against
// these exact public types to distinguish I/O failures from configuration
// or internal failures.
func TestRedactWrapsIOErrors(t *testing.T) {
	engine, err := goredact.New(goredact.Config{})
	if err != nil {
		t.Fatal(err)
	}

	srcErr := errors.New("source broke")
	_, err = engine.Redact(context.Background(), &strings.Builder{}, failingReader{err: srcErr})
	var readErr *goredact.ReadError
	if !errors.As(err, &readErr) || !errors.Is(readErr, srcErr) {
		t.Fatalf("Redact error = %v, want a *goredact.ReadError wrapping %v", err, srcErr)
	}

	dstErr := errors.New("destination broke")
	_, err = engine.Redact(context.Background(), failingWriter{err: dstErr}, strings.NewReader("data"))
	var writeErr *goredact.WriteError
	if !errors.As(err, &writeErr) || !errors.Is(writeErr, dstErr) {
		t.Fatalf("Redact error = %v, want a *goredact.WriteError wrapping %v", err, dstErr)
	}
}

// TestOnFindingReceivesPublicFinding pins that Config.OnFinding is invoked
// with the public goredact.Finding type carrying the correct rule ID and
// confidence, since the callback crosses the internal/public type boundary
// through a converting adapter rather than a direct alias.
func TestOnFindingReceivesPublicFinding(t *testing.T) {
	var got []goredact.Finding
	engine, err := goredact.New(goredact.Config{
		Profile: goredact.ProfileFast,
		OnFinding: func(f goredact.Finding) {
			got = append(got, f)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if _, err := engine.Redact(context.Background(), &output, strings.NewReader("key=AKIAUJZDEGXDNCF32EPF")); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RuleID != "aws-access-key-id" || got[0].Confidence != goredact.ConfidenceHigh {
		t.Fatalf("OnFinding findings = %+v", got)
	}
}

// TestActiveRulesAndRuleSetVersion smoke-tests the two Engine introspection
// methods that only became reachable through public forwarding methods
// once Engine stopped being a bare alias.
func TestActiveRulesAndRuleSetVersion(t *testing.T) {
	engine, err := goredact.New(goredact.Config{Profile: goredact.ProfileFast})
	if err != nil {
		t.Fatal(err)
	}
	if len(engine.ActiveRules()) == 0 {
		t.Fatal("ActiveRules returned no rules")
	}
	if engine.RuleSetVersion() == "" {
		t.Fatal("RuleSetVersion is empty")
	}
}

// TestCustomRuleValidatePanicIsError pins the documented contract that a
// panic inside a caller-supplied CustomRule.Validate does not propagate
// out of Redact: it is caught and returned as an error naming the rule,
// without leaking the panic value or input bytes, and with no partial
// output corruption (already-emitted bytes stay a clean prefix of the
// input).
func TestCustomRuleValidatePanicIsError(t *testing.T) {
	const ruleID = "panic-rule"
	const input = "prefix SECRET suffix"
	engine, err := goredact.New(goredact.Config{
		CustomRules: []goredact.CustomRule{{
			ID:       ruleID,
			Triggers: []string{"SECRET"},
			Validate: func(_ []byte, _, _ int) (int, int, bool) {
				panic("validator exploded: this value must not surface")
			},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var output strings.Builder
	_, err = engine.Redact(context.Background(), &output, &chunkedReader{data: input, size: 4})
	if err == nil {
		t.Fatal("Redact succeeded, want an error from the panicking Validate")
	}
	if !strings.Contains(err.Error(), ruleID) {
		t.Errorf("error %q does not name the panicking rule", err)
	}
	for _, leaked := range []string{"validator exploded", "SECRET"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("error %q leaks %q", err, leaked)
		}
	}
	got := output.String()
	if !strings.HasPrefix(input, got) || strings.Contains(got, "SECRET") {
		t.Errorf("output %q is not a clean prefix of the input (partial output corruption)", got)
	}
}

// TestGoDocRendersFieldAndMethodDocumentation guards against regressing to
// a bare `type Config = core.Config`-style alias: go doc (and by extension
// pkg.go.dev) cannot expand an alias's fields or methods, so this asserts
// the documentation this package's godoc consumers depend on is actually
// present in `go doc`'s rendered output.
func TestGoDocRendersFieldAndMethodDocumentation(t *testing.T) {
	out, err := exec.Command("go", "doc", ".", "Config").CombinedOutput()
	if err != nil {
		t.Fatalf("go doc . Config: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ChunkSize is the size in bytes") {
		t.Fatalf("go doc . Config did not render field documentation:\n%s", out)
	}

	out, err = exec.Command("go", "doc", ".", "Engine.Redact").CombinedOutput()
	if err != nil {
		t.Fatalf("go doc . Engine.Redact: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Redact copies src to dst") {
		t.Fatalf("go doc . Engine.Redact did not render method documentation:\n%s", out)
	}
}
