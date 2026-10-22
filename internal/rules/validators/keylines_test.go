package validators

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func TestKeyEscape(t *testing.T) {
	for _, tc := range []struct {
		in   string
		kind escKind
		end  int
	}{
		{`\n`, escLF, 2},
		{`\\\n`, escLF, 4},
		{"\\\n", escLF, 2},
		{"\\\r\n", escLF, 3},
		{`\u000A`, escLF, 6},
		{`\r`, escSep, 2},
		{`\t`, escSep, 2},
		{`\"`, escSep, 2},
		{`\u0022`, escSep, 6},
		{`\/`, escB64, 2},
		{`\\\/`, escB64, 4},
		{`\u002B`, escB64, 6},
		{`\u002f`, escB64, 6},
		{`\u003D`, escB64, 6},
		{`\u0041`, escJunk, 1},
		{`\u00zz`, escJunk, 1},
		{`\x`, escJunk, 1},
		{`\\`, escNeed, 2},
		{`\u00`, escNeed, 4},
		{"\\\r", escNeed, 2},
	} {
		kind, end, _ := keyEscape([]byte(tc.in), 0)
		if kind != tc.kind || kind != escNeed && kind != escJunk && end != tc.end {
			t.Errorf("keyEscape(%q) = %d, %d; want %d, %d", tc.in, kind, end, tc.kind, tc.end)
		}
	}
}

func TestKeyLineEnd(t *testing.T) {
	for _, tc := range []struct {
		in       string
		end      int
		ok, need bool
	}{
		{"\nx", 1, true, false},
		{"\r\nx", 2, true, false},
		{`\nx`, 2, true, false},
		{`\r\nx`, 4, true, false},
		{`\\r\\nx`, 6, true, false},
		{"\\n\" +\n\tx", 6, true, false},
		{"\\n\",\nx", 5, true, false},
		{"\\n\");\nx", 6, true, false},
		{"\" +\nx", 4, true, false},
		{"' +\r\nx", 5, true, false},
		{`\\n\" +\n\tx`, 9, true, false},
		{`\n"}`, 2, true, false}, // the end of a JSON string: no tail
		{`"}`, 0, false, false},
		{"x", 0, false, false},
		{"", 0, false, true},
		{`\`, 0, false, true},
		{"\r", 0, false, true},
		{`\n" +`, 0, false, true},
	} {
		end, ok, need := keyLineEnd([]byte(tc.in), 0)
		if end != tc.end || ok != tc.ok || need != tc.need {
			t.Errorf("keyLineEnd(%q) = %d, %v, %v; want %d, %v, %v", tc.in, end, ok, need, tc.end, tc.ok, tc.need)
		}
	}
}

func TestKeyFrameLen(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		need bool
	}{
		{"> MIIE", 2, false},
		{"> > >MIIE", 5, false},
		{"# MIIE", 2, false},
		{"// MIIE", 3, false},
		{" * MIIE", 3, false},
		{"\t\"MIIE", 2, false},
		{"    + \"MIIE", 7, false},
		{`\t\"MIIE`, 4, false},
		{"     12→MIIE", 10, false},
		{"12\tMIIE", 3, false},
		{`  7\u2192MIIE`, 9, false},
		{`7\\tMIIE`, 4, false},
		{"12MIIE", 0, false}, // digits without a separator are content
		{"-----END", 0, false},
		{"> -----END", 2, false},
		{"/MIIE", 0, false},
		{"> 12", 2, true},
		{"  ", 2, true},
		{strings.Repeat(" ", 100) + "M", keyFrameMax + 1, false}, // a leading space is outside the budget
		{strings.Repeat("\t", 100) + "M", keyFrameMax, false},
		{"  12 | MIIE", 7, false},
		{"12|MIIE", 3, false},
		{"12:MIIE", 3, false},
		{"   7│ MIIE", 8, false},
		{`\u003e MIIE`, 7, false},
		{`\/\/ MIIE`, 5, false},
		{"    + \"MIIE", 7, false},
		{"\" . MIIE", 4, false},
		{"& \"MIIE", 3, false},
		{"12 MIIE", 0, false},
		{"12 -----END", 0, false},
	} {
		n, need := keyFrameLen([]byte(tc.in), 0, len(tc.in))
		if n != tc.n || need != tc.need {
			t.Errorf("keyFrameLen(%q) = %d, %v; want %d, %v", tc.in, n, need, tc.n, tc.need)
		}
	}
}

func TestKeyHunkHeader(t *testing.T) {
	for _, tc := range []struct {
		in       string
		final    bool
		end      int
		ok, need bool
	}{
		{"@@ -1,7 +1,9 @@\nx", false, 15, true, false},
		{"@@ -1 +1 @@ MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nx", false, 44, true, false},
		{`@@ -10,2 +10,3 @@ func x() {\n`, false, 28, true, false},
		{"@@ -1,7 +1,9 @@", true, 15, true, false},
		{"@@ -1,7 +1,9 @@", false, 0, false, true},
		{"@@ -1,", false, 0, false, true},
		{"@@ -1,7 +1,9 @", false, 0, false, true},
		{"@@ -1,7 +1,9 @x", false, 0, false, false},
		{"@@ -a +1 @@\n", false, 0, false, false},
		{"@@@ -1 -1 +1 @@@\n", false, 0, false, false},
		{"@@ -1 +1 @@ " + strings.Repeat("x", 300) + "\n", false, 0, false, false},
	} {
		end, ok, need := keyHunkHeader([]byte(tc.in), 0, tc.final)
		if end != tc.end || ok != tc.ok || need != tc.need {
			t.Errorf("keyHunkHeader(%q, final %v) = %d, %v, %v; want %d, %v, %v", tc.in, tc.final, end, ok, need, tc.end, tc.ok, tc.need)
		}
	}
}

func TestKeyTriggerMarker(t *testing.T) {
	pad := strings.Repeat("x", keyLookbehind) + "\n"
	for _, tc := range []struct {
		prefix string
		marker byte
	}{
		{"", 0},
		{"+", '+'},
		{"-", '-'},
		{" ", ' '},
		{"+> ", '+'},
		{"+\t\"", '+'},
		{"  ", ' '}, // an indentation reads as a context line
		{"\t", 0},
		{"> ", 0},
		{"key: ", 0},
		{"+key: ", 0},
	} {
		for _, before := range []string{pad, "", pad[:keyLookbehind-len(tc.prefix)-2] + `\n`} {
			text := before + tc.prefix + pemTrig
			if got := keyTriggerMarker([]byte(text), len(text)-len(pemTrig)); got != tc.marker {
				t.Errorf("prefix %q after %q: marker %q, want %q", tc.prefix, before[max(0, len(before)-3):], got, tc.marker)
			}
		}
	}
	// A window that holds keyLookbehind bytes before the trigger starts
	// at the start of input only when it has fewer: then offset 0 starts a
	// line.
	if got := keyTriggerMarker([]byte(strings.Repeat("y", keyLookbehind)+"+"+pemTrig), keyLookbehind+1); got != 0 {
		t.Errorf("a marker inside a long line: %q", got)
	}
}

// TestKeyLookbehindMatchesSpec: both key rules' lookbehind is
// keyLookbehind, so a trigger window shows the trigger line's frame, its
// marker and the line break before them.
func TestKeyLookbehindMatchesSpec(t *testing.T) {
	data, err := os.ReadFile("../specs/private-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Rules []struct {
			ID            string `json:"id"`
			MaxLookbehind int    `json:"maxLookbehind"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for _, r := range spec.Rules {
		if r.MaxLookbehind != keyLookbehind {
			t.Errorf("%s maxLookbehind %d, keyLookbehind %d", r.ID, r.MaxLookbehind, keyLookbehind)
		}
	}
}

// keyShapes are the shapes a key's lines take in logs and sources.
var keyShapes = map[string]func(string) string{
	"php json":   strings.NewReplacer("/", `\/`, "\n", `\n`).Replace,
	"dotnet":     strings.NewReplacer("+", `\u002B`, "\n", `\n`).Replace,
	"quote":      func(s string) string { return "> " + strings.ReplaceAll(s, "\n", "\n> ") },
	"nested":     func(s string) string { return "> > " + strings.ReplaceAll(s, "\n", "\n> > ") },
	"comment":    func(s string) string { return "# " + strings.ReplaceAll(s, "\n", "\n# ") },
	"go concat":  func(s string) string { return "\t\"" + strings.ReplaceAll(s, "\n", "\\n\" +\n\t\"") + `\n"` },
	"yaml":       func(s string) string { return "    " + strings.ReplaceAll(s, "\n", "\n    ") },
	"transcript": strings.NewReplacer("\n", `\n`, "\t", `\t`).Replace,
	"line numbers": func(s string) string {
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = fmt.Sprintf("%6d→", i+1) + lines[i]
		}
		return strings.Join(lines, "\n")
	},
	"numbered patch": func(s string) string {
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = fmt.Sprintf("%6d→+", i+1) + lines[i]
		}
		return strings.Join(lines, "\n")
	},
	"bar numbers": func(s string) string {
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = fmt.Sprintf("%4d | ", i+1) + lines[i]
		}
		return strings.Join(lines, "\n")
	},
	"hunks": func(s string) string {
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = " " + lines[i]
			if i%50 == 49 {
				lines[i] += "\n@@ -1,50 +1,50 @@ " + strings.TrimSpace(lines[i])
			}
		}
		return strings.Join(lines, "\n")
	},
}

// TestKeyShapesChain: in every shape, a key longer than the window is
// followed window by window exactly as one scan of the whole input reads
// it, and masked from its trigger through its end.
func TestKeyShapesChain(t *testing.T) {
	pgp := synthPGPKey(60, 40<<10)
	ppk := synthPPK(61, 600)
	for name, shape := range keyShapes {
		for _, f := range []blockFuncs{pemBlock, ppkBlock} {
			key := pgp
			if f.name == "ppk" {
				key = ppk
			}
			text := []byte("prefix line\n" + shape(key) + "\nafter the key: plain text.\n")
			trigStart := strings.Index(string(text), f.trigger)
			wantS, wantE, ok := wholeSpan(f, text, trigStart)
			if !ok {
				t.Fatalf("%s %s: no key", name, f.name)
			}
			if f.name == "pem" {
				if want := strings.LastIndex(string(text), "BLOCK-----") + len("BLOCK-----"); wantE != want && wantE != want+2 {
					t.Fatalf("%s %s: whole span ends at %d, want %d", name, f.name, wantE, want)
				}
			} else if last := strings.LastIndex(string(text), "Private-MAC"); wantE < last-100 {
				t.Fatalf("%s %s: whole span ends at %d, the MAC line at %d", name, f.name, wantE, last)
			}
			for _, lookahead := range []int{16384, 2048, 1300} {
				start, end, ok, opened, _ := chainSpan(f, text, trigStart, lookahead)
				if !ok || !opened || start != wantS || end != wantE {
					t.Fatalf("%s %s, lookahead %d: chained [%d,%d) ok=%v opened=%v, whole [%d,%d)", name, f.name, lookahead, start, end, ok, opened, wantS, wantE)
				}
			}
		}
	}
}

// TestKeyShapesBeginFinalMatchesValidate extends
// TestBlockBeginFinalMatchesValidate to the key shapes, cut at every
// offset.
func TestKeyShapesBeginFinalMatchesValidate(t *testing.T) {
	rng := rand.New(rand.NewSource(62))
	for name, shape := range keyShapes {
		for _, sample := range []string{shape(synthPGPKey(63, 1500)), shape(synthPPK(64, 4))} {
			for cut := 0; cut <= len(sample); cut += 1 + rng.Intn(40) {
				window := []byte(sample[:cut])
				for _, f := range []struct {
					blockFuncs
					validate func([]byte, int, int) (int, int, bool)
				}{{pemBlock, PEMPrivateKey}, {ppkBlock, PuTTYPrivateKey}} {
					ts := strings.Index(string(window), f.trigger)
					if ts < 0 {
						continue
					}
					s1, e1, ok1 := f.validate(window, ts, ts+len(f.trigger))
					s2, e2, _, open, ok2 := f.begin(window, ts, ts+len(f.trigger), true)
					if open || ok1 != ok2 || ok1 && (s1 != s2 || e1 != e2) {
						t.Fatalf("%s %s cut %d: Validate (%d,%d,%v) != Begin final (%d,%d,%v,open=%v)", name, f.name, cut, s1, e1, ok1, s2, e2, ok2, open)
					}
				}
			}
		}
	}
}

// TestPEMChainBackslashRunBeforeHunk: a window that ends inside a long
// backslash run whose escaped line feed opens a hunk header the next window
// cuts still follows the key, as one scan of the whole input does.
func TestPEMChainBackslashRunBeforeHunk(t *testing.T) {
	for _, n := range []int{1999, 2100, 3000} {
		text := []byte(pemTrig + "RSA PRIVATE KEY-----\\n" + pemB64LineA + "\\n" + pemB64LineB +
			strings.Repeat(`\`, n) + "n@@ -1,2 +1,2 @@ " + strings.Repeat("x", 200) + "\\n" +
			pemB64LineC + "\\n" + pemB64LineA + "\\n-----END RSA PRIVATE KEY-----\\n")
		wantS, wantE, _ := wholeSpan(pemBlock, text, 0)
		for la := 1168; la < 2700; la += 37 {
			start, end, ok, _, _ := chainSpan(pemBlock, text, 0, la)
			if !ok || start != wantS || end < wantE {
				t.Fatalf("run %d, lookahead %d: chained [%d,%d) ok=%v, whole [%d,%d)", n, la, start, end, ok, wantS, wantE)
			}
		}
	}
}

// TestPEMChainEscapeCutAtTriggerWindowEnd: a body line longer than the
// trigger window, so the block only becomes plausible as its first run
// closes, with an escape (`+`) the window end cuts: the block is
// followed into the next window, not ended there.
func TestPEMChainEscapeCutAtTriggerWindowEnd(t *testing.T) {
	line := strings.Repeat(strings.ReplaceAll(pemB64LineA, "+", `\u002B`), 40)
	text := []byte(pemTrig + "RSA PRIVATE KEY-----\\n" + line + "\\n" + pemB64LineB + "\\n-----END RSA PRIVATE KEY-----\\n")
	wantS, wantE, _ := wholeSpan(pemBlock, text, 0)
	for la := 1168; la < 1400; la++ {
		start, end, ok, _, _ := chainSpan(pemBlock, text, 0, la)
		if !ok || start != wantS || end < wantE {
			t.Fatalf("lookahead %d: chained [%d,%d) ok=%v, whole [%d,%d)", la, start, end, ok, wantS, wantE)
		}
	}
}

func TestKeyLineMarker(t *testing.T) {
	for _, tc := range []struct {
		in      string
		marker  byte
		content int
	}{
		{"+MIIE", '+', 1},
		{"-MIIE", '-', 1},
		{" MIIE", ' ', 1},
		{"  MIIE", ' ', 2},
		{"\tMIIE", 0, 1},
		{"MIIE", 0, 0},
		{"+> MIIE", '+', 3},
		{"> MIIE", 0, 2},
		{"> +MIIE", '+', 3},
		{">  MIIE", ' ', 3},
		{"> -MIIE", '-', 3},
		{"     18→-MIIE", '-', 11},
		{"     18→+MIIE", '+', 11},
		{"     18→ MIIE", ' ', 11},
		{"     18→MIIE", 0, 10},
		{"10→MIIE", 0, 5},
		{"\t\"MIIE", 0, 2},
		{"    + \"MIIE", 0, 7},
		{"# MIIE", 0, 2},
		{"#  MIIE", ' ', 3},
	} {
		m, c, _, _ := keyLineMarker([]byte(tc.in), 0, len(tc.in))
		if m != tc.marker || c != tc.content {
			t.Errorf("keyLineMarker(%q) = %q, %d; want %q, %d", tc.in, m, c, tc.marker, tc.content)
		}
	}
}

// TestPPKChainStepsBackslashRunLine: a stepped PuTTY line that ends in an
// escaped line feed whose backslash run fills a whole window is split so
// the next window still reads the escape, and the context line after it is
// counted as one scan of the whole input counts it.
func TestPPKChainStepsBackslashRunLine(t *testing.T) {
	for _, n := range []int{1170, 1200, 2500} {
		text := []byte(ppkTrig + "2:\n Private-Lines:1\n+" + pemB64LineA[:16] + "\n+0" + strings.Repeat(`\`, n) + "n 0")
		wantS, wantE, ok := wholeSpan(ppkBlock, text, 0)
		if !ok || wantE != len(text) {
			t.Fatalf("run %d: whole [%d,%d) ok=%v, want the last context line counted", n, wantS, wantE, ok)
		}
		for la := 1168; la < 1300; la++ {
			start, end, ok, _, _ := chainSpan(ppkBlock, text, 0, la)
			if !ok || start != wantS || end < wantE {
				t.Fatalf("run %d, lookahead %d: chained [%d,%d) ok=%v, whole [%d,%d)", n, la, start, end, ok, wantS, wantE)
			}
		}
	}
}

// A framed context line can start with an escaped base64 slash whose
// backslash run spans several windows, before any body byte is visible.
func TestPPKChainBodyStartsWithLongEscape(t *testing.T) {
	for _, n := range []int{1400, 2500, 4000} {
		text := []byte(ppkTrig + "2:\n Private-Lines:1\n+" + pemB64LineA[:16] + "\n" +
			strings.Repeat(" ", 65) + strings.Repeat(`\`, n) + "/")
		wantS, wantE, ok := wholeSpan(ppkBlock, text, 0)
		if !ok || wantE != len(text) {
			t.Fatalf("run %d: whole [%d,%d) ok=%v", n, wantS, wantE, ok)
		}
		for la := pemArmorWindowMin; la < pemArmorWindowMin+200; la++ {
			start, end, ok, _, _ := chainSpan(ppkBlock, text, 0, la)
			if !ok || start != wantS || end < wantE {
				t.Fatalf("run %d, lookahead %d: chained [%d,%d) ok=%v, whole [%d,%d)", n, la, start, end, ok, wantS, wantE)
			}
		}
	}
}

// TestPEMChainArmorQuoteBeforeBackslashRun: an escaped armor header line
// whose value ends in a quote, spaces and a backslash run longer than a
// window is decided the same in every window as in one scan of the whole
// input (a run over keyRunMax backslashes is no line break), so the chain
// does not end at the header line while the whole scan reads the body.
func TestPEMChainArmorQuoteBeforeBackslashRun(t *testing.T) {
	for _, n := range []int{100, 566, 3000} {
		text := []byte(pemTrig + `PRIVATE KEY-----\nA:` + strings.Repeat(`\"`, 11) + strings.Repeat("0", 1002) + `"` +
			strings.Repeat(" ", 24) + strings.Repeat(`\`, n))
		wantS, wantE, ok := wholeSpan(pemBlock, text, 0)
		if !ok {
			t.Fatalf("run %d: no key", n)
		}
		for la := pemArmorWindowMin; la < pemArmorWindowMin+900; la += 7 {
			start, end, ok, _, _ := chainSpan(pemBlock, text, 0, la)
			if !ok || start != wantS || end < wantE {
				t.Fatalf("run %d, lookahead %d: chained [%d,%d) ok=%v, whole [%d,%d)", n, la, start, end, ok, wantS, wantE)
			}
		}
	}
}
