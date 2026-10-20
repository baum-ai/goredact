package validators

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// Block-scan tests: a key masked to its end marker however long it is, and
// in unified diff patches. The material is synthetic random base64, not
// real key material.

type blockFuncs struct {
	name    string
	trigger string
	begin   func([]byte, int, int, bool) (int, int, uint64, bool, bool)
	extend  func([]byte, uint64, bool) (int, uint64, bool)
}

var (
	pemBlock = blockFuncs{"pem", pemTrig, PEMPrivateKeyBegin, PEMPrivateKeyExtend}
	ppkBlock = blockFuncs{"ppk", ppkTrig, PuTTYPrivateKeyBegin, PuTTYPrivateKeyExtend}
)

// blockLookbehind is both key rules' lookbehind: the trigger line's diff
// marker and the byte before it.
const blockLookbehind = 2

// chainSpan replays the engine's windowing over text for a trigger at
// trigStart: Begin over the trigger window, then Extend over each
// following lookahead-sized window while the block is open. A window
// shorter than its lookahead ends the input (final). opened reports
// whether the first window left the block open; windows counts the Extend
// calls.
func chainSpan(f blockFuncs, text []byte, trigStart, lookahead int) (start, end int, ok, opened bool, windows int) {
	trigEnd := trigStart + len(f.trigger)
	ws := max(trigStart-blockLookbehind, 0)
	wEnd := min(trigEnd+lookahead, len(text))
	s, e, state, open, ok := f.begin(text[ws:wEnd], trigStart-ws, trigEnd-ws, wEnd < trigEnd+lookahead)
	if !ok {
		return 0, 0, false, false, 0
	}
	start, end, opened = ws+s, ws+e, open
	for open {
		base := end
		wEnd := min(base+lookahead, len(text))
		var e2 int
		e2, state, open = f.extend(text[base:wEnd], state, wEnd < base+lookahead)
		windows++
		end = base + e2
	}
	return start, end, true, opened, windows
}

// wholeSpan is the block decided in one window holding all of text.
func wholeSpan(f blockFuncs, text []byte, trigStart int) (start, end int, ok bool) {
	ws := max(trigStart-blockLookbehind, 0)
	s, e, _, _, ok := f.begin(text[ws:], trigStart-ws, trigStart-ws+len(f.trigger), true)
	return ws + s, ws + e, ok
}

func synthB64Lines(rng *rand.Rand, n, width int) []string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lines := make([]string, n)
	for i := range lines {
		b := make([]byte, width)
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		lines[i] = string(b)
	}
	return lines
}

// synthPGPKey is an ASCII-armored PGP private key block of at least size
// bytes: armor header, blank line, 64-column body, CRC24 line, footer.
func synthPGPKey(seed int64, size int) string {
	rng := rand.New(rand.NewSource(seed))
	body := synthB64Lines(rng, size/65+1, 64)
	return "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + strings.Join(body, "\n") +
		"\n=" + synthB64Lines(rng, 1, 4)[0] + "\n-----END PGP PRIVATE KEY BLOCK-----"
}

// synthPPK is a PuTTY key file whose private section has n lines.
func synthPPK(seed int64, n int) string {
	rng := rand.New(rand.NewSource(seed))
	pub := synthB64Lines(rng, 2, 64)
	priv := synthB64Lines(rng, n, 64)
	return "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: synthetic\n" +
		"Public-Lines: 2\n" + strings.Join(pub, "\n") + "\n" +
		fmt.Sprintf("Private-Lines: %d\n", n) + strings.Join(priv, "\n") + "\n" +
		"Private-MAC: 0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
}

// diffLines prefixes every line of s with marker, as a unified diff hunk
// body does.
func diffLines(marker, s string) string {
	s = strings.TrimSuffix(s, "\n")
	return marker + strings.ReplaceAll(s, "\n", "\n"+marker) + "\n"
}

// TestPEMBlockMasksToEndMarker is the acceptance case: a 40 KiB PGP
// private key, far past the 16 KiB lookahead, is masked from BEGIN through
// END by chaining windows, in every representation the scan accepts.
func TestPEMBlockMasksToEndMarker(t *testing.T) {
	key := synthPGPKey(1, 40<<10)
	forms := map[string]string{
		"raw":           key,
		"crlf":          strings.ReplaceAll(key, "\n", "\r\n"),
		"json escaped":  strings.ReplaceAll(key, "\n", `\n`),
		"double escape": strings.ReplaceAll(key, "\n", `\\n`),
		"diff added":    diffLines("+", key),
		"diff context":  diffLines(" ", key),
		"diff removed":  diffLines("-", key),
	}
	for name, block := range forms {
		for _, lookahead := range []int{16384, 1000, 257} {
			text := "prefix line\n" + block + "\nafter the key: plain text.\n"
			trigStart := strings.Index(text, pemTrig)
			wantEnd := strings.LastIndex(text, "BLOCK-----") + len("BLOCK-----")
			start, end, ok, opened, windows := chainSpan(pemBlock, []byte(text), trigStart, lookahead)
			if !ok || !opened || start != trigStart || end != wantEnd {
				t.Fatalf("%s, lookahead %d: span [%d,%d) ok=%v opened=%v, want [%d,%d)", name, lookahead, start, end, ok, opened, trigStart, wantEnd)
			}
			if windows < len(block)/lookahead-1 || windows > len(block)/(lookahead-pemResumeReserve-pemResumeLag)+2 {
				t.Errorf("%s, lookahead %d: %d extend windows for a %d-byte block", name, lookahead, windows, len(block))
			}
		}
	}
}

// TestPEMBlockUnterminated covers the fail-safe: without an END marker the
// block runs to the end of input (through the last base64 byte), or to the
// first byte that cannot be in a body.
func TestPEMBlockUnterminated(t *testing.T) {
	key := synthPGPKey(2, 40<<10)
	open := key[:strings.Index(key, "\n=")]
	cases := []struct {
		name, text string
		wantEnd    func(text string) int
	}{
		{"end of input", open, func(s string) int { return len(s) }},
		{"end of input with newline", open + "\n", func(s string) int { return len(s) - 1 }},
		{"cut mid line", open[:len(open)-30], func(s string) int { return len(s) }},
		{"junk ends it", open + "\n\"}, \"next\": 1}", func(s string) int { return strings.Index(s, "\n\"}") }},
	}
	for _, tc := range cases {
		for _, lookahead := range []int{16384, 700} {
			start, end, ok, _, _ := chainSpan(pemBlock, []byte(tc.text), 0, lookahead)
			if want := tc.wantEnd(tc.text); !ok || start != 0 || end != want {
				t.Fatalf("%s, lookahead %d: span [%d,%d) ok=%v, want [0,%d)", tc.name, lookahead, start, end, ok, want)
			}
		}
	}
}

// TestPEMBlockMarkerAcrossResumePoint slides an END marker and an escaped
// newline across every offset around the window boundaries: the chained
// scan must find the marker wherever the window cuts.
func TestPEMBlockMarkerAcrossResumePoint(t *testing.T) {
	const lookahead = 400
	rng := rand.New(rand.NewSource(3))
	for _, sep := range []string{"\n", `\n`, `\\\\n`} {
		for pad := 0; pad < 2*lookahead; pad += 7 {
			body := strings.Join(synthB64Lines(rng, 8, 64), sep) + sep + strings.Repeat("A", pad)
			text := "-----BEGIN RSA PRIVATE KEY-----" + sep + body + sep + "-----END RSA PRIVATE KEY-----" + sep + "tail"
			wantS, wantE, _ := wholeSpan(pemBlock, []byte(text), 0)
			start, end, ok, _, _ := chainSpan(pemBlock, []byte(text), 0, lookahead)
			if !ok || start != wantS || end != wantE {
				t.Fatalf("sep %q pad %d: chained [%d,%d), whole [%d,%d)", sep, pad, start, end, wantS, wantE)
			}
		}
	}
}

// TestPuTTYDiffPatch is the acceptance case for patches: PuTTY keys on
// diff lines are detected, and only their private sections are masked.
func TestPuTTYDiffPatch(t *testing.T) {
	ppk := synthPPK(4, 3)
	privStart := strings.Index(ppk, "Private-Lines:")
	privLines := strings.Split(ppk[privStart:strings.Index(ppk, "\nPrivate-MAC")], "\n")[1:]

	added := "diff --git a/k.ppk b/k.ppk\n@@ -0,0 +1,11 @@\n" + diffLines("+", ppk)
	start, end, ok := PuTTYPrivateKey([]byte(added), strings.Index(added, ppkTrig), strings.Index(added, ppkTrig)+len(ppkTrig))
	if !ok {
		t.Fatal("PuTTY key on + lines not detected")
	}
	if got := added[start:end]; !strings.HasPrefix(got, "Private-Lines: 3\n+") || !strings.HasSuffix(got, privLines[2]) {
		t.Fatalf("masked %q, want the private section from its header through its last line", got)
	}
	for _, line := range privLines {
		if !strings.Contains(added[start:end], line) {
			t.Fatalf("private line %q outside the span", line)
		}
	}
	if strings.Contains(added[start:end], "Private-MAC") || strings.Contains(added[start:end], "Public-Lines") {
		t.Fatalf("span %q covers more than the private section", added[start:end])
	}

	// A changed key: the header is a context line, the old private lines
	// and MAC are removed, the new ones added. Both versions are masked.
	rng := rand.New(rand.NewSource(5))
	oldPriv, newPriv := synthB64Lines(rng, 2, 64), synthB64Lines(rng, 2, 64)
	changed := "@@ -1,9 +1,9 @@\n PuTTY-User-Key-File-3: ssh-ed25519\n Encryption: none\n" +
		" Private-Lines: 2\n-" + oldPriv[0] + "\n-" + oldPriv[1] + "\n-Private-MAC: 00ff\n+" +
		newPriv[0] + "\n+" + newPriv[1] + "\n+Private-MAC: ff00\n"
	start, end, ok = PuTTYPrivateKey([]byte(changed), strings.Index(changed, ppkTrig), strings.Index(changed, ppkTrig)+len(ppkTrig))
	if !ok || !strings.HasSuffix(changed[start:end], newPriv[1]) || !strings.Contains(changed[start:end], oldPriv[0]) {
		t.Fatalf("changed key: ok=%v span %q, want both versions' private lines", ok, changed[start:end])
	}

	// The count changed too: the old header is removed, the new one added
	// after the old version's MAC line.
	recount := "@@ -1,6 +1,7 @@\n PuTTY-User-Key-File-3: ssh-ed25519\n-Private-Lines: 1\n-" + oldPriv[0] +
		"\n-Private-MAC: 00ff\n+Private-Lines: 2\n+" + newPriv[0] + "\n+" + newPriv[1] + "\n+Private-MAC: ff00\n"
	start, end, ok = PuTTYPrivateKey([]byte(recount), strings.Index(recount, ppkTrig), strings.Index(recount, ppkTrig)+len(ppkTrig))
	if !ok || !strings.HasSuffix(recount[start:end], newPriv[1]) || !strings.Contains(recount[start:end], oldPriv[0]) {
		t.Fatalf("recounted key: ok=%v span %q, want both versions' private lines", ok, recount[start:end])
	}

	// Markers are only accepted one deep, and body lines need theirs.
	for name, text := range map[string]string{
		"two markers":            "PuTTY-User-Key-File-2: ssh-rsa\n+-Private-Lines: 1\n+" + oldPriv[0] + "\n",
		"unmarked body in diff":  "PuTTY-User-Key-File-2: ssh-rsa\n+Private-Lines: 1\n" + pemB64LineA + "\n",
		"public section in diff": "+PuTTY-User-Key-File-2: ssh-rsa\n+Public-Lines: 1\n+" + oldPriv[0] + "\n",
	} {
		if _, _, ok := PuTTYPrivateKey([]byte(text), strings.Index(text, ppkTrig), strings.Index(text, ppkTrig)+len(ppkTrig)); ok {
			t.Errorf("%s: confirmed, want no match", name)
		}
	}
}

// TestPuTTYBlockChains masks a private section longer than the lookahead,
// plain and on diff lines.
func TestPuTTYBlockChains(t *testing.T) {
	ppk := synthPPK(6, 600) // ~39 KiB private section
	for name, text := range map[string]string{"plain": ppk, "diff": diffLines("+", ppk)} {
		wantStart := strings.Index(text, "Private-Lines:")
		macLine := strings.Index(text, "Private-MAC")
		wantEnd := strings.LastIndex(text[:macLine], "\n")
		if name == "diff" {
			wantEnd = strings.LastIndex(text[:macLine-1], "\n")
		}
		for _, lookahead := range []int{16384, 1000} {
			start, end, ok, opened, _ := chainSpan(ppkBlock, []byte(text), strings.Index(text, ppkTrig), lookahead)
			if !ok || !opened || start != wantStart || end != wantEnd {
				t.Fatalf("%s, lookahead %d: span [%d,%d) ok=%v opened=%v, want [%d,%d)", name, lookahead, start, end, ok, opened, wantStart, wantEnd)
			}
		}
	}
}

// TestBlockDecidedAtWindowEdge covers keys confirmed only by the last
// bytes of their trigger window: they are still followed to their end.
func TestBlockDecidedAtWindowEdge(t *testing.T) {
	const lookahead = 16384
	rng := rand.New(rand.NewSource(10))
	body := strings.Join(synthB64Lines(rng, 600, 64), "\n")

	// PEM: the 16th byte of the first body line is the window's last byte.
	begin := "-----BEGIN RSA PRIVATE KEY-----"
	pem := begin + strings.Repeat("\n", lookahead-(len(begin)-len(pemTrig))-16) + body + "\n-----END RSA PRIVATE KEY-----\ntail"
	start, end, ok, opened, _ := chainSpan(pemBlock, []byte(pem), 0, lookahead)
	if want := strings.Index(pem, "\ntail"); !ok || !opened || start != 0 || end != want {
		t.Fatalf("pem: span [%d,%d) ok=%v opened=%v, want [0,%d)", start, end, ok, opened, want)
	}

	// PPK: the window cuts the first private line after its 16th byte.
	head := "PuTTY-User-Key-File-3: ssh-rsa\nComment: "
	tailOfHeader := "\nPrivate-Lines: 600\n"
	comment := lookahead + len(ppkTrig) - len(head) - len(tailOfHeader) - 20
	ppk := head + strings.Repeat("c", comment) + tailOfHeader + body + "\nPrivate-MAC: 00\n"
	start, end, ok, opened, _ = chainSpan(ppkBlock, []byte(ppk), 0, lookahead)
	wantStart, wantEnd := strings.Index(ppk, "Private-Lines"), strings.Index(ppk, "\nPrivate-MAC")
	if !ok || !opened || start != wantStart || end != wantEnd {
		t.Fatalf("ppk: span [%d,%d) ok=%v opened=%v, want [%d,%d)", start, end, ok, opened, wantStart, wantEnd)
	}
}

// TestBlockBeginFinalMatchesValidate pins the contract rules.Block relies
// on: Begin with final set is the window validator.
func TestBlockBeginFinalMatchesValidate(t *testing.T) {
	samples := []string{
		rawPEM("RSA PRIVATE KEY"), escapedPEM("EC PRIVATE KEY"), synthPGPKey(7, 3000),
		rawPPK("2", "Private-Lines: 2\n"+pemB64LineB+"\n"+pemB64LineC+"\n"), diffLines("+", synthPPK(8, 4)),
	}
	for _, sample := range samples {
		for cut := 0; cut <= len(sample); cut += 1 + cut/50 {
			window := []byte(sample[:cut])
			for _, f := range []struct {
				blockFuncs
				validate func([]byte, int, int) (int, int, bool)
			}{{pemBlock, PEMPrivateKey}, {ppkBlock, PuTTYPrivateKey}} {
				ts := bytes.Index(window, []byte(f.trigger))
				if ts < 0 {
					continue
				}
				s1, e1, ok1 := f.validate(window, ts, ts+len(f.trigger))
				s2, e2, _, open, ok2 := f.begin(window, ts, ts+len(f.trigger), true)
				if open || ok1 != ok2 || ok1 && (s1 != s2 || e1 != e2) {
					t.Fatalf("%s cut %d: Validate (%d,%d,%v) != Begin final (%d,%d,%v,open=%v)", f.name, cut, s1, e1, ok1, s2, e2, ok2, open)
				}
			}
		}
	}
}

// FuzzBlockChainMatchesWholeScan checks the resumable scans: whenever the
// trigger window leaves a block open, chaining windows masks at least what
// one window holding the whole input does, from the same start, and only
// what a resume point had to mask on top: separators past a PEM body's
// last base64 byte, or PPK lines stepped over (at most a window and a
// line). Otherwise the block is decided within the trigger window alone.
func FuzzBlockChainMatchesWholeScan(f *testing.F) {
	f.Add([]byte("RSA PRIVATE KEY-----\n"+pemB64LineA+"\n"+pemB64LineB+"\n-----END RSA PRIVATE KEY-----\n"), uint8(0), uint16(300))
	f.Add([]byte("2: ssh-rsa\n+Private-Lines: 3\n+"+pemB64LineA+"\n+"+pemB64LineB+"\n+"+pemB64LineC+"\n"), uint8(1), uint16(200))
	f.Add([]byte(`EC PRIVATE KEY-----\n`+pemB64LineA+`\\n`+pemB64LineB+`\n-----END EC PRIVATE KEY-----\n"}`), uint8(0), uint16(260))
	f.Fuzz(func(t *testing.T, data []byte, which uint8, la uint16) {
		if len(data) > 8<<10 {
			data = data[:8<<10]
		}
		fn := pemBlock
		if which%2 == 1 {
			fn = ppkBlock
		}
		text := append([]byte(fn.trigger), data...)
		lookahead := 2*pemResumeReserve + pemResumeLag + 1 + int(la)%1024

		start, end, ok, opened, _ := chainSpan(fn, text, 0, lookahead)
		var wantS, wantE int
		var wantOK bool
		if opened {
			wantS, wantE, wantOK = wholeSpan(fn, text, 0)
		} else {
			wEnd := min(len(fn.trigger)+lookahead, len(text))
			wantS, wantE, wantOK = wholeSpan(fn, text[:wEnd], 0)
		}
		longest := 0
		for _, line := range bytes.Split(text, []byte("\n")) {
			longest = max(longest, len(line))
		}
		over := end - wantE
		// PPK lines stepped over while a header may still come (within
		// ppkHeaderReach of the trigger), and past it up to ppkMaxStepLines
		// of at most ppkMaxStepLine bytes, are masked across windows.
		extraOK := end <= max(wantE, len(fn.trigger)+ppkHeaderReach)+lookahead+longest+ppkMaxStepLines*(ppkMaxStepLine+1)
		if fn.name == "pem" && over > 0 {
			extraOK = pemSeparatorsOnly(text[wantE:end])
		}
		if ok != wantOK || ok && (start != wantS || over < 0 || !opened && over != 0 || !extraOK) {
			t.Fatalf("%s lookahead %d opened=%v: chained (%d,%d,%v), want (%d,%d,%v)", fn.name, lookahead, opened, start, end, ok, wantS, wantE, wantOK)
		}
		if ok && (start < 0 || end <= start || end > len(text)) {
			t.Fatalf("span [%d,%d) outside the input (len %d)", start, end, len(text))
		}
	})
}

// TestBlockExtendArbitraryState feeds Extend arbitrary states and windows:
// it must not panic and must stay within its window.
func TestBlockExtendArbitraryState(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	for iter := 0; iter < 2000; iter++ {
		window := make([]byte, rng.Intn(600))
		rng.Read(window)
		if iter%2 == 0 {
			copy(window, "\n+"+pemB64LineA+"\n-----END RSA PRIVATE KEY-----")
		}
		for _, f := range []blockFuncs{pemBlock, ppkBlock} {
			end, _, open := f.extend(window, rng.Uint64(), rng.Intn(2) == 0)
			if end < 0 || end > len(window) || open && end == 0 {
				t.Fatalf("%s: Extend returned end %d open %v for window length %d", f.name, end, open, len(window))
			}
		}
	}
}

// TestPPKHeaderReachMatchesSpec: ppkHeaderReach, how far past its trigger
// a PPK header may start, is the putty-private-key rule's lookahead, so a
// key's headers are found within the window its detection is decided in.
func TestPPKHeaderReachMatchesSpec(t *testing.T) {
	data, err := os.ReadFile("../specs/private-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Rules []struct {
			ID           string `json:"id"`
			MaxLookahead int    `json:"maxLookahead"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for _, r := range spec.Rules {
		if r.ID == "putty-private-key" && r.MaxLookahead != ppkHeaderReach {
			t.Fatalf("putty-private-key maxLookahead %d, ppkHeaderReach %d", r.MaxLookahead, ppkHeaderReach)
		}
	}
}

// pemSeparatorsOnly reports whether b holds no key material: only bytes a
// PEM body scan passes between base64 runs (whitespace, ':', ',', '-',
// and backslash escapes).
func pemSeparatorsOnly(b []byte) bool {
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case c == '\\':
			for i+1 < len(b) && b[i+1] == '\\' {
				i++
			}
			if i+1 < len(b) && strings.IndexByte("nrt\"", b[i+1]) >= 0 {
				i++
			}
		case pemBase64[c]:
			return false
		}
	}
	return true
}
