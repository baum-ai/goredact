# Rule authoring

Built-in rules are declared in `internal/rules/specs/*.json` and compiled by
`go generate ./internal/rules`. Do not hand-edit the generated `zz_generated_*`
files.

Each rule needs a stable `id`, display `name`, one or more bounded literal
`triggers`, a validator name, minimum profile, confidence, maximum lookbehind
and lookahead, provenance, and both matching and non-matching synthetic
fixtures. Provider documentation is the preferred provenance source. Fixtures
must never be copied from live credentials.

Validators live in `internal/rules/validators`. They operate on byte slices,
must respect the supplied bounded window, must not retain or log source bytes,
and return only a half-open span. Validate prefix, length, alphabet, separators,
boundaries, and placeholders as applicable. A generic prefix requires
additional context or entropy validation; do not promote a heuristic rule into
the fast profile.

For a fixed-literal-prefix token rule (the trigger is the token's own prefix,
e.g. `ghp_`, `sk_live_`, `hvs.`, not a contextual keyword like a `password`
assignment), set `maxLookbehind: 1` and reject when the byte immediately
before the trigger is itself an identifier byte (`precededByIdentByte`, or an
equivalent check for a validator whose body alphabet includes `-`/`_` and so
needs a wider preceding-boundary set). This is what keeps the trigger from
firing on a false match embedded inside a longer identifier or opaque blob
(e.g. a base64-encoded blob that happens to contain `ghp_` mid-string).
Contextual rules keyed on an assignment or header (whose "boundary" is
already the separator/quote grammar around the value, not the trigger
literal itself) do not need this — see `consumeAssignedValue` and
`parseAssignmentValue` for that family's own boundary handling.

A rule whose secret is a delimited block of unbounded length (a private
key) names block functions next to its validator:
`"block": {"begin": "PEMPrivateKeyBegin", "extend": "PEMPrivateKeyExtend"}`
(see `rules.Block` and `docs/DESIGN.md`). The window validator must equal
`Begin` with `final` set. Detection must still be decided within the
trigger window; `Extend` only carries the masked extent on, as a resumable
scan whose stopping points leave every token it decides wholly in view.

Grammar anchored at the start of a line must also accept one leading
unified-diff marker (`+`, `-` or space) where a line in a patch can hold
the same text, since agent sessions and review bundles carry diffs. A check
that rejects a `-` before a fixed-prefix trigger (to avoid matching inside
`x-sk-...`) accepts a `-` that opens a line, as a removal marker. Any rule
that reads the diff marker of its trigger's line declares
`maxLookbehind: 2`, so the byte before that marker is in its window and
the start of the window is the start of a line only at the start of input
(`TestLineStartRulesSeeTheBytesBeforeTheirTrigger`).

A block rule reads every line of its block, so its line grammar must also
accept what a log or a source puts around each line: the escapes of a
string literal, a line frame (a quote or comment marker, a line number,
an indentation, an opening quote), the end of a concatenated string line
and a hunk header between two hunks. `internal/rules/validators/keylines.go`
holds those shapes for the private-key rules. A frame may sit between a
line's diff marker and its trigger, so those rules declare
`maxLookbehind: 72` (`keyLookbehind`: the marker, a frame of up to 65
bytes and a six-byte escaped line break before them;
`TestKeyLookbehindMatchesSpec`), and the start of
their window is the start of a line only when it holds fewer bytes before
the trigger.

After changing a rule:

```sh
go generate ./internal/rules
go generate ./internal/accuracy
gofmt -w internal/rules
go test ./...
go test -race ./...
```

Update `docs/PROFILES.md` when rule metadata changes. The generated accuracy
corpus requires positive and negative coverage for every built-in rule and
tests fixtures across chunk boundaries. When a rule overlaps Gitleaks semantics,
add it to the deliberately supported offline differential subset and compare
only sanitized aggregate results.

Embedding applications that need private rules should prefer `Config.CustomRules`
instead of editing generated built-ins. Custom validators have the same bounded
window and no-source-logging obligations.
