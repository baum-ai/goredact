# Changelog

All notable changes are documented here. This project follows semantic
versioning.

## Unreleased

- **Fixed:** private keys in string literals escaped by PHP and .NET JSON
  encoders. `json_encode` writes '/' as `\/` and System.Text.Json writes
  '+' as `\u002B` (and '"' as `\u0022`); the key scans stopped at the first
  such escape, so only the BEGIN line and the first base64 run were masked,
  or nothing. Both rules now read `\/`, `\uXXXX` escapes of base64 bytes and
  separators, and escaped line feeds after any backslash run (JSON inside
  JSON).
- **Fixed:** keys whose lines carry a prefix were not detected: quoted in
  an email or Markdown (`> `, `> > `, `>> `), commented out (`# `, ` * `,
  `; `), line-numbered as tools show a file (`     12→` from agent
  transcripts, raw or as `\u2192`; `  12 | ` and `12|`; `12:` from
  `grep -n` and `rg -n`; `12│` from bat; `12<tab>` from `cat -n`), or
  concatenated from one string literal per line (`"...\n" +`,
  `+ "...\n"`, `'...' +`, `"...\n" .`, `"...\n"..`, `" & vbLf & _`, in
  Go, Java, JavaScript, Python, PHP, Lua and Visual Basic sources). At
  the start of every line, after a raw or an escaped line feed, the scans
  skip a line frame of up to 64 bytes (65 when it starts with a space) —
  quote and comment markers (a `//` followed by base64 is key content), a
  line number followed by optional spaces and a tab, an arrow, '|', ':'
  or a box-drawing bar, an indentation, an opening quote, a leading `+`,
  `&`, `.` or `..` (before a space, a quote or the line break), each raw
  or escaped (`\u003e` as Go's encoding/json writes '>', `\/\/`) — and
  take a quote closing a string literal's line with its line break. A
  line number may change width without padding (` 9→` then `10→`). A diff
  marker may precede the frame (`+> `, `+\t"` on a patch of Go source) or
  follow it (`    18→-`, `> +`, `>-` on a numbered or quoted patch), so both
  rules' lookbehind grows from 2 to 67 bytes to read the trigger line from
  its start; a removed line's `-` before a frame is read too when the
  trigger line holds more than a marker and a frame
  (`-var key = "-----BEGIN`). RFC 4880 armor header lines may carry any
  diff marker, list bullet or none, whatever the BEGIN line starts with.
  `// ` comments and `cat -n` line numbers were already masked.
- **Fixed:** PuTTY keys JSON-escaped (lines broken by `\n`) or indented by
  two or more spaces (a YAML block) were never detected. The
  `Private-Lines:` header and the body lines are read with the same
  frames, escapes and line ends as PEM lines; a header indented by spaces
  reads as a context line, so its body lines are counted as context.
- **Fixed:** a key spanning two hunks of a patch leaked from the second
  hunk on: the scans stopped at the `@@ -a,b +c,d @@` header. A hunk header
  inside a key — also behind a frame or a marker (`    40→@@ -40,7`,
  `> @@`, `+@@`) — is now skipped and masked with the key (git may put a
  key line in its section heading), and the key is followed into the next
  hunk, for PEM and PuTTY keys. A PuTTY key rotated in a numbered or
  quoted patch is read with each line's marker after its frame.
- **Fixed:** base64 lines past a PuTTY `Private-Lines` count that is too
  low leaked. Up to 100 further lines of at most 512 bytes each, line end
  included, are masked up
  to the `Private-MAC:` line: a line of 16 or more base64 bytes, one that
  ends with '=' padding, or a shorter one directly before the MAC line,
  also in a patch (on a version whose count is done, past hunk headers).
  A well-formed file is masked as before.
- The rule-set version changes. The balanced profile's streaming lag
  bound grows by 65 bytes (the key rules' lookbehind), to 16,633 bytes,
  and the smallest accepted `Config.ChunkSize` with both key rules active
  from 32,812 to 32,942 bytes: `New` now rejects a `ChunkSize` from 32,812
  to 32,941 that v0.3.0 accepted.
- Internal: new fuzz target `FuzzEngineKeyShapes` runs the block checks on
  key-shaped text behind line prefixes, concatenated, JSON-escaped and
  split by hunk headers; new synthetic fixtures for quoted, escaped,
  concatenated and indented keys. `BenchmarkRedactLongKeyBlocks` runs
  about 4% slower (about 600 MB/s); the quiet and noisy benchmarks and
  `make bench-ci` are unchanged. In the worst cases, floods of BEGIN lines
  each starting a scan of its 16 KiB window, a bare flood drops from about
  7.0 to about 4.9 MB/s, and a flood of short keys behind line numbers and
  diff markers (`    12→+> -----BEGIN …`, which v0.3.0 did not scan) runs
  at about 2.3 MB/s. Both stay linear: at most one 16 KiB window of
  scanning per trigger, as in v0.3.0.

## v0.3.0 — 2026-10-20

- **Fixed:** private keys are masked to their end, however long. The
  `pem-private-key` and `putty-private-key` rules read at most 16 KiB past
  their trigger, so a longer key — a large PGP private key block, for one —
  kept its tail unmasked. Both rules still decide within that window, then
  follow a key window by window to its END marker (or the end of its
  Private-Lines section) and mask it as one finding. An unterminated key is
  masked through its last body byte at the end of input. Every key marker
  is followed on its own, so a key nested in another is masked to its own
  end; scans of the same bytes meet and merge, so the work stays linear,
  and a key longer than the buffer has its interior discarded, so memory
  stays bounded. Where a scan resumes past a long run of separators or a
  backslash run, those bytes are masked with the key even if it ends right
  after them. Output inside a key that runs past the window is held until
  the key ends. Callers that bound how far a span reaches past its trigger
  (for example to cut text after redaction) must treat key blocks as
  unbounded; detection still needs no more than 16 KiB past the trigger.
- **Fixed:** PuTTY keys in unified diff patches. `putty-private-key`
  required `Private-Lines:` at the start of a line, so a key on the `+`
  lines of a patch was never detected. A header behind one diff marker
  (`+`, `-` or space) now reads marked body lines and counts the old and
  new file versions separately. A key follows the versions of its own
  `PuTTY-User-Key-File-` line: an added key the new file, a removed key the
  old one, a key whose first line is unchanged context both, stepping over
  the other version's lines and its public lines until each version's
  `Private-Lines:` header (within 16 KiB of the trigger; a stepped line
  may end at most 512 bytes past that reach or past its own start, and
  past the reach a section waiting for more lines ends after 64 stepped
  lines). Added, removed, changed and rotated keys —
  to another type or size, as `git diff` shows them — are masked; public
  lines between two private sections of a changed key may be masked too. A
  private line longer than the window is masked as far as it goes.
- **Fixed:** PEM keys in patches follow their file version: an END line
  on `-` lines no longer closes a key on `+` lines, nor the reverse, and a
  context END closes both. Both key rules' lookbehind grows from 0 to 2
  bytes to see the trigger line's marker.
- **Fixed:** RFC 4880 armor headers after a BEGIN line (`Version: GnuPG
  v1.4.11 (GNU/Linux)`, `Comment: "Alice" <alice@example.com>`) are taken
  whole, so their bytes no longer end the scan before the key body; GnuPG
  1.x keys were not detected at all. Up to 32 header lines of up to 1 KiB
  are accepted, indented (as in a YAML block) or on diff lines, with ": ",
  ":\t" or a bare ':' after the key, raw or JSON-escaped. Headers that run
  past the 16 KiB window are followed into the next one, and such a block
  is masked as a key even before its body is seen.
- **Fixed:** the other checks anchored on what precedes a trigger accept a
  diff removal marker. `command-line-password-flag` rejected
  `---password=...` and `openai-legacy-key` and `deepseek-api-key` rejected
  a `-` before `sk-`; a `-` that opens a line now counts as a boundary, so
  a flag or key starting a removed line is masked. The two key rules'
  lookbehind grows from 1 to 2 bytes.
- Under `MaskLengthPreserving` and `MaskFormatPreserving`, the interior of
  a key longer than `ChunkSize` is emitted as `*` bytes: masked, but its
  shape depends on the chunk size.
- The balanced profile's streaming lag bound grows by 2 bytes (the key
  rules' lookbehind).
- Internal: block rules (`rules.Block`, the rulegen spec field `block`) and
  their engine continuation; the rule-set version changes. New benchmark
  `BenchmarkRedactLongKeyBlocks` (about 615 MB/s on input that is mostly
  64 KiB keys, against 430 MB/s for v0.2.0, which masked only their first
  16 KiB; the quiet and noisy benchmarks are unchanged) and fuzz targets
  `FuzzBlockChainMatchesWholeScan` and `FuzzEngineBlocks`.

## v0.2.0 — 2026-10-14

- **Breaking:** the module path is now `github.com/baum-ai/goredact`,
  following the GitHub org rename from `lastpersonlabs` to `baum-ai`.
  Importers must update their import paths and `go.mod` requirements; the
  old path stays at v0.1.0 and receives no further releases. The copyright
  holder is now Baum AI and the security contact is
  `security@usebaum.com`.
- Documentation: README repositioned around the filter-versus-auditor
  distinction, with explicit guidance on when to reach for a repository
  auditor instead, the measured streaming latency bound, and a benchmark
  summary that spans the candidate spectrum rather than the no-trigger
  corpus alone.
- `scripts/benchmark-betterleaks.zsh` takes an optional fifth argument
  labelling the corpus scenario in its reported rows, so candidate-bearing
  comparisons are not mislabelled as `quiet`.
- `docs/BENCHMARKS.md` records a three-scenario one-core comparison against
  Betterleaks 1.7.4, including the disjoint-detection caveat and the
  `confirmed-secret` corpus defect behind it.
- `THIRD_PARTY.md` records the dependency releases actually required by
  `go.mod` (`klauspost/compress` v1.19.2, `spf13/cobra` v1.10.2,
  `spf13/pflag` v1.0.10); the previous entries and their pinned licence-file
  URLs still named v1.18.0, v1.10.1, and v1.0.9.
- New `TestThirdPartyRegisterMatchesGoMod`: every module in `go.mod` must
  have a provenance entry whose recorded release and pinned licence-file URL
  match the required version.
- New `TestProfilesDocMatchesBuiltins`: `docs/PROFILES.md`'s rule table,
  total rule count, and per-profile counts are checked against the compiled
  `Builtins()` table, so the hand-maintained inventory can no longer drift
  from the shipped rules unnoticed.

## v0.1.0 — 2026-08-17

Initial release.

- Bounded-memory `io.Reader` to `io.Writer` redaction API with deterministic
  span merging, cancellation, typed I/O errors, and record-aligned streaming.
- Fast, balanced, and deep profiles; rule introspection, allow/deny lists, and
  custom validators.
- Deterministic provider, contextual credential, entropy, URL/header/cookie,
  and multiline private-key detection.
- Generated rule schema with provenance and synthetic fixtures.
- Accuracy corpus, sanitized offline Gitleaks differential harness, fuzz and
  property tests, and reproducible large-corpus benchmark tooling.
- Reference CLI with stream and recursive directory commands, optional secret
  display in JSON/CSV/JUnit/SARIF reports, streaming zstd, and a bounded
  multipart-upload example. Directory scans emit a count-only findings summary
  on standard error.
- Cobra-based CLI with discoverable command and flag help, conventional long
  and shorthand flags, version output, typo suggestions, examples, argument
  validation, and generated shell completion.
- Add a standalone JWT detection rule (`jwt`, balanced profile): bare
  `header.payload.signature` JWS compact serializations in transcripts,
  logs, and tool output are now caught without needing cookie or header
  context.
- Add `Config.MaskStrategy` with `MaskFixedMarker` (default, unchanged
  behavior), `MaskLengthPreserving` (`*` fill, output length equals input
  length), and `MaskFormatPreserving` (per-character-class substitution
  that keeps token shapes), plus a `--mask` flag on `goredact stream`.
- Detect `session_secret` and `secret_key_base` assignment families.
- Make directory scans parallel and deterministic while reusing compiled
  engines across files.
- Apply Gitleaks-compatible default dependency, generated-file, media, and
  binary path exclusions during recursive directory scans.
- `scripts/benchmark-betterleaks.zsh` takes an optional GoRedact profile
  argument; `docs/BENCHMARKS.md` adds a cross-profile (`fast`/`balanced`/`deep`)
  one-core comparison against Betterleaks.
- Public API types (`Config`, `Engine`, `Finding`, `Stats`, `RuleInfo`,
  `Profile`, `Confidence`, `MaskStrategy`, `ReadError`, `WriteError`) are no
  longer bare aliases into the internal implementation package, so
  `go doc`/pkg.go.dev now render their field and method documentation.
- `Stats.Findings` is `int64` and `Stats.ByRule`'s values are `int64`,
  matching the other counters on `Stats`.
- Fixed several validator inconsistencies found in a pre-publish review:
  `SlackUserToken` now rejects placeholder digit segments like
  `SlackBotToken` already did; `DopplerToken`'s optional config-label
  grammar is scoped to the `dp.st.` prefix that actually documents one,
  instead of over-matching all seven scoped prefixes; every
  fixed-literal-prefix token rule (GitHub, GitLab, npm, PyPI, Docker Hub,
  Stripe, Vault, Vercel, Doppler) now rejects a trigger embedded inside a
  longer identifier or blob, matching the convention already used by
  AWS/GCP/Hugging Face/Groq/OpenAI/Cursor rules.
- A panic inside a custom rule's `Validate` no longer propagates out of
  `Redact`: it is caught and returned as an error naming the rule, the panic
  value never appears in the error, and output already written remains valid
  redacted output.
- The streaming output path retries short writes instead of silently
  dropping bytes, and rejects destinations that report impossible byte
  counts or make no progress.
- `New` rejects custom rules whose validation-window bounds overflow instead
  of compiling them with wrapped windows.
- Directory scans reject report paths that alias a scanned input, so a
  findings report can never overwrite or be overwritten by a file under scan.

Release evidence and known detection limits are documented in `docs/ACCURACY.md`,
`docs/BENCHMARKS.md`, and `docs/THREAT_MODEL.md`.
