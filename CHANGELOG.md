# Changelog

All notable changes are documented here. This project follows semantic
versioning.

## Unreleased

- **Fixed:** private keys are masked to their end, however long. The
  `pem-private-key` and `putty-private-key` rules read at most 16 KiB past
  their trigger, so a longer key — a large PGP private key block, for one —
  kept its tail unmasked. Both rules still decide within that window, then
  follow a key window by window to its END marker (or the end of its
  Private-Lines section) and mask it as one finding. An unterminated key is
  masked through its last body byte at the end of input. Memory stays
  bounded and the work linear: a key longer than the buffer has its
  interior discarded, and a key marker nested in an open key cannot start a
  second scan. Output inside a key that runs past the window is held until
  the key ends. Callers that bound how far a span reaches past its trigger
  (for example to cut text after redaction) must treat key blocks as
  unbounded; detection still needs no more than 16 KiB past the trigger.
- **Fixed:** PuTTY keys in unified diff patches. `putty-private-key`
  required `Private-Lines:` at the start of a line, so a key on the `+`
  lines of a patch was never detected. A header behind one diff marker
  (`+`, `-` or space) now reads marked body lines and counts the old and
  new file versions separately, so added, removed and changed keys are
  masked and their public lines kept. PEM keys in patches were already
  detected and are now masked to their end too.
- **Fixed:** the other checks anchored on what precedes a trigger accept a
  diff removal marker. `command-line-password-flag` rejected
  `---password=...` and `openai-legacy-key` and `deepseek-api-key` rejected
  a `-` before `sk-`; a `-` that opens a line now counts as a boundary, so
  a flag or key starting a removed line is masked. The two key rules'
  lookbehind grows from 1 to 2 bytes.
- Under `MaskLengthPreserving` and `MaskFormatPreserving`, the interior of
  a key longer than `ChunkSize` is emitted as `*` bytes: masked, but its
  shape depends on the chunk size.
- Internal: block rules (`rules.Block`, the rulegen spec field `block`) and
  their engine continuation; the rule-set version changes. New benchmark
  `BenchmarkRedactLongKeyBlocks` (570 MB/s on input that is mostly 64 KiB
  keys, against 430 MB/s for v0.2.0, which masked only their first 16 KiB;
  the quiet and noisy benchmarks are unchanged) and fuzz target
  `FuzzBlockChainMatchesWholeScan`.

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
