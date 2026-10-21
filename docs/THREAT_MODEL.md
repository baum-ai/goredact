# Threat model — goredact v0.1

## Purpose

goredact removes secret values from large text streams (agent session logs,
CI output, shell transcripts, environment dumps) before they are stored or
uploaded. It is a *data-loss-prevention filter*, not an access-control or
credential-management mechanism.

## Assets

- **Secret values** present in the input stream: provider API tokens,
  passwords, private keys, session cookies, connection-string credentials.
- **The redacted output**: consumers rely on it being safe to store, index,
  and share.

## Trust boundaries

- **Input is untrusted.** The scanned stream may be adversarial: crafted to
  cause pathological CPU or memory use, malformed UTF-8, arbitrary binary,
  truncated structures, or keyword floods. The library must remain
  correct, bounded, and panic-free on any byte sequence. The panic-free
  guarantee covers the engine's own processing of input bytes; a panic
  inside a caller-supplied `CustomRule.Validate` is caught and returned as
  an error naming the rule, per the API documentation.
- **The host process is trusted.** goredact does not defend against a
  compromised process, debugger, or memory scraping.
- **Callers of the API are trusted** to wire dst/src correctly. Custom-rule
  validators run in-process with full access to candidate windows; a
  malicious custom rule can exfiltrate data and is out of scope.

## Security guarantees

1. **No secret persistence.** The library never writes unredacted input to
   temporary files or any storage; all buffering is in fixed-size memory.
2. **No secret leakage through diagnostics.** Errors, findings, statistics,
   and any log-like output contain rule IDs, offsets, and counts — never
   matched input bytes. Errors from caller-supplied readers/writers are
   propagated as-is (their content is the caller's responsibility).
3. **Bounded resources.** Memory is O(chunk size + rule-set constants),
   independent of input size. CPU per byte is bounded; no detector performs
   unbounded backtracking or whole-input analysis.
4. **Fail closed at boundaries.** Bytes are emitted only once no active
   rule could still confirm a secret overlapping them. On error, already
   emitted output contains no unredacted confirmed secret.
5. **Determinism.** Identical input + configuration + rule-set version
   produce identical output, independent of chunking. (Exception: under
   `MaskLengthPreserving` and `MaskFormatPreserving`, the interior of a
   span longer than `ChunkSize`, such as a large private key, is discarded
   under buffer pressure and emitted as `*` bytes, so its masked shape
   depends on the chunk size. It is masked either way, and the default
   `MaskFixedMarker` output does not depend on it.)

## Explicit non-guarantees (v0.1)

- **Encoded or obfuscated secrets**: base64/hex-wrapped secrets (except
  formats detected natively), URL-encoding beyond standard cases, rot13,
  compression, encryption, homoglyph substitution.
- **Split secrets**: values fragmented across records, interleaved streams,
  or reassembled by the consumer.
- **Novel formats**: secrets with no detectable structure or context (e.g.
  a random string pasted with no keyword nearby) may evade contextual
  detection, particularly in the fast profile.
- **PII** (names, emails, addresses) is out of scope.
- **Validity**: findings are not verified against providers; revoked or
  fake-but-well-formed tokens are still redacted (by design).

## Failure-mode analysis

| Failure | Mitigation |
| --- | --- |
| Adversarial keyword floods causing validator storms | Validators run on bounded windows; per-candidate cost is capped; benchmarks include candidate-heavy corpora |
| Secrets straddling chunk boundaries | Rule-derived overlap retention; fixtures test every boundary position |
| Truncated multiline blocks (PEM) buffering forever | Detection is decided in a bounded window; a confirmed key is followed window by window to its end marker and masked whole, while its held interior is discarded under buffer pressure, so memory stays bounded; an unterminated block fails safe, masked through its last body byte at end of input; every key marker is followed on its own, and scans of the same bytes meet on a fixed grid and merge, so nested markers cannot multiply the work |
| Multiline keys in diff patches | Key grammars accept one leading unified-diff marker (`+`, `-`, space); a key follows the file versions of its trigger line, closes only on its own versions' END lines (PEM), and counts each version's PPK section separately, stepping over the other version's lines; a hunk header inside a key is masked with it and the key followed into the next hunk |
| Keys in string literals or behind line prefixes | Key grammars read JSON escapes (any backslash run, PHP's `\/`, .NET's `\u002B`), skip a bounded line frame of at most 64 bytes at the start of every line — quote markers (`> `, `> > `), comment markers (`#`, `//`, `;`, ` * `, `%`), line numbers followed by a tab, `→` (raw or `\u2192`), `\|`, `:` or `│` (`cat -n`, agent transcripts, `grep -n`, bat), indentation, opening quotes and leading `+`/`&`/`.` — with a diff marker before or after it, and the end of a concatenated string line (`"...\n" +`, `" .`, `" & _`), so such a key is masked whole. Other per-line prefixes (log timestamps, `svc-1  \| `, `kubectl --prefix`) are not recognised |
| Undercounted PuTTY sections | Base64 lines past a too-low `Private-Lines` count are masked up to the `Private-MAC` line, at most 100 lines of at most 512 bytes |
| Panic on malformed input | Fuzzing of validators, parsers, span merging, and streaming boundaries; invalid UTF-8 and arbitrary bytes are first-class inputs |
| Secret appears in error text | Error paths carry no input bytes by construction; enforced by tests and review |

## Residual risks

- Detection is rule-based; unknown providers and unstructured secrets can
  pass through. Consumers needing stronger guarantees should treat the
  output as *reduced-risk*, not *guaranteed-clean*.
- ASCII case folding only; exotic Unicode case tricks on trigger keywords
  can evade contextual detection.
