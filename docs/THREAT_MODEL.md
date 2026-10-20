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
   produce identical output, independent of chunking.

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
| Truncated multiline blocks (PEM) buffering forever | Detection is decided in a bounded window; a confirmed key is followed window by window to its end marker and masked whole, while its held interior is discarded under buffer pressure, so memory stays bounded; an unterminated block fails safe, masked through its last body byte at end of input; a key marker nested in an open key cannot start a second chain |
| Multiline keys in diff patches | Line-anchored key grammar accepts one leading unified-diff marker (`+`, `-`, space) and counts the old and new file versions separately |
| Panic on malformed input | Fuzzing of validators, parsers, span merging, and streaming boundaries; invalid UTF-8 and arbitrary bytes are first-class inputs |
| Secret appears in error text | Error paths carry no input bytes by construction; enforced by tests and review |

## Residual risks

- Detection is rule-based; unknown providers and unstructured secrets can
  pass through. Consumers needing stronger guarantees should treat the
  output as *reduced-risk*, not *guaranteed-clean*.
- ASCII case folding only; exotic Unicode case tricks on trigger keywords
  can evade contextual detection.
