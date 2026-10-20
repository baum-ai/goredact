# goredact

[![CI](https://github.com/baum-ai/goredact/actions/workflows/ci.yml/badge.svg)](https://github.com/baum-ai/goredact/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/baum-ai/goredact.svg)](https://pkg.go.dev/github.com/baum-ai/goredact)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`goredact` is a pure-Go, bounded-memory **redaction filter**: it reads a byte
stream, writes the same stream back with secrets replaced, and never holds
more than a fixed window of input. It is built for the data path — agent
sessions, log shippers, environment dumps, upload pipelines — where plaintext
must not be buffered whole, spilled to a temporary file, or delayed until a
scan finishes.

## What it is, and what it is not

The distinction that matters is not "faster scanner". It is **filter versus
auditor**, and the two are complements:

| | `goredact` | Gitleaks / Betterleaks |
| --- | --- | --- |
| Shape | `Redact(ctx, dst, src)` — bytes in, redacted bytes out | scan a repository, emit a findings report |
| Output | the sanitized stream itself | JSON/SARIF/CSV findings; `--redact` masks the *report*, never the content |
| Memory | fixed: `ChunkSize` + rule-set window, independent of input size and finding count | grows with findings; the reporter needs the complete result set |
| Latency | first output after one rule window of input, then continuous | nothing until the scan completes |
| Rules | 67 built-in, literal triggers plus bounded Go validators, no regex on the scan path | several hundred regexes, plus decoding, archives, git history, live credential validation |
| Scope | one stream | repositories, commit history, archives, remote forges |

**Use `goredact` when** secrets must be removed from data in flight, with a
latency and memory budget: filtering agent or LLM output before it is
persisted, sanitizing logs before they leave a host, redacting a body before
it is uploaded or compressed, or scrubbing a stream inside a request handler.

**Use Gitleaks or Betterleaks when** you are auditing artifacts at rest and
want maximum coverage rather than a byte-output path: pre-commit hooks, CI
gates, git-history forensics, archive and multi-layer encoding recursion,
baseline diffing, and checking whether a discovered credential is live.
GoRedact does none of those things and is not trying to.

Running both is a reasonable posture: `goredact` in the pipeline, a repository
auditor in CI.

## The shape

```go
engine, err := goredact.New(goredact.Config{
	Profile: goredact.ProfileBalanced,
})
if err != nil {
	log.Fatal(err)
}

stats, err := engine.Redact(ctx, os.Stdout, os.Stdin)
if err != nil {
	log.Fatal(err)
}
log.Printf("redactions=%d bytes=%d", stats.Findings, stats.BytesRead)
```

The zero configuration selects the balanced profile. An engine is immutable
after construction and safe for concurrent use; every call consumes an
`io.Reader` and writes redacted bytes to an `io.Writer` without retaining the
whole input.

By default each secret is replaced with one `[REDACTED]` marker
(`Config.Marker`). `Config.MaskStrategy` can instead select
`MaskLengthPreserving` (`*` per redacted byte, output length equals input
length) or `MaskFormatPreserving` (per-character-class substitution that
also keeps separators, so token shapes and fixed-width records survive) —
see the `MaskStrategy` docs for the disclosure trade-offs.

## Performance profile

GoRedact's cost is a function of bytes, not of how many secrets it finds.
That property, rather than any single multiplier, is the reason it fits the
data path. One-core, same host, same protocol, against Betterleaks 1.7.4:

| Corpus | GoRedact | Betterleaks | Ratio |
| --- | ---: | ---: | ---: |
| No trigger literals, 512 MiB | 648 MiB/s, 10 MiB RSS | 106 MiB/s, 41 MiB RSS | 6.1x |
| Trigger literals, no secrets, 512 MiB | 296 MiB/s, 10 MiB RSS | 80 MiB/s, 41 MiB RSS | 3.7x |
| A secret in every record, 32 MiB | 229 MiB/s, 10 MiB RSS | 1 MiB/s, 4,829 MiB RSS | 242x |

Read the shape of the table, not the last number. GoRedact's memory is flat
at ~10 MiB across a 16x change in input size and every candidate density,
and its throughput degrades gracefully (648 → 296 → 229 MiB/s) because each
candidate is validated inside that rule's bounded window. An auditor's cost
is driven by confirmed findings instead, since each one pays for submatch
extraction, entropy scoring, context extraction, filtering, and permanent
residency in the report.

The two tools are **not** doing identical work: on the third corpus they
confirm nearly the same number of findings but from disjoint rules, and
neither is a superset of the other. Nothing here measures relative recall or
precision. Gitleaks 8.30.1-1 numbers, the private 976-file session corpus,
per-profile runs, host details, scanner flags, the corpus defect behind the
third row, and every reproduction command are in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

### Streaming latency

Output lags input by at most one rule-set window, regardless of how long the
stream runs — the engine emits every byte it can prove is not part of a
growing match. Measured on a trickle producer, first output byte arrives
after 16,568 bytes of input on the balanced profile, and the bound is
tunable by dropping the rules that need the longest lookahead:

| Active rules | Lag bound |
| --- | ---: |
| balanced, all 66 | 16,568 B |
| minus `pem-private-key`, `putty-private-key` | 8,278 B |
| minus also `jwt`, `supabase-service-role-key` | 4,393 B |
| minus also `aws-bedrock-short-lived-api-key` | 774 B |

The default 16 KiB comes entirely from the two private-key block rules; the
median built-in rule window is 86 bytes. Trade block-key detection for
latency with `Config.DisableRules` when the stream is interactive.

The one exception is a private key itself. Those rules decide within their
16 KiB window, but mask a key to its end marker however long it is (an
unterminated key, through its last body byte at the end of input), so the
bytes of a key that runs past the window are held until its end is seen.
Memory stays bounded: a key longer than the buffer has its interior
discarded, never buffered whole.

## Install and use

```sh
go get github.com/baum-ai/goredact@v0.2.0
go install github.com/baum-ai/goredact/cmd/goredact@v0.2.0
goredact stream --profile balanced < session.jsonl > session.redacted.jsonl
goredact stream --zstd --stats - < session.jsonl > session.redacted.jsonl.zst
goredact dir --report-format sarif --report-path findings.sarif ./workspace
```

Run `goredact --help` to discover commands, `goredact <command> --help` for
command-specific flags and examples, or `goredact completion --help` to set up
shell completion. The `stream` command also accepts `--input` and `--output`; it removes incomplete
output after a failed scan. The `dir` command recursively scans regular files
and writes JSON, CSV, JUnit, or SARIF findings without including matched secret
values. By default, progress, statistics, and reports contain metadata and
counts only. See
[`docs/CLI_AND_UPLOAD.md`](docs/CLI_AND_UPLOAD.md) for reports, compression, and
multipart upload integration.

Directory reports omit matched values by default. `dir --show-secrets` includes
them when explicitly requested; its output must be handled as credential
material.

## Detection and guarantees

The built-in rules cover provider tokens (source control, cloud, AI, payment,
messaging, and project management), authentication headers, contextual
assignments, cookies, credentials in URLs, and private-key blocks. Private
keys are masked whole, to their end marker, and are also found in unified
diff patches, where every line opens with a `+`, `-` or space marker. Fast,
balanced, and deep profiles trade detector coverage for cost; deep adds a
broader-keyword, lower-confidence generic assignment heuristic on top of
everything balanced already catches. See [`docs/PROFILES.md`](docs/PROFILES.md)
for the complete rule table.

For every profile, memory is bounded by the configured chunk and rule windows.
Matched bytes are excluded from findings, statistics, and package-generated
errors. The same input, rule-set version, and configuration produce the same
output. Detection is deliberately not a proof that an input contains no
secrets; unsupported encodings and obfuscation are documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Development and release evidence

```sh
go test ./...
go test -race ./...
go vet ./...
make bench-ci
```

- Architecture: [`docs/DESIGN.md`](docs/DESIGN.md)
- Accuracy and differential harness: [`docs/ACCURACY.md`](docs/ACCURACY.md)
- Benchmark suite and report procedure: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- Rule authoring: [`docs/RULE_AUTHORING.md`](docs/RULE_AUTHORING.md)
- Security reporting: [`SECURITY.md`](SECURITY.md)
- Versioning: [`docs/VERSIONING.md`](docs/VERSIONING.md)
- Changes: [`CHANGELOG.md`](CHANGELOG.md)
- Code of Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

The core library remains stdlib-only and has no cgo path. The optional
reference CLI uses the pure-Go `klauspost/compress` module for zstd.

## Licence

MIT. Dependency and source provenance is recorded in [`THIRD_PARTY.md`](THIRD_PARTY.md).
