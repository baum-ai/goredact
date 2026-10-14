# Security policy

goredact is a data-loss-prevention filter that handles secret material by
design (see `docs/THREAT_MODEL.md`). We take vulnerabilities in it
seriously, especially anything that could cause a secret to leak into
output, errors, logs, or diagnostics that this library is supposed to
redact.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not via a public
GitHub issue or pull request:

- Email: **security@usebaum.com**

Include:

- A description of the issue and its potential impact.
- Steps to reproduce, or a minimal test case.
- The version/commit of goredact affected.

We will acknowledge reports as quickly as possible and work with you on a
fix and coordinated disclosure timeline.

## Please do not include secret material in reports

When reporting an issue that involves a specific input that fails to be
redacted, or that leaks a value through an error/log path, **do not include
real, live secret values** in the report (issue text, email, attached logs,
or reproduction code). Use synthetic or clearly-invalidated example values
(e.g. a fake API key with an obviously fake prefix/suffix) that reproduce
the shape of the problem without disclosing real credentials. If a real
secret was ever exposed as part of triggering the bug, treat that secret as
compromised and rotate it independently of this report.

## Scope

This policy covers the `goredact` library itself (this repository). It does
not cover vulnerabilities in software that merely depends on goredact.
