# Third-party code provenance

This file is the provenance register for any vendored or adapted third-party
source code included in this repository.

## Current status

The core library under the module root and `internal/` is original and
stdlib-only. The directory CLI adapts the Gitleaks path-exclusion list recorded
below, and the reference CLI and integrations use the pure-Go dependencies
also recorded below.

The `licence-check` CI job (`.github/workflows/ci.yml`) enforces this by
scanning for copyright headers that do not attribute Baum AI and by
failing the build if this file is missing.

`TestThirdPartyRegisterMatchesGoMod` (`thirdparty_test.go`) enforces the
other half: every module in `go.mod` — direct or indirect — must have an
entry below whose recorded release and pinned licence-file URL match the
required version. Bumping a dependency without updating its entry here is a
test failure, because a register pinned to a version the project no longer
ships cannot be re-audited.

## Recording a new entry

If a future change vendors or adapts code from another project (for example,
a small algorithm lifted from a reference implementation, or a generated
table derived from a third-party corpus), add an entry below **before**
merging, and record the copied code's licence header here, in this file (see
the Gitleaks entry below for the pattern), rather than embedding it in the
local source file itself: the `licence-check` CI job scans every file except
this one and `LICENSE` for non-"Baum AI" `Copyright` lines and fails
the build on a match, so a third-party header left in the local file would
break CI. Each entry must record:

- **Source URL** — the exact upstream repository/file URL the code was taken
  from.
- **Commit** — the upstream commit hash (or release tag) the code was copied
  at, so provenance can be re-verified later.
- **Licence** — the upstream licence identifier (e.g. `MIT`, `Apache-2.0`,
  `BSD-3-Clause`) and confirmation that it is compatible with this project's
  MIT licence.
- **Local path** — where the adapted/vendored code lives in this repository.

### Entry template

```
### <short name of the vendored component>

- Source URL:
- Commit:
- Licence:
- Local path:
- Notes: (what was changed from upstream, if anything)
```

Entries are append-only; do not remove a historical entry even if the code is
later deleted, unless the entire file is being reset to reflect a clean
audit (note the reset in the PR description).

## Adapted code

### Gitleaks default path exclusions

- Source URL: https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/base/config.go
- Commit: `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`
- Licence file: https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/LICENSE
- Licence: MIT; compatible with this project's MIT licence.
- Local path: `cmd/goredact/dir.go`
- Notes: The upstream default path regular expressions are used to prune
  dependency directories and skip generated, media, document, and binary files
  during recursive scans. Traversal and explicit-file behavior are original.

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## External dependencies

### klauspost/compress

- Source URL: https://github.com/klauspost/compress
- Release: v1.20.1
- Licence file: https://github.com/klauspost/compress/blob/v1.20.1/LICENSE
- Licence: mixed by file. The module's primary terms are BSD-3-Clause;
  `gzhttp/*` is Apache-2.0; `s2/cmd/internal/readahead/*` and
  `s2/cmd/internal/filepathx/*` are MIT; and `snappy/*` plus
  `internal/snapref/*` carry BSD-3-Clause terms. This project directly imports
  `github.com/klauspost/compress/zstd`; its linked transitive packages from
  the module (`fse`, `huff0`, `internal/cpuinfo`, `internal/le`,
  `internal/snapref`, and `zstd/internal/xxhash`) are also covered by
  BSD-3-Clause terms. Those applicable terms are compatible with this
  project's MIT licence.
- Local use: `cmd/goredact` and `examples/multipartupload`
- Notes: pure-Go streaming Zstandard encoder; consumed as a Go module and not
  vendored or adapted. Binary redistributors must preserve the applicable
  copyright notice, conditions, and disclaimer as required by BSD-3-Clause.

### spf13/cobra

- Source URL: https://github.com/spf13/cobra
- Release: v1.10.2
- Licence file: https://github.com/spf13/cobra/blob/v1.10.2/LICENSE.txt
- Licence: Apache-2.0; compatible with this project's MIT licence.
- Local use: `cmd/goredact`
- Notes: CLI command hierarchy, help, flag handling, argument validation,
  version output, command suggestions, and shell-completion generation;
  consumed as a Go module and not vendored or adapted. Distributions must
  include a copy of the Apache-2.0 licence and preserve applicable attribution
  notices.

### spf13/pflag

- Source URL: https://github.com/spf13/pflag
- Release: v1.0.10
- Licence file: https://github.com/spf13/pflag/blob/v1.0.10/LICENSE
- Licence: BSD-3-Clause; compatible with this project's MIT licence.
- Local use: transitive dependency of `github.com/spf13/cobra` in
  `cmd/goredact`
- Notes: POSIX/GNU-style flag parsing; consumed as a Go module and not
  vendored or adapted. Binary redistributors must reproduce the copyright
  notice, conditions, and disclaimer in accompanying documentation or other
  materials.

### inconshreveable/mousetrap

- Source URL: https://github.com/inconshreveable/mousetrap
- Release: v1.1.0
- Licence file: https://github.com/inconshreveable/mousetrap/blob/v1.1.0/LICENSE
- Licence: Apache-2.0; compatible with this project's MIT licence.
- Local use: transitive dependency of `github.com/spf13/cobra` in
  `cmd/goredact` on Windows
- Notes: detects execution from Windows Explorer; consumed as a Go module and
  not vendored or adapted. Distributions must include a copy of the
  Apache-2.0 licence and preserve applicable attribution notices.
