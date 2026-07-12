# AGENTS.md — working in mss

Guidance for coding agents. The full behavioural specification lives in
[REQUIREMENTS.md](REQUIREMENTS.md); treat that document as authoritative for
CLI contract, scan rules, output format, and scope.

## Project summary

**mss** is a macOS-only security scanner written in ISO C17. It walks a file or
directory tree and reports dangerous Mach-O entitlements, risky `@rpath` /
`LC_RPATH` combinations, setuid/setgid bits, and related filesystem findings.
Parsing is done entirely in-process — no `codesign`, `otool`, `file`, or other
external utilities at scan time.

## Hard constraints

- **macOS only** — do not add Linux branches or cross-platform abstractions.
- **C17, pure C** — no Objective-C, Security.framework, or external plist libs.
- **No shell-outs in the scanner** — `codesign` and `cc` are allowed only in
  `tests/fixtures/build_fixtures.sh` for building signed test inputs.
- **Report only** — no remediation, quarantine, or auto-fix.
- **Deferred for v1** — `.dmg`, `.pkg`, JSON output, broad vulnerability
  catalogues. See REQUIREMENTS.md §6.

When behaviour is ambiguous, read REQUIREMENTS.md before guessing.

## Source layout

| Path | Role |
|------|------|
| `mss.c` | CLI entry (`usage`, argument parsing) |
| `scan.c` / `scan.h` | Path classification, recursive walk, reporting |
| `macho.c` / `macho.h` | Mach-O parsing, entitlements, rpath/deps |
| `plist.c` / `plist.h` | Minimal XML plist `<key>` extraction |
| `tests/unit/*.c` | In-process module tests |
| `tests/functional/run_tests.sh` | CLI end-to-end tests |
| `tests/fixtures/` | Fixture **sources** only (`hello.c`, `ent_*.plist`, build script) |

## Build and verification

Run these before finishing work:

```sh
make              # build mss + cppcheck
make test         # unit + functional tests
make check        # cppcheck only
```

Other targets:

| Command | Purpose |
|---------|---------|
| `make test-unit` | Module tests in `tests/build/unit/` |
| `make test-functional` | CLI tests via `run_tests.sh` |
| `make fixtures` | Build signed/unsigned Mach-O fixtures |
| `make clean` | Remove `mss` and `tests/build/` |

`make` requires `cppcheck` (`brew install cppcheck`). Fixture builds require
`cc` and `codesign`.

## Test artifacts

All generated test binaries live under `tests/build/` (gitignored):

- `tests/build/unit/` — unit test executables (built by Makefile)
- `tests/build/fixtures/` — Mach-O fixtures, symlinks, dirs (built by
  `make fixtures`)

Do **not** commit binaries under `tests/`. Fixture sources stay in
`tests/fixtures/`; outputs go to `tests/build/fixtures/`. Tests reference
`tests/build/fixtures` as the fixture root.

Tests must exercise real shipped code paths — no mocked parsers and no
hard-coded pass strings.

## Coding style

- ISO C17 with `-Wall -Wextra -Werror -pedantic`.
- BSD/macOS conventions: `__progname`, `<err.h>`, `errx`/`warnx` where appropriate.
- Match existing indentation and naming in each file you touch.
- Keep changes focused; avoid drive-by refactors.

## Common pitfalls

- **Default vs verbose mode** — reporting rules differ significantly; check
  REQUIREMENTS.md §4.5, §4.7, §4.8, and §5.3–5.4 before changing output logic.
- **Executables vs dylibs** — default mode filters entitlements and rpath
  findings differently for `MH_EXECUTE` vs other Mach-O kinds.
- **Path display** — input path, symlink resolution, `realpath`, and `../`
  collapsing all have explicit rules (REQUIREMENTS.md §4.1, §5.1).
- **TTY colouring** — red/yellow headers only on interactive TTY; piped output
  must be plain text so functional tests stay stable.
- **Fixture paths** — after moving binaries to `tests/build/`, source edits to
  unit or functional tests must keep `tests/build/fixtures` as the fixture root.
- **Directory symlinks** — do not recurse into symlink directories during
  enumeration; only the scan root is resolved via `realpath(3)`.

## When changing behaviour

1. Update the implementation.
2. Update or add tests (unit for parsers/classifiers; functional for CLI output).
3. If the user-visible contract changes, update REQUIREMENTS.md to match.
4. Run `make test` and `make check`.