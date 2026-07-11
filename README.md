# mss — macOS Security Scanner

By cenobyte <vincitamorpatriae@gmail.com> 2026

**mss** is a macOS-only command-line security scanner written in ISO C17. It walks a
file or directory tree and reports configurations that weaken code signing,
library loading, or filesystem permissions. Parsing is done entirely in-process
from Mach-O load commands and embedded code-signature blobs — no `codesign`,
`otool`, `file`, or other external utilities are invoked at scan time.

## Build

```sh
make
```

## Usage

```sh
./mss <path> [-v]
```

| Argument | Description |
|----------|-------------|
| `<path>` | Single file or directory to scan (directories are walked recursively) |
| `-v` | Verbose mode (optional, must be the second argument) |

Exit `0` on success; non-zero with a usage message for bad arguments or scan
failures.

## What it checks

### Code-signing entitlements (Mach-O)

Entitlements are read from the `LC_CODE_SIGNATURE` superblob and parsed as an
embedded XML plist. Two keys are treated as dangerous:

| Entitlement | Risk |
|-------------|------|
| `com.apple.security.cs.allow-dyld-environment-variables` | DYLD environment variables can alter library loading |
| `com.apple.security.cs.disable-library-validation` | Library validation is disabled |

**Default mode** reports entitlements on **MH_EXECUTE** binaries when **both**
dangerous keys are present, or when an **rpath** finding (below) is also raised
on that executable. When entitlements are shown, **all** keys on the binary are
listed, not only the dangerous ones. Dylibs are skipped in default mode to
reduce noise.

**Verbose mode** lists entitlements on any Mach-O file that has them.

### LC_RPATH and `@rpath` (Mach-O executables)

For each executable, **mss** parses `LC_RPATH` entries and linked libraries
whose install names start with `@rpath/`. A finding is raised in **default
mode** only when **all** of the following hold:

- At least one `@rpath/…` dependency exists.
- At least one resolved `LC_RPATH` directory is **writable by others**
  (`S_IWOTH`), including missing paths whose parent tree is writable by others.
- The binary has `com.apple.security.cs.disable-library-validation` (without
  it, planted libraries are not loadable even from a writable rpath).

When a risky rpath directory does not exist, **missing** (informational) and
**creatable** (when the current user could create it) are also shown, including
the writable ancestor directory and its permissions.

**Verbose mode** lists rpath data for any Mach-O with `LC_RPATH` and/or
`@rpath` dependencies; the header is red only when the writable-rpath
combination is present (the entitlement is not required for listing).

### setuid / setgid

Regular files (including symlink targets) with the setuid and/or setgid bit set
are reported with symbolic mode, octal permissions, and owner/group.

### World-writable files and directories

Files writable by others (`S_IWOTH`) are reported. Scan-root directories
writable by others are reported with **writable-by-others, sticky bit** and
mode details (sticky status appears in the mode string when set).

### Symlinks

- **Dangling symlinks** whose target does not exist: reported in default mode
  only when the current user could create the target (**creatable**); all
  dangling symlinks are reported in verbose mode.
- **Explicit symlink scan target** (user passes a symlink to a regular file):
  always reported in default mode with **symlink**, resolved target, and **inode**,
  then any findings on the target.
- **Path display**: when the scanned path or any path component is a symlink,
  the user-supplied path is shown first, then yellow **symlink**, then the
  canonical path from `realpath(3)`.
- **Paths with `../`**: when any printed path contains `../` or `/./`, a second
  line with the fully resolved path is added (`realpath` when the path exists,
  otherwise logical `..` / `.` collapse). For **creatable** ancestor
  directories that contain `../`, permissions are shown on the resolved path
  line.

### Mach-O detection

Thin and universal (fat) Mach-O binaries are recognized. Non-Mach-O files may
still be reported for permission findings. Verbose mode adds `KIND:` and
`MACHO:` metadata per object.

## Output

Reported objects use tab-indented sections. On a TTY, flagged section headers
are **red**; **symlink**, **inode**, and **missing** are **yellow**. Piped
output is plain text.

Typical layout:

```
<path>
	symlink                  ← when the path differs from canonical form
	<resolved-path>
	inode
		<number>
	entitlements             ← red when dangerous keys present (or rpath-flagged)
		<key>
	rpath
		<LC_RPATH entry>
		<@rpath dependency>
	missing
		<path>
		<resolved-path>      ← when path contains ../
	creatable
		<path>
		<resolved-path>
		<ancestor> <mode> <octal> <owner:group>
	setuid / setgid / writable-by-others …
```

**Default mode** prints only objects with findings (silent on clean trees).
**Verbose mode** prints every regular file and symlink under the target, plus
the scan-root directory; subdirectories discovered during walks are not listed
separately.

### Example (default, rpath + entitlements)

```
/path/to/Lucid
	inode
		172374585
	entitlements
		com.apple.security.cs.disable-library-validation
		…
	rpath
		/Users/Shared/toolset/…/lib
		@rpath/lucidfs.fs/Contents/Frameworks/liblucidfs.dylib
	missing
		/Users/Shared/toolset/…/lib
		/Users/Shared/toolset/…/lib
	creatable
		/Users/Shared/toolset/…/lib
		/Users/Shared/toolset/…/lib
		/Users/Shared drwxrwxrwt 1777 root:wheel
```

## Verification

```sh
make test          # unit + functional tests
make test-unit     # in-process module tests
make test-functional
make check         # cppcheck (also run by default make)
```

Test fixtures are built with `make fixtures` (requires `cc` and `codesign` for
signing sample binaries only — not used by the scanner itself).

## Development dependencies

- C17 compiler (`cc`)
- `cppcheck` for static analysis (`make check`)
- `codesign` (test fixture build only)

Install cppcheck on macOS:

```sh
brew install cppcheck
```

## Project layout

| File | Role |
|------|------|
| `mss.c` | CLI entry |
| `scan.c` / `scan.h` | Traversal, classification, reporting |
| `macho.c` / `macho.h` | Mach-O parsing, entitlements, rpath/deps |
| `plist.c` / `plist.h` | Minimal XML plist key extraction |

See [REQUIREMENTS.md](REQUIREMENTS.md) for the full behavioural specification.

## Limitations

- macOS only; no `.dmg` or `.pkg` handling (yet) beyond normal directory traversal.
- Report-only — no remediation or quarantine.
- Human-oriented text output (no JSON mode).

