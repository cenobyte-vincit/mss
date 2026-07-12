# mss — macOS Security Scanner

By cenobyte <vincitamorpatriae@gmail.com> 2026

**mss** is a macOS-only command-line security scanner written in ISO C17. It is
meant to surface **directly exploitable** vulnerabilities and traits in Mach-O
executables and Application Bundle directories (for example `.app` trees). It
walks a Mach-O executable or Application Bundle directory path and reports
misconfigurations in code signing,
library loading, and filesystem permissions that an attacker can abuse without
first finding a separate memory-corruption bug. Parsing is done entirely
in-process from Mach-O load commands and embedded code-signature blobs — no
`codesign`, `otool`, `file`, or other external utilities are invoked at scan
time.

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
| `<path>` | Single Mach-O executable or Application Bundle directory to scan (Application Bundle directories are walked recursively) |
| `-v` | Verbose mode (optional, must be the second argument) |

Exit `0` on success; non-zero with a usage message for bad arguments or scan
failures.

### Default vs verbose

**Default mode** (no `-v`) is tuned for **direct assessment**: it prints only
findings that are **immediately exploitable** under current permissions and
entitlements — writable rpath trees with library validation disabled,
world-writable linked libraries, relocatable binaries with `disable-library-validation`,
setuid binaries, and similar. Clean paths produce no output, so you can point
**mss** at an executable or `.app` and read what matters without wading through
the whole bundle.

**Verbose mode** (`-v`) is better suited to **broader security audits**: it
lists every regular file and symlink, full entitlement and library metadata,
and informational rpath data even when not flagged. Pipe or paste that output
into **Grok**, **Claude**, or another assistant for deeper review — hunting
weak configurations, correlating entitlements with linked libraries, or
building audit notes across a large tree.

## What it checks

### Code-signing entitlements (Mach-O)

Entitlements are read from the `LC_CODE_SIGNATURE` superblob and parsed as an
embedded XML plist. Two keys are especially relevant to **library injection and
process compromise**:

| Entitlement | Exploitation |
|-------------|--------------|
| `com.apple.security.cs.allow-dyld-environment-variables` | Permits DYLD environment variables (for example `DYLD_INSERT_LIBRARIES`) that can force loading of attacker-controlled dynamic libraries |
| `com.apple.security.cs.disable-library-validation` | Disables library validation, so unsigned or tampered libraries may load; together with other entitlements this can be abused to compromise the target process or system |

**Default mode** reports entitlements on **MH_EXECUTE** binaries when **both**
of these keys are present, or when an **rpath**, **relative-path**, or
**writable-libraries** finding (below) is also raised on that executable. When
entitlements are shown, **all** keys on the binary are listed, not only the two
above — other entitlements (JIT, microphone access, and so on) indicate further
abuse surface once code execution is gained. Dylibs are skipped in default mode
to reduce noise.

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

When an exploitable rpath directory does not exist, **missing** (informational)
and **creatable** (when the current user could create it) are also shown,
including the writable ancestor directory and its permissions.

**Verbose mode** lists rpath data for any Mach-O with `LC_RPATH` and/or
`@rpath` dependencies; the header is red only when the writable-rpath
combination is present (the entitlement is not required for listing).

`@executable_path` and `@loader_path` prefixes are resolved relative to the
scanned binary when checking `LC_RPATH` directories.

### `@executable_path` and `@loader_path` (Mach-O executables)

For each executable, **mss** parses linked libraries whose install names start
with `@executable_path` or `@loader_path`. A finding is raised in **default
mode** only when **all** of the following hold:

- At least one such dependency exists.
- The binary has `com.apple.security.cs.disable-library-validation` (without
  it, library validation blocks loading attacker-supplied libraries even when
  the binary is copied to an attacker-controlled directory tree).

Without library validation, an attacker who can place the executable in a
chosen location can reconstruct the relative directory layout those install
names resolve to and supply malicious dylibs.

When a **relative-path** finding is raised, **all** entitlement keys on that
executable are also listed. **Verbose mode** lists `relative-path` data for any
Mach-O with `@executable_path` and/or `@loader_path` dependencies; the header
is red only when `disable-library-validation` is also present.

### Writable linked libraries (Mach-O executables)

For each executable, **mss** resolves every linked library install name to a
filesystem path (absolute paths as-is; `@executable_path`, `@loader_path`, and
`@rpath` relative to the scanned binary). A finding is raised when at least one
resolved library exists and is either **writable by others** (`S_IWOTH`) or
**writable by the current user** through group permission bits (`S_IWGRP` and
`access(2)` `W_OK`). Owner-only write permission alone is not flagged.

Each match is shown under a red **writable-libraries** header: the resolved
path, then a mode detail line (`<symbolic-mode> <octal> <owner:group>`). When
no passwd or group entry exists, the numeric UID or GID is shown instead of a
name. When a **writable-libraries** finding is raised in default mode, **all**
entitlement keys on that executable are also listed when present. **Verbose
mode** uses the same rules.

### setuid / setgid

Regular files (including symlink targets) with the setuid and/or setgid bit set
are reported with symbolic mode, octal permissions, and owner/group. These bits
mean the programme **can** run with elevated privileges; **mss** does not look
for conventional implementation flaws. It is up to you to audit the binary for
memory-corruption bugs (buffer overflows, format-string issues), unsafe
`system()` or `popen()` use, `PATH` hijacking, predictable temporary files,
and similar classic privilege-escalation paths.

### World-writable files and Application Bundle directories

Files writable by others (`S_IWOTH`) are reported. Scan-root Application Bundle
directories writable by others are reported with **writable-by-others, sticky bit** and
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

Thin and universal (fat) Mach-O binaries are recognised. Non-Mach-O files may
still be reported for permission findings. **Verbose mode** adds a **libraries**
section (all linked dylib install names), then `KIND:` and `MACHO:` metadata
per object.

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
	entitlements             ← red when exploitable keys present (or load-flagged)
		<key>
	rpath
		<LC_RPATH entry>
		<@rpath dependency>
	relative-path
		<@executable_path or @loader_path dependency>
	writable-libraries
		<resolved library path>
		<mode> <octal> <owner:group>
	libraries                ← verbose only; install names, not red
		<install name>
	missing
		<path>
		<resolved-path>      ← when path contains ../
	creatable
		<path>
		<resolved-path>
		<ancestor> <mode> <octal> <owner:group>
	setuid / setgid / writable-by-others …
```

**Default mode** prints only **immediately exploitable** findings (silent on
clean trees) — see [Default vs verbose](#default-vs-verbose) above.
**Verbose mode** prints every regular file and symlink under the target, plus
the scan-root Application Bundle directory; subdirectories discovered during
walks of Application Bundle directories are not listed separately. Use `-v` when
you want a full inventory to analyse offline or with an LLM assistant.

### Example (default, relative-path + writable libraries)

```
/Applications/Example.app/Contents/MacOS/Example
	inode
		12345678
	entitlements
		com.apple.security.cs.disable-library-validation
		…
	relative-path
		@executable_path/../Frameworks/libexample.dylib
	writable-libraries
		/Applications/Example.app/Contents/Frameworks/libexample.dylib
		-rwxrwxrwx 0777 echobravo:admin
```

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

- macOS only; no `.dmg` or `.pkg` handling (yet) beyond normal Application Bundle directory traversal.
- Report-only — no remediation or quarantine.
- Human-oriented text output (no JSON mode).