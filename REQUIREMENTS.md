# mss — macOS Security Scanner

Requirements document for the **mss** CLI (`macOS Security Scanner`). This
captures the agreed scope, behaviour, and constraints from design and
implementation discussions.

## 1. Purpose

**mss** is a macOS-only command-line security scanner. It walks a file or
directory tree, classifies objects, detects Mach-O binaries, and reports
security-relevant properties — especially code-signing entitlements and
setuid/setgid permission bits.

The tool is intentionally narrow in its first release: it flags known
dangerous configurations rather than providing a broad vulnerability catalogue.

## 2. Platform and implementation constraints

| Requirement | Detail |
|-------------|--------|
| Target OS | macOS only (no cross-platform support) |
| Language | ISO C17 |
| External utilities at scan time | **None** — no `codesign`, `file`, `otool`, or shell-outs |
| Objective-C / Security.framework | Not used; entitlement parsing is done in pure C by reading the Mach-O `LC_CODE_SIGNATURE` superblob |
| Test fixture signing | `codesign` and `cc` may be used only in `tests/fixtures/build_fixtures.sh` to create signed sample binaries; this is not part of the shipped scanner |

## 3. CLI contract

### 3.1 Invocation

```sh
mss <path> [-v]
```

| Argument | Position | Required | Description |
|----------|----------|----------|-------------|
| `<path>` | `argv[1]` | Yes | File or directory to scan |
| `-v` | `argv[2]` | No | Verbose mode |

### 3.2 Rules

- Exactly one positional path argument.
- Optional verbose flag must be `-v` as the second argument only (no other flags).
- Missing path, empty path, wrong argument count, or unknown second argument → non-zero exit and usage message on stderr.
- Successful scan → exit `0`.

### 3.3 Usage text

```
usage: mss <path> [-v]
```

## 4. Scan behaviour

### 4.1 Path handling

- Accept a single **file** or **directory**.
- **Directories** are walked recursively; every file and subdirectory under the target is considered. Enumeration does **not** recurse into symlinks to directories (e.g. a Sparkle cache entry pointing at `/Applications`); symlink targets are still analysed when the symlink itself is enumerated.
- Enumeration order is deterministic (child paths sorted alphabetically before recursion).
- Paths are **normalised** when stored and joined (duplicate slashes collapsed;
  trailing-slash roots such as `/tmp/` must not produce `/tmp//…`).
- When the user-supplied path differs from its canonical form, both are shown:
  the input path first, then (when the path itself or any path component is a
  symlink) a yellow **symlink** header, then the path resolved with
  `realpath(3)` (e.g. `/tmp/foobar`, **symlink**, `/private/tmp/foobar`).

### 4.2 Object classification

Each scanned object is classified as one of:

| Kind | Detection |
|------|-----------|
| **directory** | `S_ISDIR` via `lstat` |
| **file** | `S_ISREG` via `lstat` (or `stat` after following a symlink) |
| **symlink** | `S_ISLNK` via `lstat` |

Symlink targets are followed with `stat` when analysing file content (Mach-O, setuid/setgid on the target).

### 4.3 Mach-O detection

For each regular file (including symlink targets that are regular files):

- Detect **thin** Mach-O (32- and 64-bit magic values).
- Detect **fat / universal** Mach-O.
- Non-Mach-O files are not analysed for entitlements but may still be reported for setuid/setgid or verbose metadata.

### 4.4 Entitlement extraction

For Mach-O binaries that contain an embedded code signature:

1. Locate `LC_CODE_SIGNATURE` in the Mach-O load commands.
2. Parse the embedded signature **superblob** (`0xfade0cc0`).
3. Read the entitlements slot (`CSSLOT_ENTITLEMENTS`, type `5`).
4. Accept entitlement blob magic `0xfade7171` (and generic blob magic where applicable).
5. Parse the embedded XML plist and enumerate all `<key>` entries.

No external plist libraries are required; a minimal in-process XML key extractor is sufficient.

### 4.5 Dangerous entitlements (flagged)

These two entitlements are treated as **security findings**:

| Entitlement key | Risk |
|-----------------|------|
| `com.apple.security.cs.allow-dyld-environment-variables` | Allows DYLD environment variables that can alter library loading |
| `com.apple.security.cs.disable-library-validation` | Disables library validation |

In **default** mode, entitlements are reported only on **MH_EXECUTE** Mach-O
binaries (not dylibs or other loadable images) when **both** dangerous
entitlements are present, or when an **rpath** (§4.7) or **relative-path**
(§4.7.1), or **writable-libraries** (§4.7.2) finding is also raised
on that binary; when entitlements are shown, **all** entitlement keys on that
binary are listed (not only the dangerous ones). Dylibs may duplicate the
app executable's entitlements but are not independently launched; skipping
them reduces noise without hiding the process-level risk on the main binary.
In **verbose** mode, any entitlements on any Mach-O file are listed.

### 4.6 setuid / setgid detection

For each regular file (including followed symlink targets):

- If the **setuid** and/or **setgid** bit is set, report it as a finding.
- Show file details on double-indented lines below a section header.

Details include:

- Symbolic mode (e.g. `-rwsr-xr-x`)
- Octal permission bits (e.g. `4755`)
- Owner and group names (`owner:group`)

### 4.7 LC_RPATH and `@rpath` dependency checks

For Mach-O files, parse `LC_RPATH` load commands and linked libraries whose
install names start with `@rpath/`.

A finding is raised when **all** of the following hold:

- The binary links against at least one `@rpath/…` library.
- At least one `LC_RPATH` entry resolves to a directory that is
  **writable by others** (`S_IWOTH`), including when intermediate path
  components do not yet exist but a parent directory is writable by others
  (an attacker could create the tree).
- The executable has the
  `com.apple.security.cs.disable-library-validation` entitlement (without it,
  library validation blocks loading attacker-supplied libraries even from a
  writable rpath).
- Absolute paths and `@loader_path` prefixes are resolved relative to the
  scanned binary. `@executable_path` is resolved relative to the directory
  containing the scanned **MH_EXECUTE** binary; when the scanned file is a
  non-executable Mach-O inside a `*.app/Contents/…` tree, `@executable_path`
  is resolved relative to that bundle's main executable in
  `Contents/MacOS/` (from `Info.plist` `CFBundleExecutable`, or the sole
  `MH_EXECUTE` in `MacOS/` when unambiguous). If no bundle main executable is
  found, `@executable_path` falls back to the scanned file's directory (same
  as `@loader_path` anchor for loadable images).

When a risky `LC_RPATH` directory does not exist, also show yellow **missing**
and red **creatable** when the current user could create that path. Under
**creatable**, show the nearest existing ancestor directory that grants write
access to the current user. When that ancestor path contains `../`, print the
unresolved path on one line and the mode detail
(`<resolved-path> <symbolic-mode> <octal> <owner:group>`) on the next; otherwise
attach the mode detail to the ancestor path on a single line.

**Default** mode reports this only on **MH_EXECUTE** binaries that also have
`disable-library-validation`. When an **rpath** finding is raised, **all**
entitlement keys on that executable are also listed (§4.5). **Verbose** mode
lists `rpath` data for any Mach-O with `LC_RPATH` and/or `@rpath`
dependencies; the header is red only when the risky `@rpath` + writable
`LC_RPATH` combination above is present (the entitlement is not required for
verbose listing).

### 4.7.1 `@executable_path` and `@loader_path` dependency checks

For Mach-O files, parse linked libraries whose install names start with
`@executable_path` or `@loader_path`.

A finding is raised when **all** of the following hold:

- The binary links against at least one such library.
- The executable has the
  `com.apple.security.cs.disable-library-validation` entitlement (without it,
  library validation blocks loading attacker-supplied libraries even when the
  binary is copied to an attacker-controlled directory tree).

Without library validation, an attacker who can place the executable in a
chosen location can reconstruct the relative directory layout those install
names resolve to and supply malicious dylibs.

**Default** mode reports this only on **MH_EXECUTE** binaries. When a
**relative-path** finding is raised, **all** entitlement keys on that
executable are also listed (§4.5). **Verbose** mode lists `relative-path`
data for any Mach-O with `@executable_path` and/or `@loader_path`
dependencies; the header is red only when
`disable-library-validation` is also present.

### 4.7.2 Writable linked libraries

For **MH_EXECUTE** Mach-O binaries (any Mach-O in verbose mode), resolve
every linked library install name to a filesystem path:

- Absolute paths are used as-is.
- `@loader_path` and `@rpath` prefixes are resolved relative to the scanned
  binary; `@executable_path` uses the bundle main-executable directory when
  the scanned file lies inside `*.app/Contents/…` (see §4.7). For `@rpath`,
  each `LC_RPATH` entry is tried until an existing regular file is found.

A finding is raised when at least one resolved library exists and is either
**writable by others** (`S_IWOTH`) or **writable by the current user**
(`access(2)` `W_OK`) through the group permission bits (`S_IWGRP`). Owner-only
write permission alone is not flagged.

Each flagged library is shown under a red **`writable-libraries`** header: the
resolved path on one double-indented line, then a mode detail line
(`<symbolic-mode> <octal> <owner:group>`). When a **writable-libraries**
finding is raised in default mode, **all** entitlement keys on that executable
are also listed when present (§4.5). **Verbose** mode uses the same rules;
the header is red whenever at least one library matches.

### 4.8 Dangling symlink targets

When a scanned symlink's target path does not exist:

- Show the symlink path, yellow **symlink**, and resolved target path.
- Show yellow **missing** with the target path (informational).
- If the **current user** can create the target (an existing parent directory
  grants write access to `geteuid()`), show red **creatable** — an attacker
  (or the user) could plant a file at the dangling location — with the
  writable ancestor path and mode detail (see §4.7 for `../` handling).

**Default** mode reports dangling symlinks only when the target is user-
creatable. **Verbose** mode reports all dangling symlinks.

When the user passes a **symlink to a regular file** as the scan target, always
report the symlink path, resolved target, and inode in default mode, then any
other findings on the target. Symlinks discovered during directory walks are analysed for findings on their
targets (regular files, dangling links) but directory symlinks are not
traversed recursively. Such symlinks are reported only when they have findings
or a dangling target. Directory symlink scan roots keep existing directory
permission reporting.

### 4.9 Scan-root symlink and directory permission checks

When the scan target is a directory or a symlink to a directory, report the
user-supplied path on the first line only when the root itself has a finding
(symlink, or writable-by-others permissions in default mode; always in verbose).

If the scan root itself is a **symlink**, the user-supplied path is shown
first, then a yellow **symlink** header, then the resolved target:

```
	<user-supplied-path>
	symlink
	<resolved-path>
```

**Default mode** — paths writable by others (`S_IWOTH`) show a single red
**writable-by-others, sticky bit** finding on scan-root directories with
setuid-style detail (sticky status appears in the mode string, e.g. trailing
`t`). Files writable by others show a red **writable-by-others** finding only.

**Verbose mode** — when there is no finding (sticky set on a directory
writable by others, or directory not writable by others), show plain
**directory permissions** with the same detail line. When writable by others
without sticky, show red **writable-by-others, sticky bit** with the mode
detail line.

Directory traversal follows symlinks (e.g. `/tmp` → `/private/tmp`).

## 5. Output format

### 5.1 General layout

Reported files use a consistent structure:

```
<normalised-path>
	inode                    ← one tab indent, yellow on TTY; shown when findings exist
		<number>             ← two tab indents
	<section-header>          ← one tab indent
		<detail or key>       ← two tab indents
```

Section headers and detail lines use tab indentation, not spaces.

When a printed path contains `../` or `/./`, add another line immediately
below it (same indentation) with the fully resolved path: use `realpath(3)`
when the path exists, otherwise collapse `.` and `..` components logically.
Skip the extra line when the resolved form is identical to the printed path.

### 5.2 Colour (TTY)

**Standard:** whenever something is **flagged**, its section header is printed in **red** on an interactive TTY (ANSI escape). Plain text is used when stdout is not a TTY (e.g. piped output, tests).

| Section header | Red when |
|----------------|----------|
| `setuid` | Always (setuid bit set) |
| `setgid` | Always (setgid bit set) |
| `setuid, setgid` | Always (both bits set) |
| `entitlements` | Both dangerous entitlements present (default), at least one (verbose), or any keys when `rpath`, `relative-path`, or `writable-libraries` is flagged (default) |
| `entitlements` | Not red when only non-dangerous entitlements are listed |
| `rpath` | `@rpath` dependency, writable-by-others `LC_RPATH`, and `disable-library-validation` (default); verbose omits entitlement requirement |
| `relative-path` | `@executable_path` or `@loader_path` dependency and `disable-library-validation` |
| `writable-libraries` | Resolved linked library writable by others or by the current user via group bits |
| `creatable` | Dangling symlink target creatable by the current user |
| `missing` | Not red — informational dangling symlink target |

Detail lines (double-indented) are not coloured. Section headers use red when
flagged; `symlink`, `inode`, and `missing` use yellow on a TTY.

### 5.3 Default mode (no `-v`)

Only print objects with **findings**:

| Finding / object | Printed |
|----------------|---------|
| Scan root symlink-to-directory | User path; `symlink` + resolved path |
| Scan root directory writable by others | Path; red `writable-by-others, sticky bit` + mode line |
| Scan root safe directory (not writable by others, not a symlink) | No |
| setuid and/or setgid on a file | Yes |
| Both dangerous entitlements on an **executable** Mach-O | Yes — list **all** entitlement keys |
| Dangerous entitlements on a **dylib** only | No |
| Executable with only one dangerous entitlement (no setuid/setgid) | No |
| `@rpath` deps with writable-by-others `LC_RPATH` and `disable-library-validation` on an executable | Yes — list **all** entitlement keys when present |
| Risky `@rpath`/`LC_RPATH` without `disable-library-validation` | No (verbose: list rpath data) |
| `LC_RPATH` without `@rpath` deps, or safe directories only | No |
| `@executable_path` or `@loader_path` deps with `disable-library-validation` on an executable | Yes — list matching install names; list **all** entitlement keys when present |
| `@executable_path` or `@loader_path` deps without `disable-library-validation` | No (verbose: list relative-path data) |
| Writable linked library on an executable (others or group-writable to user) | Yes — resolved path and mode detail; list **all** entitlement keys when present |
| Writable linked library (verbose, non-executable Mach-O) | Yes |
| Dangling symlink with user-creatable target | Yes |
| Dangling symlink target not creatable by user | No (verbose: yes, without `creatable`) |
| Clean Mach-O (no dangerous entitlements, no setuid/setgid) | No |
| Plain non-Mach-O file | No |
| Subdirectories (non-root) | No |
| Symlinks (non-root) | No |

Each reported file starts with the user-supplied path and, when it differs
because of a symlink (the object itself or a parent path component), a yellow
**symlink** header and the resolved canonical path, then
`inode` (from `lstat` on the path) when any finding is present, followed by
flagged sections. Matching inodes indicate hard links to the same file.

### 5.4 Verbose mode (`-v`)

| Object | Printed |
|--------|---------|
| Scan root directory | Once, with `KIND: directory` |
| Subdirectories | No (avoid noise on large trees such as `/tmp`) |
| Regular files | Yes — path, then setuid/setgid sections if applicable, then all entitlements if any |
| Symlinks | Yes — path and `KIND: symlink` |
| Mach-O metadata | `KIND: file` and `MACHO: yes` or `MACHO: no` (one tab indent) after sections |
| Mach-O libraries | `libraries` section listing all linked dylib install names (from `LC_LOAD_DYLIB` and related load commands), one per double-indented line |

Entitlements are **always** listed for Mach-O files that have them, regardless of whether dangerous flags are present. The `entitlements` header is red only when a dangerous flag is set. The `libraries` header is never red.

### 5.5 Example (default, flagged Mach-O)

```
/usr/local/Cellar/openjdk/26.0.1/libexec/openjdk.jdk/Contents/Home/bin/java
	entitlements
		com.apple.security.cs.allow-jit
		com.apple.security.cs.allow-unsigned-executable-memory
		com.apple.security.cs.disable-library-validation
		com.apple.security.cs.allow-dyld-environment-variables
		com.apple.security.cs.debugger
		com.apple.security.device.audio-input
		com.apple.security.get-task-allow
```

(`entitlements` header shown in red on a TTY.)

### 5.6 Example (default, setuid)

```
/path/to/setuid_bin
	inode
		12345678
	setuid
		-rwsr-xr-x 4755 root:wheel
```

(`setuid` header shown in red on a TTY.)

## 6. Deferred / out of scope (v1)

The following were discussed but are **not** part of the current deliverable:

| Item | Notes |
|------|-------|
| `.dmg` scanning | Explicitly deferred |
| `.pkg` scanning | Explicitly deferred |
| `.app` bundle-specific checks | Directory traversal is sufficient for now |
| Broad vulnerability catalogues | Beyond Mach-O + named entitlements + setuid/setgid |
| Remediation / quarantine / auto-fix | Report only |
| Cross-platform support | macOS only |

## 7. Project layout

| Component | Role |
|-----------|------|
| `mss.c` | CLI entry (`usage`, argument parsing) |
| `scan.c` / `scan.h` | Path classification, recursive walk, reporting |
| `macho.c` / `macho.h` | Mach-O identification, code-signature entitlement extraction |
| `plist.c` / `plist.h` | Minimal XML plist `<key>` enumeration |

## 8. Build and verification

| Command | Purpose |
|---------|---------|
| `make` | Build `mss` binary |
| `make test` | Unit + functional tests |
| `make test-unit` | In-process module tests |
| `make test-functional` | CLI end-to-end tests |
| `make check` | `cppcheck` static analysis |
| `make fixtures` | Build signed/unsigned test binaries |

Tests must exercise real shipped code paths (no mocked parsers, no hard-coded pass strings). Functional tests cover good/bad CLI arguments and representative file/directory inputs.

## 9. Future considerations

Items that may be discussed before implementation:

- **Security.framework / Objective-C** — alternative entitlement access; not used in v1.
- Additional dangerous entitlement keys.
- `.app`, `.dmg`, and `.pkg` scanners.
- Filtering / severity levels for large directory scans.
- JSON or machine-readable output mode.