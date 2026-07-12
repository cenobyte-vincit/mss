#!/usr/bin/env bash
#
# run_tests.sh - Functional tests for the mss CLI.
#
set -euo pipefail
IFS=$'\n\t'

readonly __progname="run_tests"
readonly ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly FIXTURES="${ROOT}/tests/build/fixtures"

errx() {
	printf '%s: %s\n' "$__progname" "$*" >&2
	exit 1
}

assert_contains() {
	local haystack="$1"
	local needle="$2"
	local label="$3"

	if ! printf '%s' "$haystack" | grep -Fq -- "$needle"; then
		printf 'FAIL %s: missing %q\n' "$label" "$needle" >&2
		printf '%s\n' "$haystack" >&2
		exit 1
	fi
}

assert_not_contains() {
	local haystack="$1"
	local needle="$2"
	local label="$3"

	if printf '%s' "$haystack" | grep -Fq -- "$needle"; then
		printf 'FAIL %s: unexpected %q\n' "$label" "$needle" >&2
		exit 1
	fi
}

run_case() {
	local label="$1"
	local expect_rc="$2"
	shift 2
	local rc
	local out
	local err

	set +e
	out="$("$@" 2>&1)"
	rc=$?
	set -e
	if [[ "$rc" -ne "$expect_rc" ]]; then
		printf 'FAIL %s: expected exit %d got %d\n' "$label" "$expect_rc" "$rc" >&2
		printf '%s\n' "$out" >&2
		exit 1
	fi
	printf '%s' "$out"
}

main() {
	local prog

	if [[ $# -ne 1 ]]; then
		errx "usage: run_tests.sh <mss-binary>"
	fi
	prog="$1"
	cd "$ROOT"

	# t001 bad args
	run_case t001_bad_args 1 "$prog" >/dev/null
	run_case t001_bad_args 1 "$prog" extra args >/dev/null
	run_case t001_bad_args 1 "$prog" "${FIXTURES}/plain.txt" --verbose >/dev/null

	# t002 good file non-macho (default: no findings, silent)
	out="$(run_case t002_non_macho 0 "$prog" "${FIXTURES}/plain.txt")"
	assert_not_contains "$out" "plain.txt" t002

	# t003 good macho default (both dangerous entitlements)
	out="$(run_case t003_both_ent 0 "$prog" "${FIXTURES}/with_both_ent")"
	assert_contains "$out" "${FIXTURES}/with_both_ent" t003
	assert_contains "$out" $'\tentitlements' t003
	assert_contains "$out" \
		$'\t\tcom.apple.security.cs.allow-dyld-environment-variables' t003
	assert_contains "$out" \
		$'\t\tcom.apple.security.cs.disable-library-validation' t003
	assert_contains "$out" $'\t\tcom.apple.security.get-task-allow' t003

	# t003b dylib with both dangerous entitlements (default: silent)
	out="$(run_case t003b_dylib_both 0 "$prog" "${FIXTURES}/with_both_ent.dylib")"
	assert_not_contains "$out" "${FIXTURES}/with_both_ent.dylib" t003b

	# t003c single dangerous entitlement (default: silent)
	out="$(run_case t003c_dyld_only 0 "$prog" "${FIXTURES}/with_dyld_ent")"
	assert_not_contains "$out" "${FIXTURES}/with_dyld_ent" t003c
	out="$(run_case t003d_lv_only 0 "$prog" "${FIXTURES}/with_lv_ent")"
	assert_not_contains "$out" "${FIXTURES}/with_lv_ent" t003d

	# t004 directory tree (default: silent root and children)
	out="$(run_case t004_directory 0 "$prog" "${FIXTURES}/tree")"
	assert_not_contains "$out" "${FIXTURES}/tree" t004
	assert_not_contains "$out" "readme.txt" t004

	# t004b directory tree (verbose)
	out="$(run_case t004b_directory_verbose 0 "$prog" "${FIXTURES}/tree" -v)"
	assert_contains "$out" "${FIXTURES}/tree" t004b
	assert_contains "$out" $'\tdirectory permissions' t004b
	assert_contains "$out" "${FIXTURES}/tree/binary" t004b
	assert_contains "$out" $'\tMACHO: yes' t004b
	assert_contains "$out" "${FIXTURES}/tree/readme.txt" t004b
	assert_contains "$out" $'\tMACHO: no' t004b

	# t005 system universal binary (default: silent)
	out="$(run_case t005_system_macho 0 "$prog" /bin/ls)"
	assert_not_contains "$out" "/bin/ls" t005

	# t006 verbose dyld entitlement
	out="$(run_case t006_verbose_dyld 0 "$prog" "${FIXTURES}/with_dyld_ent" -v)"
	assert_contains "$out" "${FIXTURES}/with_dyld_ent" t006
	assert_contains "$out" $'\tentitlements' t006
	assert_contains "$out" \
		$'\t\tcom.apple.security.cs.allow-dyld-environment-variables' t006
	assert_contains "$out" $'\t\tcom.apple.security.get-task-allow' t006
	assert_contains "$out" $'\tKIND: file' t006
	assert_contains "$out" $'\tMACHO: yes' t006

	# t007 verbose lv entitlement
	out="$(run_case t007_verbose_lv 0 "$prog" "${FIXTURES}/with_lv_ent" -v)"
	assert_contains "$out" "${FIXTURES}/with_lv_ent" t007
	assert_contains "$out" $'\tentitlements' t007
	assert_contains "$out" \
		$'\t\tcom.apple.security.cs.disable-library-validation' t007

	# t008 verbose clean binary (no entitlements)
	out="$(run_case t008_verbose_clean 0 "$prog" /bin/ls -v)"
	assert_contains "$out" "/bin/ls" t008
	assert_not_contains "$out" $'\tentitlements' t008
	assert_contains "$out" $'\tMACHO: yes' t008
	assert_contains "$out" $'\tlibraries' t008
	assert_contains "$out" $'\t\t/usr/lib/libSystem.B.dylib' t008

	# t009 verbose safe entitlements (no dangerous flags)
	out="$(run_case t009_verbose_safe 0 "$prog" "${FIXTURES}/with_safe_ent" -v)"
	assert_contains "$out" "${FIXTURES}/with_safe_ent" t009
	assert_contains "$out" $'\tentitlements' t009
	assert_contains "$out" $'\t\tcom.apple.security.get-task-allow' t009

	# t010 setuid binary
	out="$(run_case t010_setuid 0 "$prog" "${FIXTURES}/setuid_bin")"
	assert_contains "$out" "${FIXTURES}/setuid_bin" t010
	inode="$(stat -f '%i' "${FIXTURES}/setuid_bin")"
	assert_contains "$out" $'\tinode' t010
	assert_contains "$out" $'\t\t'"${inode}" t010
	assert_contains "$out" $'\tsetuid' t010
	assert_contains "$out" $'\t\t-rws' t010

	# t011 path normalization (no double slashes)
	out="$(run_case t011_normpath 0 "$prog" "${FIXTURES}/tree/" -v)"
	assert_not_contains "$out" "//" t011
	assert_contains "$out" "${FIXTURES}/tree/binary" t011

	# t012 symlink scan root (default)
	out="$(run_case t012_symlink_root 0 "$prog" "${FIXTURES}/tree_link")"
	assert_contains "$out" "${FIXTURES}/tree_link" t012
	assert_contains "$out" $'\tsymlink' t012
	assert_contains "$out" "${FIXTURES}/tree" t012
	assert_not_contains "$out" $'\tsticky bit' t012

	# t012b path through symlink component (/tmp -> /private/tmp)
	if [[ -L /tmp ]]; then
		tmpfile="/tmp/mss_path_$$"
		touch "$tmpfile"
		chmod 0777 "$tmpfile"
		out="$(run_case t012b_tmp_resolve 0 "$prog" "$tmpfile")"
		assert_contains "$out" "/private/tmp/mss_path_$$" t012b
		assert_contains "$out" $'\tsymlink' t012b
		if [[ "${out%%$'\n'*}" != "$tmpfile" ]]; then
			printf 'FAIL t012b: first line is not input path\n' >&2
			printf '%s\n' "$out" >&2
			exit 1
		fi
		rm -f "$tmpfile"
	fi

	# t018 explicit symlink scan target (default: always report)
	out="$(run_case t018_link_root 0 "$prog" "${FIXTURES}/link_unsigned")"
	assert_contains "$out" "${FIXTURES}/link_unsigned" t018
	assert_contains "$out" $'\tsymlink' t018
	assert_contains "$out" "${FIXTURES}/unsigned" t018
	assert_contains "$out" $'\tinode' t018

	# t019 dangling symlink with ../ in target shows resolved path
	out="$(run_case t019_dotdot 0 "$prog" "${FIXTURES}/dotdot_link")"
	assert_contains "$out" 'sub/../dotdot_tree/noexist' t019
	assert_contains "$out" "${FIXTURES}/dotdot_tree/noexist" t019

	# t017 dangling symlink with user-creatable target (default)
	out="$(run_case t017_dangle 0 "$prog" "${FIXTURES}/dangle_link")"
	assert_contains "$out" "${FIXTURES}/dangle_link" t017
	assert_contains "$out" $'\tsymlink' t017
	assert_contains "$out" $'\tmissing' t017
	assert_contains "$out" 'does/not/exist' t017
	assert_contains "$out" $'\tcreatable' t017
	assert_contains "$out" $'\t\t'"${FIXTURES}"' drwx' t017

	# t017b dangling symlink verbose
	out="$(run_case t017b_dangle_verbose 0 "$prog" "${FIXTURES}/dangle_link" -v)"
	assert_contains "$out" $'\tmissing' t017b
	assert_contains "$out" $'\tKIND: symlink' t017b

	# t016 rpath + disable-library-validation (default)
	out="$(run_case t016_rpath 0 "$prog" "${FIXTURES}/with_rpath_lv")"
	assert_contains "$out" "${FIXTURES}/with_rpath_lv" t016
	assert_contains "$out" $'\trpath' t016
	assert_contains "$out" 'unsafe_rpath_lib' t016
	assert_contains "$out" '@rpath/libevil.dylib' t016
	assert_not_contains "$out" $'\tmissing' t016

	# t016d risky rpath without disable-library-validation (default: silent)
	out="$(run_case t016d_rpath_no_lv 0 "$prog" "${FIXTURES}/with_rpath")"
	assert_not_contains "$out" $'\trpath' t016d

	# t016e risky rpath without disable-library-validation (verbose)
	out="$(run_case t016e_rpath_verbose 0 "$prog" "${FIXTURES}/with_rpath" -v)"
	assert_contains "$out" $'\trpath' t016e
	assert_contains "$out" 'unsafe_rpath_lib' t016e

	# t016b rpath directory missing but creatable under writable parent
	out="$(run_case t016b_rpath_missing 0 "$prog" \
		"${FIXTURES}/with_rpath_missing_lv")"
	assert_contains "$out" $'\tmissing' t016b
	assert_contains "$out" 'unsafe_rpath_lib/missing/lib' t016b
	assert_contains "$out" $'\tcreatable' t016b
	assert_contains "$out" 'unsafe_rpath_lib drwxrwxrwx' t016b

	# t016c rpath flagged: list all entitlements (default)
	out="$(run_case t016c_rpath_ent 0 "$prog" "${FIXTURES}/with_rpath_lv")"
	assert_contains "$out" $'\trpath' t016c
	assert_contains "$out" $'\tentitlements' t016c
	assert_contains "$out" \
		'com.apple.security.cs.disable-library-validation' t016c

	# t018 relative-path + disable-library-validation (default)
	out="$(run_case t018_relpath 0 "$prog" "${FIXTURES}/with_relpath_lv")"
	assert_contains "$out" "${FIXTURES}/with_relpath_lv" t018
	assert_contains "$out" $'\trelative-path' t018
	assert_contains "$out" '@executable_path/rel_framework/librel.dylib' t018
	assert_contains "$out" $'\tentitlements' t018

	# t018b relative-path without disable-library-validation (default: silent)
	out="$(run_case t018b_relpath_no_lv 0 "$prog" "${FIXTURES}/with_relpath")"
	assert_not_contains "$out" $'\trelative-path' t018b

	# t018c relative-path without disable-library-validation (verbose)
	out="$(run_case t018c_relpath_verbose 0 "$prog" \
		"${FIXTURES}/with_relpath" -v)"
	assert_contains "$out" $'\trelative-path' t018c
	assert_contains "$out" '@executable_path/rel_framework/librel.dylib' t018c

	# t019 writable linked library (default)
	out="$(run_case t019_writable_lib 0 "$prog" \
		"${FIXTURES}/with_writable_lib")"
	assert_contains "$out" "${FIXTURES}/with_writable_lib" t019
	assert_contains "$out" $'\twritable-libraries' t019
	assert_contains "$out" 'writable_lib/libw.dylib' t019
	assert_contains "$out" '0777' t019

	# t019b relpath_lv also has world-writable resolved library
	out="$(run_case t019b_relpath_writable 0 "$prog" \
		"${FIXTURES}/with_relpath_lv")"
	assert_contains "$out" $'\twritable-libraries' t019b
	assert_contains "$out" 'rel_framework/librel.dylib' t019b

	# t013 writable-by-others without sticky bit (default)
	out="$(run_case t013_unsafe_dir 0 "$prog" "${FIXTURES}/unsafe_dir")"
	assert_contains "$out" "${FIXTURES}/unsafe_dir" t013
	assert_contains "$out" $'\twritable-by-others, sticky bit' t013
	assert_contains "$out" $'\t\tdrwxrwxrwx 0777' t013

	# t014 writable-by-others with sticky (default)
	out="$(run_case t014_sticky_dir 0 "$prog" "${FIXTURES}/sticky_dir")"
	assert_contains "$out" "${FIXTURES}/sticky_dir" t014
	assert_contains "$out" $'\twritable-by-others, sticky bit' t014
	assert_contains "$out" $'\t\tdrwxrwxrwt 1777' t014

	# t015 sticky dir verbose (no finding: directory permissions)
	out="$(run_case t015_sticky_verbose 0 "$prog" "${FIXTURES}/sticky_dir" -v)"
	assert_contains "$out" "${FIXTURES}/sticky_dir" t015
	assert_contains "$out" $'\tdirectory permissions' t015
	assert_not_contains "$out" $'\tsticky bit' t015
	assert_contains "$out" $'\t\tdrwxrwxrwt 1777' t015

	# t020 directory symlink must not recurse outside scan tree
	out="$(run_case t020_escape_symlink_dir 0 "$prog" \
		"${FIXTURES}/escape_walk/scan_here")"
	assert_not_contains "$out" \
		"${FIXTURES}/escape_walk/outside/with_both_ent" t020
	assert_not_contains "$out" \
		'com.apple.security.cs.allow-dyld-environment-variables' t020

	printf 'PASS functional\n'
}

main "$@"