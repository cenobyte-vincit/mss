#!/usr/bin/env bash
#
# build_fixtures.sh - Build signed and unsigned Mach-O test fixtures.
#
# Uses cc and codesign only to create inputs for tests. The mss scanner
# itself does not invoke external utilities.
#
set -euo pipefail
IFS=$'\n\t'

readonly __progname="build_fixtures"
readonly SRC="$(cd "$(dirname "$0")" && pwd)"
readonly OUT="${SRC}/../build/fixtures"

errx() {
	printf '%s: %s\n' "$__progname" "$*" >&2
	exit 1
}

main() {
	local hello_c

	hello_c="${SRC}/hello.c"
	mkdir -p "${OUT}/tree"
	printf 'plain text fixture\n' >"${OUT}/plain.txt"
	cc -std=c17 -Wall -Wextra -Werror -o "${OUT}/unsigned" "$hello_c"
	cc -std=c17 -Wall -Wextra -Werror -dynamiclib \
		-o "${OUT}/with_both_ent.dylib" "$hello_c"
	cp "${OUT}/unsigned" "${OUT}/tree/binary"
	cp "${OUT}/plain.txt" "${OUT}/tree/readme.txt"
	mkdir -p "${OUT}/tree/subdir"
	cp "${OUT}/plain.txt" "${OUT}/tree/subdir/nested.txt"
	cp "${OUT}/unsigned" "${OUT}/with_dyld_ent"
	cp "${OUT}/unsigned" "${OUT}/with_lv_ent"
	cp "${OUT}/unsigned" "${OUT}/with_both_ent"
	cp "${OUT}/unsigned" "${OUT}/with_safe_ent"
	codesign -s - --entitlements "${SRC}/ent_dyld.plist" \
		"${OUT}/with_dyld_ent"
	codesign -s - --entitlements "${SRC}/ent_lv.plist" \
		"${OUT}/with_lv_ent"
	codesign -s - --entitlements "${SRC}/ent_both.plist" \
		"${OUT}/with_both_ent"
	codesign -s - --entitlements "${SRC}/ent_safe.plist" \
		"${OUT}/with_safe_ent"
	cp "${OUT}/unsigned" "${OUT}/setuid_bin"
	chmod 4755 "${OUT}/setuid_bin"
	ln -sfn tree "${OUT}/tree_link"
	mkdir -p "${OUT}/sticky_dir" "${OUT}/unsafe_dir"
	chmod 1777 "${OUT}/sticky_dir"
	chmod 0777 "${OUT}/unsafe_dir"
	mkdir -p "${OUT}/unsafe_rpath_lib"
	chmod 0777 "${OUT}/unsafe_rpath_lib"
	cc -std=c17 -Wall -Wextra -Werror -dynamiclib \
		-install_name '@rpath/libevil.dylib' \
		-o "${OUT}/unsafe_rpath_lib/libevil.dylib" "$hello_c"
	cc -std=c17 -Wall -Wextra -Werror -o "${OUT}/with_rpath" "$hello_c" \
		-L"${OUT}/unsafe_rpath_lib" -levil \
		-Wl,-rpath,"${OUT}/unsafe_rpath_lib"
	cc -std=c17 -Wall -Wextra -Werror -o "${OUT}/with_rpath_missing" \
		"$hello_c" -L"${OUT}/unsafe_rpath_lib" -levil \
		-Wl,-rpath,"${OUT}/unsafe_rpath_lib/missing/lib"
	cp "${OUT}/with_rpath" "${OUT}/with_rpath_lv"
	codesign -s - --entitlements "${SRC}/ent_lv.plist" \
		"${OUT}/with_rpath_lv"
	cp "${OUT}/with_rpath_missing" "${OUT}/with_rpath_missing_lv"
	codesign -s - --entitlements "${SRC}/ent_lv.plist" \
		"${OUT}/with_rpath_missing_lv"
	mkdir -p "${OUT}/rel_framework"
	cc -std=c17 -Wall -Wextra -Werror -dynamiclib \
		-install_name '@executable_path/rel_framework/librel.dylib' \
		-o "${OUT}/rel_framework/librel.dylib" "$hello_c"
	cc -std=c17 -Wall -Wextra -Werror -o "${OUT}/with_relpath" "$hello_c" \
		-L"${OUT}/rel_framework" -lrel
	cp "${OUT}/with_relpath" "${OUT}/with_relpath_lv"
	codesign -s - --entitlements "${SRC}/ent_lv.plist" \
		"${OUT}/with_relpath_lv"
	chmod 0777 "${OUT}/rel_framework/librel.dylib"
	mkdir -p "${OUT}/writable_lib"
	cc -std=c17 -Wall -Wextra -Werror -dynamiclib \
		-install_name '@executable_path/writable_lib/libw.dylib' \
		-o "${OUT}/writable_lib/libw.dylib" "$hello_c"
	chmod 0777 "${OUT}/writable_lib/libw.dylib"
	cc -std=c17 -Wall -Wextra -Werror -o "${OUT}/with_writable_lib" \
		"$hello_c" -L"${OUT}/writable_lib" -lw
	ln -sfn "does/not/exist" "${OUT}/dangle_link"
	mkdir -p "${OUT}/dotdot_tree/sub"
	chmod 0777 "${OUT}/dotdot_tree"
	ln -sfn "sub/../dotdot_tree/noexist" "${OUT}/dotdot_link"
	ln -sfn unsigned "${OUT}/link_unsigned"
	mkdir -p "${OUT}/escape_walk/outside" "${OUT}/escape_walk/scan_here"
	cp "${OUT}/with_both_ent" "${OUT}/escape_walk/outside/with_both_ent"
	ln -sfn ../outside "${OUT}/escape_walk/scan_here/escape"
}

main "$@"