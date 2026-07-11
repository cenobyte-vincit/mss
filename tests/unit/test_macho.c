/*
 * test_macho.c - Unit tests for Mach-O detection and entitlement extraction.
 */

#include "macho.h"
#include "plist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		return (1); \
	} \
} while (0)

static const char *FIXTURES = "tests/build/fixtures";

static int
test_non_macho(void)
{
	macho_kind_t kind;
	char path[512];

	snprintf(path, sizeof(path), "%s/plain.txt", FIXTURES);
	TEST_ASSERT(macho_kind_of(path, &kind) == 0);
	TEST_ASSERT(kind == MACHO_KIND_NONE);
	return (0);
}

static int
test_thin_macho(void)
{
	macho_kind_t kind;
	char path[512];

	snprintf(path, sizeof(path), "%s/unsigned", FIXTURES);
	TEST_ASSERT(macho_kind_of(path, &kind) == 0);
	TEST_ASSERT(kind == MACHO_KIND_THIN);
	return (0);
}

static int
test_entitlements_dyld(void)
{
	macho_entitlements_t ent;
	plist_keys_t keys;
	char path[512];
	int rc;

	snprintf(path, sizeof(path), "%s/with_dyld_ent", FIXTURES);
	memset(&ent, 0, sizeof(ent));
	rc = macho_entitlements_for_path(path, &ent);
	TEST_ASSERT(rc == 1);
	TEST_ASSERT(ent.len > 0);
	TEST_ASSERT(plist_keys_from_xml((const char *)ent.data, ent.len,
	    &keys) == 0);
	TEST_ASSERT(plist_keys_has(&keys,
	    "com.apple.security.cs.allow-dyld-environment-variables"));
	TEST_ASSERT(!plist_keys_has(&keys,
	    "com.apple.security.cs.disable-library-validation"));
	plist_keys_free(&keys);
	macho_entitlements_free(&ent);
	return (0);
}

static int
test_entitlements_lv(void)
{
	macho_entitlements_t ent;
	plist_keys_t keys;
	char path[512];
	int rc;

	snprintf(path, sizeof(path), "%s/with_lv_ent", FIXTURES);
	memset(&ent, 0, sizeof(ent));
	rc = macho_entitlements_for_path(path, &ent);
	TEST_ASSERT(rc == 1);
	TEST_ASSERT(plist_keys_from_xml((const char *)ent.data, ent.len,
	    &keys) == 0);
	TEST_ASSERT(plist_keys_has(&keys,
	    "com.apple.security.cs.disable-library-validation"));
	TEST_ASSERT(!plist_keys_has(&keys,
	    "com.apple.security.cs.allow-dyld-environment-variables"));
	plist_keys_free(&keys);
	macho_entitlements_free(&ent);
	return (0);
}

static int
test_system_universal(void)
{
	macho_kind_t kind;

	TEST_ASSERT(macho_kind_of("/bin/ls", &kind) == 0);
	TEST_ASSERT(kind == MACHO_KIND_FAT);
	return (0);
}

static int
test_filetype_execute(void)
{
	macho_filetype_t ftype;
	char path[512];

	snprintf(path, sizeof(path), "%s/with_both_ent", FIXTURES);
	TEST_ASSERT(macho_filetype_of(path, &ftype) == 0);
	TEST_ASSERT(ftype == MACHO_FILE_EXECUTE);
	return (0);
}

static int
test_rpath_info(void)
{
	macho_rpath_info_t info;
	char path[512];

	snprintf(path, sizeof(path), "%s/with_rpath", FIXTURES);
	memset(&info, 0, sizeof(info));
	TEST_ASSERT(macho_rpath_info_for_path(path, &info) == 1);
	TEST_ASSERT(info.rpaths.count == 1);
	TEST_ASSERT(info.deps.count == 1);
	TEST_ASSERT(strstr(info.rpaths.items[0], "unsafe_rpath_lib") != NULL);
	TEST_ASSERT(strcmp(info.deps.items[0], "@rpath/libevil.dylib") == 0);
	macho_rpath_info_free(&info);
	return (0);
}

static int
test_filetype_dylib(void)
{
	macho_filetype_t ftype;
	char path[512];

	snprintf(path, sizeof(path), "%s/with_both_ent.dylib", FIXTURES);
	TEST_ASSERT(macho_filetype_of(path, &ftype) == 0);
	TEST_ASSERT(ftype == MACHO_FILE_DYLIB);
	return (0);
}

int
main(void)
{
	if (test_non_macho() != 0)
		exit (1);
	if (test_thin_macho() != 0)
		exit (1);
	if (test_entitlements_dyld() != 0)
		exit (1);
	if (test_entitlements_lv() != 0)
		exit (1);
	if (test_system_universal() != 0)
		exit (1);
	if (test_filetype_execute() != 0)
		exit (1);
	if (test_filetype_dylib() != 0)
		exit (1);
	if (test_rpath_info() != 0)
		exit (1);
	printf("PASS\n");
	return (0);
}
