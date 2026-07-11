/*
 * test_scan.c - Unit tests for path classification.
 */

#include "scan.h"

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
test_classify_file(void)
{
	scan_kind_t kind;
	char path[512];

	snprintf(path, sizeof(path), "%s/plain.txt", FIXTURES);
	TEST_ASSERT(scan_classify_path(path, &kind) == 0);
	TEST_ASSERT(kind == SCAN_KIND_FILE);
	return (0);
}

static int
test_classify_directory(void)
{
	scan_kind_t kind;
	char path[512];

	snprintf(path, sizeof(path), "%s/tree", FIXTURES);
	TEST_ASSERT(scan_classify_path(path, &kind) == 0);
	TEST_ASSERT(kind == SCAN_KIND_DIRECTORY);
	return (0);
}

int
main(void)
{
	if (test_classify_file() != 0)
		exit (1);
	if (test_classify_directory() != 0)
		exit (1);
	printf("PASS\n");
	return (0);
}
