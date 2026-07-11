/*
 * test_plist.c - Unit tests for XML plist key enumeration.
 */

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

static const char SAMPLE[] =
    "<plist><dict>"
    "<key>alpha</key><true/>"
    "<key>beta</key><false/>"
    "</dict></plist>";

static int
test_keys(void)
{
	plist_keys_t keys;

	memset(&keys, 0, sizeof(keys));
	TEST_ASSERT(plist_keys_from_xml(SAMPLE, strlen(SAMPLE), &keys) == 0);
	TEST_ASSERT(keys.count == 2);
	TEST_ASSERT(plist_keys_has(&keys, "alpha"));
	TEST_ASSERT(plist_keys_has(&keys, "beta"));
	TEST_ASSERT(!plist_keys_has(&keys, "gamma"));
	plist_keys_free(&keys);
	return (0);
}

int
main(void)
{
	if (test_keys() != 0)
		exit (1);
	printf("PASS\n");
	return (0);
}
