/*
 * mss.c - macOS Security Scanner (MSS) CLI entry.
 *
 * Accepts one file or directory path and an optional -v flag. Mach-O files
 * print paths with entitlement findings on executables when both dangerous
 * entitlements are present; -v lists every entitlement on any Mach-O.
 */

#include "scan.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void);

static void
usage(void)
{
	fprintf(stderr, "usage: %s <path> [-v]\n", getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *path;
	int	verbose;

	verbose = 0;
	if (argc != 2 && argc != 3)
		usage();
	path = argv[1];
	if (!*path)
		errx(1, "empty path");
	if (argc == 3) {
		if (strcmp(argv[2], "-v") != 0)
			usage();
		verbose = 1;
	}
	if (scan_target(path, verbose) != 0)
		errx(1, "cannot scan %s", path);
	return (0);
}
