/*
 * scan.h - Path classification and recursive scanning.
 */

#ifndef SCAN_H
#define SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	SCAN_KIND_FILE = 0,
	SCAN_KIND_DIRECTORY,
	SCAN_KIND_SYMLINK
} scan_kind_t;

int scan_classify_path(const char *, scan_kind_t *);
int scan_target(const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* SCAN_H */
