/*
 * plist.h - Minimal XML plist key enumeration.
 */

#ifndef PLIST_H
#define PLIST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct plist_keys {
	char	**keys;
	size_t	count;
} plist_keys_t;

int plist_keys_from_xml(const char *, size_t, plist_keys_t *);
void plist_keys_free(plist_keys_t *);
int plist_keys_has(const plist_keys_t *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* PLIST_H */
