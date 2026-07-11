/*
 * plist.c - Minimal XML plist <key> enumeration for entitlement plists.
 */

#include "plist.h"

#include <stdlib.h>
#include <string.h>

static int
plist_push_key(plist_keys_t *keys, const char *key)
{
	char	**grown;
	char	*copy;
	size_t	i;

	for (i = 0; i < keys->count; i++) {
		if (strcmp(keys->keys[i], key) == 0)
			return (0);
	}
	copy = strdup(key);
	if (copy == NULL)
		return (-1);
	grown = realloc(keys->keys, (keys->count + 1) * sizeof(*grown));
	if (grown == NULL) {
		free(copy);
		return (-1);
	}
	keys->keys = grown;
	keys->keys[keys->count] = copy;
	keys->count++;
	return (0);
}

/*
 * Enumerate top-level <key> strings from an XML plist dict.
 */
int
plist_keys_from_xml(const char *xml, size_t len, plist_keys_t *keys)
{
	const char	*end;
	const char	*key_close;
	const char	*key_open;
	const char	*p;

	if (xml == NULL || keys == NULL)
		return (-1);
	keys->keys = NULL;
	keys->count = 0;
	end = xml + len;
	p = xml;
	while (p < end) {
		key_open = strstr(p, "<key>");
		if (key_open == NULL || key_open >= end)
			break;
		key_close = strstr(key_open, "</key>");
		if (key_close == NULL || key_close >= end)
			break;
		if (key_close > key_open + 5) {
			char	keybuf[512];
			size_t	keylen;

			keylen = (size_t)(key_close - (key_open + 5));
			if (keylen >= sizeof(keybuf))
				return (-1);
			memcpy(keybuf, key_open + 5, keylen);
			keybuf[keylen] = '\0';
			if (plist_push_key(keys, keybuf) != 0) {
				plist_keys_free(keys);
				return (-1);
			}
		}
		p = key_close + 6;
	}
	return (0);
}

void
plist_keys_free(plist_keys_t *keys)
{
	size_t	i;

	if (keys == NULL)
		return;
	for (i = 0; i < keys->count; i++)
		free(keys->keys[i]);
	free(keys->keys);
	keys->keys = NULL;
	keys->count = 0;
}

int
plist_keys_has(const plist_keys_t *keys, const char *key)
{
	size_t	i;

	if (keys == NULL || key == NULL)
		return (0);
	for (i = 0; i < keys->count; i++) {
		if (strcmp(keys->keys[i], key) == 0)
			return (1);
	}
	return (0);
}
