/*
 * macho.h - Mach-O identification and load-command helpers.
 */

#ifndef MACHO_H
#define MACHO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MACHO_LC_CODE_SIGNATURE	0x1d

#define MACHO_CS_MAGIC_EMBEDDED		0xfade0cc0U
#define MACHO_CS_MAGIC_BLOB		0xfade0b01U
#define MACHO_CS_MAGIC_ENTITLEMENTS	0xfade7171U
#define MACHO_CS_SLOT_ENTITLEMENTS	5U

typedef enum {
	MACHO_KIND_NONE = 0,
	MACHO_KIND_THIN,
	MACHO_KIND_FAT
} macho_kind_t;

typedef enum {
	MACHO_FILE_NONE = 0,
	MACHO_FILE_EXECUTE,
	MACHO_FILE_DYLIB,
	MACHO_FILE_OTHER
} macho_filetype_t;

typedef struct macho_cs_range {
	size_t	offset;
	size_t	length;
} macho_cs_range_t;

typedef struct macho_entitlements {
	uint8_t	*data;
	size_t	len;
} macho_entitlements_t;

typedef struct macho_strlist {
	char	**items;
	size_t	 count;
} macho_strlist_t;

typedef struct macho_rpath_info {
	macho_strlist_t	rpaths;
	macho_strlist_t	deps;
} macho_rpath_info_t;

int macho_kind_of(const char *, macho_kind_t *);
int macho_filetype_of(const char *, macho_filetype_t *);
int macho_entitlements_for_path(const char *, macho_entitlements_t *);
int macho_entitlements_for_slice(const uint8_t *, size_t,
    macho_entitlements_t *);
void macho_entitlements_free(macho_entitlements_t *);
int macho_rpath_info_for_path(const char *, macho_rpath_info_t *);
void macho_rpath_info_free(macho_rpath_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* MACHO_H */
