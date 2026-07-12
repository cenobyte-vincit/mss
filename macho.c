/*
 * macho.c - Mach-O identification and code-signature entitlement extraction.
 *
 * Reads Mach-O headers and load commands in-process. Extracts the
 * entitlements slot from an embedded code-signature superblob without
 * invoking external utilities.
 */

#include "macho.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MACHO_MAGIC_32		0xfeedfaceU
#define MACHO_MAGIC_64		0xfeedfacfU
#define MACHO_MAGIC_32_SWAPPED	0xcefaedfeU
#define MACHO_MAGIC_64_SWAPPED	0xcffaedfeU
#define MACHO_FAT_MAGIC		0xcafebabeU
#define MACHO_FAT_MAGIC_SWAPPED	0xbebafecaU

#define MACHO_FILETYPE_EXECUTE	2U
#define MACHO_FILETYPE_DYLIB	6U

#define MACHO_LC_LOAD_DYLIB		0xcU
#define MACHO_LC_LOAD_WEAK_DYLIB	0x80000018U
#define MACHO_LC_REEXPORT_DYLIB		0x8000001fU
#define MACHO_LC_LAZY_LOAD_DYLIB	0x20U
#define MACHO_LC_LOAD_UPWARD_DYLIB	0x80000023U
#define MACHO_LC_RPATH			0x8000001cU

struct macho_fat_header {
	uint32_t	magic;
	uint32_t	nfat_arch;
};

struct macho_fat_arch {
	uint32_t	cputype;
	uint32_t	cpusubtype;
	uint32_t	offset;
	uint32_t	size;
	uint32_t	align;
};

struct macho_header_32 {
	uint32_t	magic;
	uint32_t	cputype;
	uint32_t	cpusubtype;
	uint32_t	filetype;
	uint32_t	ncmds;
	uint32_t	sizeofcmds;
	uint32_t	flags;
};

struct macho_header_64 {
	uint32_t	magic;
	uint32_t	cputype;
	uint32_t	cpusubtype;
	uint32_t	filetype;
	uint32_t	ncmds;
	uint32_t	sizeofcmds;
	uint32_t	flags;
	uint32_t	reserved;
};

struct macho_load_command {
	uint32_t	cmd;
	uint32_t	cmdsize;
};

struct macho_linkedit_data_command {
	uint32_t	cmd;
	uint32_t	cmdsize;
	uint32_t	dataoff;
	uint32_t	datasize;
};

struct macho_cs_blob_index {
	uint32_t	type;
	uint32_t	offset;
};

struct macho_cs_superblob {
	uint32_t	magic;
	uint32_t	length;
	uint32_t	count;
};

struct macho_cs_generic_blob {
	uint32_t	magic;
	uint32_t	length;
};

static int macho_entitlements_from_slice(const uint8_t *, size_t,
    macho_entitlements_t *);

static int
macho_read_file(const char *path, uint8_t **out, size_t *out_len)
{
	uint8_t	*buf;
	ssize_t	nread;
	size_t	total;
	size_t	cap;
	int	fd;

	*out = NULL;
	*out_len = 0;
	if ((fd = open(path, O_RDONLY)) < 0)
		return (-1);
	cap = 65536;
	buf = malloc(cap);
	if (buf == NULL) {
		close(fd);
		return (-1);
	}
	total = 0;
	for (;;) {
		if (total == cap) {
			uint8_t *grown;

			if (cap > SIZE_MAX / 2) {
				free(buf);
				close(fd);
				errno = EFBIG;
				return (-1);
			}
			cap *= 2;
			grown = realloc(buf, cap);
			if (grown == NULL) {
				free(buf);
				close(fd);
				return (-1);
			}
			buf = grown;
		}
		nread = read(fd, buf + total, cap - total);
		if (nread < 0) {
			free(buf);
			close(fd);
			return (-1);
		}
		if (nread == 0)
			break;
		total += (size_t)nread;
	}
	close(fd);
	*out = buf;
	*out_len = total;
	return (0);
}

static uint32_t
macho_read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t
macho_swap32(uint32_t value, int swap)
{
	if (!swap)
		return (value);
	return (((value & 0x000000ffU) << 24) | ((value & 0x0000ff00U) << 8) |
	    ((value & 0x00ff0000U) >> 8) | ((value & 0xff000000U) >> 24));
}

static int
macho_magic_is_thin(uint32_t magic)
{
	return (magic == MACHO_MAGIC_32 || magic == MACHO_MAGIC_64 ||
	    magic == MACHO_MAGIC_32_SWAPPED || magic == MACHO_MAGIC_64_SWAPPED);
}

static int
macho_magic_is_fat(uint32_t magic)
{
	return (magic == MACHO_FAT_MAGIC || magic == MACHO_FAT_MAGIC_SWAPPED);
}

/*
 * Classify a file as thin Mach-O, fat Mach-O, or neither.
 */
int
macho_kind_of(const char *path, macho_kind_t *kind)
{
	uint8_t	*data;
	size_t	len;
	uint32_t magic;

	if (kind == NULL)
		return (-1);
	*kind = MACHO_KIND_NONE;
	if (macho_read_file(path, &data, &len) != 0)
		return (-1);
	if (len < sizeof(uint32_t)) {
		free(data);
		return (0);
	}
	memcpy(&magic, data, sizeof(magic));
	free(data);
	if (macho_magic_is_thin(magic))
		*kind = MACHO_KIND_THIN;
	else if (macho_magic_is_fat(magic))
		*kind = MACHO_KIND_FAT;
	return (0);
}

static int
macho_slice_is_64(uint32_t magic)
{
	return (magic == MACHO_MAGIC_64 || magic == MACHO_MAGIC_64_SWAPPED);
}

static int
macho_slice_swapped(uint32_t magic)
{
	return (magic == MACHO_MAGIC_32_SWAPPED ||
	    magic == MACHO_MAGIC_64_SWAPPED);
}

static macho_filetype_t
macho_filetype_classify(uint32_t filetype)
{
	if (filetype == MACHO_FILETYPE_EXECUTE)
		return (MACHO_FILE_EXECUTE);
	if (filetype == MACHO_FILETYPE_DYLIB)
		return (MACHO_FILE_DYLIB);
	return (MACHO_FILE_OTHER);
}

static int
macho_filetype_from_slice(const uint8_t *slice, size_t slice_len,
    macho_filetype_t *ftype)
{
	const struct macho_header_32	*mh32;
	const struct macho_header_64	*mh64;
	uint32_t			 filetype;
	uint32_t			 magic;
	int				 swap;

	if (ftype == NULL || slice_len < sizeof(struct macho_header_32))
		return (-1);
	memcpy(&magic, slice, sizeof(magic));
	if (!macho_magic_is_thin(magic))
		return (-1);
	swap = macho_slice_swapped(magic);
	if (macho_slice_is_64(magic)) {
		if (slice_len < sizeof(*mh64))
			return (-1);
		mh64 = (const struct macho_header_64 *)slice;
		filetype = macho_swap32(mh64->filetype, swap);
	} else {
		if (slice_len < sizeof(*mh32))
			return (-1);
		mh32 = (const struct macho_header_32 *)slice;
		filetype = macho_swap32(mh32->filetype, swap);
	}
	*ftype = macho_filetype_classify(filetype);
	return (0);
}

static macho_filetype_t
macho_filetype_merge(macho_filetype_t acc, macho_filetype_t slice)
{
	if (acc == MACHO_FILE_EXECUTE || slice == MACHO_FILE_EXECUTE)
		return (MACHO_FILE_EXECUTE);
	if (acc == MACHO_FILE_DYLIB || slice == MACHO_FILE_DYLIB)
		return (MACHO_FILE_DYLIB);
	if (acc == MACHO_FILE_OTHER || slice == MACHO_FILE_OTHER)
		return (MACHO_FILE_OTHER);
	return (MACHO_FILE_NONE);
}

/*
 * Classify Mach-O filetype as executable, dylib, or other.
 */
int
macho_filetype_of(const char *path, macho_filetype_t *ftype)
{
	macho_filetype_t	slice_type;
	uint8_t			*data;
	size_t			len;
	uint32_t		magic;
	uint32_t		nfat;
	int			swap;
	size_t			i;

	if (ftype == NULL)
		return (-1);
	*ftype = MACHO_FILE_NONE;
	if (macho_read_file(path, &data, &len) != 0)
		return (-1);
	if (len < sizeof(uint32_t)) {
		free(data);
		return (0);
	}
	memcpy(&magic, data, sizeof(magic));
	if (macho_magic_is_thin(magic)) {
		if (macho_filetype_from_slice(data, len, ftype) != 0)
			*ftype = MACHO_FILE_NONE;
		free(data);
		return (0);
	}
	if (!macho_magic_is_fat(magic)) {
		free(data);
		return (0);
	}
	swap = (magic == MACHO_FAT_MAGIC_SWAPPED);
	memcpy(&nfat, data + sizeof(uint32_t), sizeof(nfat));
	nfat = macho_swap32(nfat, swap);
	for (i = 0; i < nfat; i++) {
		const struct macho_fat_arch	*arch;
		uint32_t			 offset;
		uint32_t			 size;

		if (sizeof(struct macho_fat_header) +
		    (i + 1) * sizeof(struct macho_fat_arch) > len)
			break;
		arch = (const struct macho_fat_arch *)(data +
		    sizeof(struct macho_fat_header) +
		    i * sizeof(struct macho_fat_arch));
		offset = macho_swap32(arch->offset, swap);
		size = macho_swap32(arch->size, swap);
		if ((size_t)offset + (size_t)size > len)
			continue;
		if (macho_filetype_from_slice(data + offset, size,
		    &slice_type) != 0)
			continue;
		*ftype = macho_filetype_merge(*ftype, slice_type);
	}
	free(data);
	return (0);
}

static int
macho_find_cs_range(const uint8_t *slice, size_t slice_len,
    macho_cs_range_t *range)
{
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t dataoff;
	uint32_t datasize;
	uint32_t hdrsize;
	uint32_t magic;
	uint32_t ncmds;
	size_t	off;
	int	swap;
	int	is64;

	memset(range, 0, sizeof(*range));
	if (slice_len < sizeof(uint32_t))
		return (0);
	memcpy(&magic, slice, sizeof(magic));
	if (!macho_magic_is_thin(magic))
		return (0);
	swap = macho_slice_swapped(magic);
	is64 = macho_slice_is_64(magic);
	hdrsize = is64 ? sizeof(struct macho_header_64) :
	    sizeof(struct macho_header_32);
	if (slice_len < hdrsize)
		return (0);
	if (is64) {
		memcpy(&ncmds, slice + offsetof(struct macho_header_64, ncmds),
		    sizeof(ncmds));
	} else {
		memcpy(&ncmds, slice + offsetof(struct macho_header_32, ncmds),
		    sizeof(ncmds));
	}
	ncmds = macho_swap32(ncmds, swap);
	off = hdrsize;
	for (uint32_t i = 0; i < ncmds; i++) {
		if (off + sizeof(struct macho_load_command) > slice_len)
			return (0);
		memcpy(&cmd, slice + off, sizeof(cmd));
		memcpy(&cmdsize, slice + off + sizeof(uint32_t),
		    sizeof(cmdsize));
		cmd = macho_swap32(cmd, swap);
		cmdsize = macho_swap32(cmdsize, swap);
		if (cmdsize < sizeof(struct macho_load_command) ||
		    off + cmdsize > slice_len)
			return (0);
		if (cmd == MACHO_LC_CODE_SIGNATURE) {
			if (cmdsize <
			    sizeof(struct macho_linkedit_data_command))
				return (0);
			memcpy(&dataoff, slice + off + 2 * sizeof(uint32_t),
			    sizeof(dataoff));
			memcpy(&datasize, slice + off + 3 * sizeof(uint32_t),
			    sizeof(datasize));
			dataoff = macho_swap32(dataoff, swap);
			datasize = macho_swap32(datasize, swap);
			if ((size_t)dataoff + (size_t)datasize > slice_len)
				return (0);
			range->offset = dataoff;
			range->length = datasize;
			return (1);
		}
		off += cmdsize;
	}
	return (0);
}

static int
macho_merge_entitlements(macho_entitlements_t *dst,
    const macho_entitlements_t *src)
{
	uint8_t	*grown;
	size_t	newlen;

	if (src->data == NULL || src->len == 0)
		return (0);
	if (dst->data == NULL) {
		dst->data = malloc(src->len + 1);
		if (dst->data == NULL)
			return (-1);
		memcpy(dst->data, src->data, src->len);
		dst->data[src->len] = '\0';
		dst->len = src->len;
		return (0);
	}
	newlen = dst->len + src->len;
	grown = realloc(dst->data, newlen + 1);
	if (grown == NULL)
		return (-1);
	memcpy(grown + dst->len, src->data, src->len);
	grown[newlen] = '\0';
	dst->data = grown;
	dst->len = newlen;
	return (0);
}

/*
 * Extract entitlements XML from a Mach-O file (thin or fat).
 */
int
macho_entitlements_for_path(const char *path, macho_entitlements_t *out)
{
	macho_entitlements_t slice_ent;
	uint8_t	*data;
	size_t	len;
	uint32_t magic;
	uint32_t nfat;
	int	swap;
	int	rc;
	size_t	i;

	memset(out, 0, sizeof(*out));
	if (macho_read_file(path, &data, &len) != 0)
		return (-1);
	if (len < sizeof(uint32_t)) {
		free(data);
		return (0);
	}
	memcpy(&magic, data, sizeof(magic));
	if (macho_magic_is_thin(magic)) {
		rc = macho_entitlements_from_slice(data, len, out);
		free(data);
		return (rc);
	}
	if (!macho_magic_is_fat(magic)) {
		free(data);
		return (0);
	}
	swap = (magic == MACHO_FAT_MAGIC_SWAPPED);
	memcpy(&nfat, data + sizeof(uint32_t), sizeof(nfat));
	nfat = macho_swap32(nfat, swap);
	for (i = 0; i < nfat; i++) {
		const struct macho_fat_arch *arch;
		uint32_t offset;
		uint32_t size;

		if (sizeof(struct macho_fat_header) +
		    (i + 1) * sizeof(struct macho_fat_arch) > len)
			break;
		arch = (const struct macho_fat_arch *)(data +
		    sizeof(struct macho_fat_header) +
		    i * sizeof(struct macho_fat_arch));
		offset = macho_swap32(arch->offset, swap);
		size = macho_swap32(arch->size, swap);
		if ((size_t)offset + (size_t)size > len)
			continue;
		memset(&slice_ent, 0, sizeof(slice_ent));
		rc = macho_entitlements_from_slice(data + offset, size,
		    &slice_ent);
		if (rc < 0) {
			macho_entitlements_free(&slice_ent);
			macho_entitlements_free(out);
			free(data);
			return (-1);
		}
		if (rc > 0) {
			if (macho_merge_entitlements(out, &slice_ent) != 0) {
				macho_entitlements_free(&slice_ent);
				macho_entitlements_free(out);
				free(data);
				return (-1);
			}
		}
		macho_entitlements_free(&slice_ent);
	}
	free(data);
	return (out->len > 0 ? 1 : 0);
}

static int
macho_extract_entitlements_blob(const uint8_t *cs, size_t cs_len,
    const uint8_t **ent, size_t *ent_len)
{
	uint32_t blob_length;
	uint32_t blob_magic;
	uint32_t count;
	uint32_t length;
	uint32_t magic;
	uint32_t offset;
	uint32_t type;
	size_t	idx_off;
	const struct macho_cs_blob_index *index;
	const struct macho_cs_generic_blob *blob;
	const struct macho_cs_superblob *super;

	*ent = NULL;
	*ent_len = 0;
	if (cs_len < sizeof(struct macho_cs_superblob))
		return (0);
	super = (const struct macho_cs_superblob *)cs;
	magic = macho_read_be32((const uint8_t *)&super->magic);
	length = macho_read_be32((const uint8_t *)&super->length);
	count = macho_read_be32((const uint8_t *)&super->count);
	if (magic != MACHO_CS_MAGIC_EMBEDDED)
		return (0);
	if (length > cs_len || length < sizeof(struct macho_cs_superblob))
		return (0);
	idx_off = sizeof(struct macho_cs_superblob);
	for (uint32_t i = 0; i < count; i++) {
		if (idx_off + sizeof(struct macho_cs_blob_index) > length)
			return (0);
		index = (const struct macho_cs_blob_index *)(cs + idx_off);
		type = macho_read_be32((const uint8_t *)&index->type);
		offset = macho_read_be32((const uint8_t *)&index->offset);
		if (type == MACHO_CS_SLOT_ENTITLEMENTS) {
			if (offset + sizeof(struct macho_cs_generic_blob) >
			    length)
				return (0);
			blob = (const struct macho_cs_generic_blob *)
			    (cs + offset);
			blob_magic = macho_read_be32((const uint8_t *)&blob->magic);
			blob_length = macho_read_be32((const uint8_t *)&blob->length);
			if (blob_magic != MACHO_CS_MAGIC_BLOB &&
			    blob_magic != MACHO_CS_MAGIC_ENTITLEMENTS)
				return (0);
			if (blob_length < sizeof(struct macho_cs_generic_blob) ||
			    offset + blob_length > length)
				return (0);
			*ent = cs + offset +
			    sizeof(struct macho_cs_generic_blob);
			*ent_len = blob_length -
			    sizeof(struct macho_cs_generic_blob);
			return (1);
		}
		idx_off += sizeof(struct macho_cs_blob_index);
	}
	return (0);
}

static int
macho_entitlements_from_slice(const uint8_t *slice, size_t slice_len,
    macho_entitlements_t *out)
{
	const uint8_t	*ent;
	macho_cs_range_t range;
	size_t		ent_len;

	memset(out, 0, sizeof(*out));
	if (!macho_find_cs_range(slice, slice_len, &range))
		return (0);
	if (!macho_extract_entitlements_blob(slice + range.offset,
	    range.length, &ent, &ent_len))
		return (0);
	if (ent_len == 0)
		return (0);
	out->data = malloc(ent_len + 1);
	if (out->data == NULL)
		return (-1);
	memcpy(out->data, ent, ent_len);
	out->data[ent_len] = '\0';
	out->len = ent_len;
	return (1);
}

/*
 * Extract entitlements XML from one Mach-O slice buffer.
 */
int
macho_entitlements_for_slice(const uint8_t *slice, size_t slice_len,
    macho_entitlements_t *out)
{
	if (slice == NULL || out == NULL)
		return (-1);
	return (macho_entitlements_from_slice(slice, slice_len, out));
}

void
macho_entitlements_free(macho_entitlements_t *ent)
{
	if (ent == NULL)
		return;
	free(ent->data);
	ent->data = NULL;
	ent->len = 0;
}

static int
macho_strlist_has(const macho_strlist_t *list, const char *str)
{
	size_t	i;

	for (i = 0; i < list->count; i++) {
		if (strcmp(list->items[i], str) == 0)
			return (1);
	}
	return (0);
}

static int
macho_strlist_push(macho_strlist_t *list, const char *str)
{
	char	**grown;
	char	*copy;

	if (list == NULL || str == NULL || *str == '\0')
		return (-1);
	if (macho_strlist_has(list, str))
		return (0);
	copy = strdup(str);
	if (copy == NULL)
		return (-1);
	grown = realloc(list->items, (list->count + 1) * sizeof(*grown));
	if (grown == NULL) {
		free(copy);
		return (-1);
	}
	list->items = grown;
	list->items[list->count] = copy;
	list->count++;
	return (0);
}

void
macho_rpath_info_free(macho_rpath_info_t *info)
{
	size_t	i;

	if (info == NULL)
		return;
	for (i = 0; i < info->rpaths.count; i++)
		free(info->rpaths.items[i]);
	free(info->rpaths.items);
	for (i = 0; i < info->deps.count; i++)
		free(info->deps.items[i]);
	free(info->deps.items);
	for (i = 0; i < info->relpaths.count; i++)
		free(info->relpaths.items[i]);
	free(info->relpaths.items);
	memset(info, 0, sizeof(*info));
}

static int
macho_is_relpath_dep(const char *str)
{
	if (strncmp(str, "@executable_path", 16) == 0)
		return (1);
	if (strncmp(str, "@loader_path", 12) == 0)
		return (1);
	return (0);
}

static int
macho_lc_string(const uint8_t *slice, size_t slice_len, size_t lc_off,
    uint32_t str_off, uint32_t cmdsize, char *out, size_t outlen)
{
	size_t	abs;
	size_t	i;

	if (str_off >= cmdsize)
		return (-1);
	abs = lc_off + str_off;
	if (abs >= slice_len || outlen == 0)
		return (-1);
	for (i = 0; abs + i < slice_len && i + 1 < outlen; i++) {
		out[i] = (char)slice[abs + i];
		if (out[i] == '\0')
			return (0);
	}
	return (-1);
}

static int
macho_slice_is_dylib_load(uint32_t cmd)
{
	return (cmd == MACHO_LC_LOAD_DYLIB ||
	    cmd == MACHO_LC_LOAD_WEAK_DYLIB ||
	    cmd == MACHO_LC_REEXPORT_DYLIB ||
	    cmd == MACHO_LC_LAZY_LOAD_DYLIB ||
	    cmd == MACHO_LC_LOAD_UPWARD_DYLIB);
}

static int
macho_rpath_from_slice(const uint8_t *slice, size_t slice_len,
    macho_rpath_info_t *out)
{
	uint32_t	cmd;
	uint32_t	cmdsize;
	uint32_t	hdrsize;
	uint32_t	magic;
	uint32_t	name_off;
	uint32_t	ncmds;
	uint32_t	path_off;
	char		str[PATH_MAX];
	size_t		off;
	int		is64;
	int		swap;

	if (slice_len < sizeof(uint32_t))
		return (0);
	memcpy(&magic, slice, sizeof(magic));
	if (!macho_magic_is_thin(magic))
		return (0);
	swap = macho_slice_swapped(magic);
	is64 = macho_slice_is_64(magic);
	hdrsize = is64 ? sizeof(struct macho_header_64) :
	    sizeof(struct macho_header_32);
	if (slice_len < hdrsize)
		return (0);
	if (is64) {
		memcpy(&ncmds, slice + offsetof(struct macho_header_64, ncmds),
		    sizeof(ncmds));
	} else {
		memcpy(&ncmds, slice + offsetof(struct macho_header_32, ncmds),
		    sizeof(ncmds));
	}
	ncmds = macho_swap32(ncmds, swap);
	off = hdrsize;
	for (uint32_t i = 0; i < ncmds; i++) {
		if (off + sizeof(struct macho_load_command) > slice_len)
			return (0);
		memcpy(&cmd, slice + off, sizeof(cmd));
		memcpy(&cmdsize, slice + off + sizeof(uint32_t),
		    sizeof(cmdsize));
		cmd = macho_swap32(cmd, swap);
		cmdsize = macho_swap32(cmdsize, swap);
		if (cmdsize < sizeof(struct macho_load_command) ||
		    off + cmdsize > slice_len)
			return (0);
		if (cmd == MACHO_LC_RPATH) {
			memcpy(&path_off, slice + off + 2 * sizeof(uint32_t),
			    sizeof(path_off));
			path_off = macho_swap32(path_off, swap);
			if (macho_lc_string(slice, slice_len, off, path_off,
			    cmdsize, str, sizeof(str)) != 0)
				return (-1);
			if (macho_strlist_push(&out->rpaths, str) != 0)
				return (-1);
		} else if (macho_slice_is_dylib_load(cmd)) {
			memcpy(&name_off, slice + off + 2 * sizeof(uint32_t),
			    sizeof(name_off));
			name_off = macho_swap32(name_off, swap);
			if (macho_lc_string(slice, slice_len, off, name_off,
			    cmdsize, str, sizeof(str)) != 0)
				return (-1);
			if (strncmp(str, "@rpath/", 7) == 0) {
				if (macho_strlist_push(&out->deps, str) != 0)
					return (-1);
			} else if (macho_is_relpath_dep(str)) {
				if (macho_strlist_push(&out->relpaths, str) != 0)
					return (-1);
			}
		}
		off += cmdsize;
	}
	return (1);
}

static int
macho_merge_rpath_info(macho_rpath_info_t *dst, const macho_rpath_info_t *src)
{
	size_t	i;

	for (i = 0; i < src->rpaths.count; i++) {
		if (macho_strlist_push(&dst->rpaths, src->rpaths.items[i]) != 0)
			return (-1);
	}
	for (i = 0; i < src->deps.count; i++) {
		if (macho_strlist_push(&dst->deps, src->deps.items[i]) != 0)
			return (-1);
	}
	for (i = 0; i < src->relpaths.count; i++) {
		if (macho_strlist_push(&dst->relpaths, src->relpaths.items[i]) !=
		    0)
			return (-1);
	}
	return (0);
}

int
macho_rpath_info_for_path(const char *path, macho_rpath_info_t *out)
{
	macho_rpath_info_t	slice_info;
	uint8_t			*data;
	size_t			len;
	uint32_t		magic;
	uint32_t		nfat;
	int			rc;
	int			swap;
	size_t			i;

	memset(out, 0, sizeof(*out));
	if (macho_read_file(path, &data, &len) != 0)
		return (-1);
	if (len < sizeof(uint32_t)) {
		free(data);
		return (0);
	}
	memcpy(&magic, data, sizeof(magic));
	if (macho_magic_is_thin(magic)) {
		rc = macho_rpath_from_slice(data, len, out);
		free(data);
		if (rc < 0) {
			macho_rpath_info_free(out);
			return (-1);
		}
		return (out->rpaths.count > 0 || out->deps.count > 0 ||
		    out->relpaths.count > 0 ? 1 : 0);
	}
	if (!macho_magic_is_fat(magic)) {
		free(data);
		return (0);
	}
	swap = (magic == MACHO_FAT_MAGIC_SWAPPED);
	memcpy(&nfat, data + sizeof(uint32_t), sizeof(nfat));
	nfat = macho_swap32(nfat, swap);
	for (i = 0; i < nfat; i++) {
		const struct macho_fat_arch	*arch;
		uint32_t			 offset;
		uint32_t			 size;

		if (sizeof(struct macho_fat_header) +
		    (i + 1) * sizeof(struct macho_fat_arch) > len)
			break;
		arch = (const struct macho_fat_arch *)(data +
		    sizeof(struct macho_fat_header) +
		    i * sizeof(struct macho_fat_arch));
		offset = macho_swap32(arch->offset, swap);
		size = macho_swap32(arch->size, swap);
		if ((size_t)offset + (size_t)size > len)
			continue;
		memset(&slice_info, 0, sizeof(slice_info));
		rc = macho_rpath_from_slice(data + offset, size, &slice_info);
		if (rc < 0) {
			macho_rpath_info_free(&slice_info);
			macho_rpath_info_free(out);
			free(data);
			return (-1);
		}
		if (rc > 0) {
			if (macho_merge_rpath_info(out, &slice_info) != 0) {
				macho_rpath_info_free(&slice_info);
				macho_rpath_info_free(out);
				free(data);
				return (-1);
			}
		}
		macho_rpath_info_free(&slice_info);
	}
	free(data);
	return (out->rpaths.count > 0 || out->deps.count > 0 ||
	    out->relpaths.count > 0 ? 1 : 0);
}

void
macho_libs_free(macho_strlist_t *libs)
{
	size_t	i;

	if (libs == NULL)
		return;
	for (i = 0; i < libs->count; i++)
		free(libs->items[i]);
	free(libs->items);
	memset(libs, 0, sizeof(*libs));
}

static int
macho_libs_from_slice(const uint8_t *slice, size_t slice_len,
    macho_strlist_t *out)
{
	uint32_t	cmd;
	uint32_t	cmdsize;
	uint32_t	hdrsize;
	uint32_t	magic;
	uint32_t	name_off;
	uint32_t	ncmds;
	char		str[PATH_MAX];
	size_t		off;
	int		is64;
	int		swap;

	if (slice_len < sizeof(uint32_t))
		return (0);
	memcpy(&magic, slice, sizeof(magic));
	if (!macho_magic_is_thin(magic))
		return (0);
	swap = macho_slice_swapped(magic);
	is64 = macho_slice_is_64(magic);
	hdrsize = is64 ? sizeof(struct macho_header_64) :
	    sizeof(struct macho_header_32);
	if (slice_len < hdrsize)
		return (0);
	if (is64) {
		memcpy(&ncmds, slice + offsetof(struct macho_header_64, ncmds),
		    sizeof(ncmds));
	} else {
		memcpy(&ncmds, slice + offsetof(struct macho_header_32, ncmds),
		    sizeof(ncmds));
	}
	ncmds = macho_swap32(ncmds, swap);
	off = hdrsize;
	for (uint32_t i = 0; i < ncmds; i++) {
		if (off + sizeof(struct macho_load_command) > slice_len)
			return (0);
		memcpy(&cmd, slice + off, sizeof(cmd));
		memcpy(&cmdsize, slice + off + sizeof(uint32_t),
		    sizeof(cmdsize));
		cmd = macho_swap32(cmd, swap);
		cmdsize = macho_swap32(cmdsize, swap);
		if (cmdsize < sizeof(struct macho_load_command) ||
		    off + cmdsize > slice_len)
			return (0);
		if (macho_slice_is_dylib_load(cmd)) {
			memcpy(&name_off, slice + off + 2 * sizeof(uint32_t),
			    sizeof(name_off));
			name_off = macho_swap32(name_off, swap);
			if (macho_lc_string(slice, slice_len, off, name_off,
			    cmdsize, str, sizeof(str)) != 0)
				return (-1);
			if (macho_strlist_push(out, str) != 0)
				return (-1);
		}
		off += cmdsize;
	}
	return (1);
}

static int
macho_merge_libs(macho_strlist_t *dst, const macho_strlist_t *src)
{
	size_t	i;

	for (i = 0; i < src->count; i++) {
		if (macho_strlist_push(dst, src->items[i]) != 0)
			return (-1);
	}
	return (0);
}

int
macho_libs_for_path(const char *path, macho_strlist_t *out)
{
	macho_strlist_t	slice_libs;
	uint8_t		*data;
	size_t		len;
	uint32_t	magic;
	uint32_t	nfat;
	int		rc;
	int		swap;
	size_t		i;

	memset(out, 0, sizeof(*out));
	if (macho_read_file(path, &data, &len) != 0)
		return (-1);
	if (len < sizeof(uint32_t)) {
		free(data);
		return (0);
	}
	memcpy(&magic, data, sizeof(magic));
	if (macho_magic_is_thin(magic)) {
		rc = macho_libs_from_slice(data, len, out);
		free(data);
		if (rc < 0) {
			macho_libs_free(out);
			return (-1);
		}
		return (out->count > 0 ? 1 : 0);
	}
	if (!macho_magic_is_fat(magic)) {
		free(data);
		return (0);
	}
	swap = (magic == MACHO_FAT_MAGIC_SWAPPED);
	memcpy(&nfat, data + sizeof(uint32_t), sizeof(nfat));
	nfat = macho_swap32(nfat, swap);
	for (i = 0; i < nfat; i++) {
		const struct macho_fat_arch	*arch;
		uint32_t			 offset;
		uint32_t			 size;

		if (sizeof(struct macho_fat_header) +
		    (i + 1) * sizeof(struct macho_fat_arch) > len)
			break;
		arch = (const struct macho_fat_arch *)(data +
		    sizeof(struct macho_fat_header) +
		    i * sizeof(struct macho_fat_arch));
		offset = macho_swap32(arch->offset, swap);
		size = macho_swap32(arch->size, swap);
		if ((size_t)offset + (size_t)size > len)
			continue;
		memset(&slice_libs, 0, sizeof(slice_libs));
		rc = macho_libs_from_slice(data + offset, size, &slice_libs);
		if (rc < 0) {
			macho_libs_free(&slice_libs);
			macho_libs_free(out);
			free(data);
			return (-1);
		}
		if (rc > 0) {
			if (macho_merge_libs(out, &slice_libs) != 0) {
				macho_libs_free(&slice_libs);
				macho_libs_free(out);
				free(data);
				return (-1);
			}
		}
		macho_libs_free(&slice_libs);
	}
	free(data);
	return (out->count > 0 ? 1 : 0);
}
