/*
 * scan.c - Path classification, recursive enumeration, and scan reporting.
 */

#include "scan.h"

#include "macho.h"
#include "plist.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENT_ALLOW_DYLD	"com.apple.security.cs.allow-dyld-environment-variables"
#define ENT_DISABLE_LV	"com.apple.security.cs.disable-library-validation"
#define SCAN_PATH_MAX_PARTS 64

#define ANSI_RED	"\x1b[31m"
#define ANSI_YELLOW	"\x1b[33m"
#define ANSI_RESET	"\x1b[0m"

static int
scan_path_cmp(const void *a, const void *b)
{
	return (strcmp(*(const char *const *)a, *(const char *const *)b));
}

static void
scan_collapse_slashes(char *path)
{
	char	*dst;
	char	*src;
	int	slash;

	if (path == NULL || *path == '\0')
		return;
	dst = path;
	src = path;
	slash = 0;
	while (*src != '\0') {
		if (*src == '/') {
			if (slash) {
				src++;
				continue;
			}
			slash = 1;
		} else
			slash = 0;
		*dst++ = *src++;
	}
	*dst = '\0';
}

static int
scan_path_needs_resolve(const char *path)
{
	size_t	len;

	if (path == NULL || path[0] == '\0')
		return (0);
	if (strstr(path, "/../") != NULL || strstr(path, "/./") != NULL)
		return (1);
	if (strncmp(path, "../", 3) == 0)
		return (1);
	len = strlen(path);
	if (len >= 3 && strcmp(path + len - 3, "/..") == 0)
		return (1);
	if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
		return (1);
	return (0);
}

static int
scan_path_push_part(char parts[][PATH_MAX], size_t *nparts, const char *part)
{
	if (*nparts >= SCAN_PATH_MAX_PARTS)
		return (-1);
	if (strlcpy(parts[*nparts], part, PATH_MAX) >= PATH_MAX)
		return (-1);
	(*nparts)++;
	return (0);
}

static int
scan_path_logical_resolve(const char *path, char *out, size_t outlen)
{
	char		parts[SCAN_PATH_MAX_PARTS][PATH_MAX];
	char		part[PATH_MAX];
	size_t		i;
	size_t		j;
	size_t		nparts;
	int		absolute;

	nparts = 0;
	absolute = (path[0] == '/');
	i = absolute ? 1 : 0;
	while (path[i] != '\0') {
		while (path[i] == '/')
			i++;
		if (path[i] == '\0')
			break;
		j = 0;
		while (path[i] != '\0' && path[i] != '/') {
			if (j + 1 >= sizeof(part))
				return (-1);
			part[j++] = path[i++];
		}
		part[j] = '\0';
		if (strcmp(part, ".") == 0)
			continue;
		if (strcmp(part, "..") == 0) {
			if (nparts == 0) {
				if (!absolute &&
				    scan_path_push_part(parts, &nparts, "..") != 0)
					return (-1);
			} else if (strcmp(parts[nparts - 1], "..") == 0) {
				if (scan_path_push_part(parts, &nparts, "..") != 0)
					return (-1);
			} else
				nparts--;
			continue;
		}
		if (scan_path_push_part(parts, &nparts, part) != 0)
			return (-1);
	}
	out[0] = '\0';
	for (i = 0; i < nparts; i++) {
		if (i > 0) {
			if (strlcat(out, "/", outlen) >= outlen)
				return (-1);
		} else if (absolute) {
			if (strlcpy(out, "/", outlen) >= outlen)
				return (-1);
		}
		if (strlcat(out, parts[i], outlen) >= outlen)
			return (-1);
	}
	if (absolute && nparts == 0) {
		if (strlcpy(out, "/", outlen) >= outlen)
			return (-1);
	}
	if (!absolute && nparts == 0) {
		if (strlcpy(out, ".", outlen) >= outlen)
			return (-1);
	}
	return (0);
}

static int
scan_path_display_resolve(const char *path, char *out, size_t outlen)
{
	if (realpath(path, out) != NULL)
		return (0);
	return (scan_path_logical_resolve(path, out, outlen));
}

static void
scan_print_resolved_path_line(const char *path, const char *indent)
{
	char	resolved[PATH_MAX];

	if (!scan_path_needs_resolve(path))
		return;
	if (scan_path_display_resolve(path, resolved, sizeof(resolved)) != 0)
		return;
	if (strcmp(path, resolved) == 0)
		return;
	printf("%s%s\n", indent, resolved);
}

static int
scan_path_join(const char *dir, const char *name, char *out, size_t outlen)
{
	size_t	dirlen;

	if (dir == NULL || name == NULL || out == NULL || outlen == 0)
		return (-1);
	dirlen = strlen(dir);
	if (dirlen > 0 && dir[dirlen - 1] == '/')
		snprintf(out, outlen, "%s%s", dir, name);
	else
		snprintf(out, outlen, "%s/%s", dir, name);
	scan_collapse_slashes(out);
	return (0);
}

static char *
scan_normalize_dup(const char *path)
{
	char	*copy;

	copy = strdup(path);
	if (copy == NULL)
		return (NULL);
	scan_collapse_slashes(copy);
	return (copy);
}

static char *
scan_resolve_dup(const char *path)
{
	char	*copy;
	char	 real[PATH_MAX];

	if (realpath(path, real) != NULL)
		return (scan_normalize_dup(real));
	copy = scan_normalize_dup(path);
	return (copy);
}

static int
scan_push_path(char ***paths, size_t *count, const char *path)
{
	char	**grown;
	char	*copy;

	copy = scan_normalize_dup(path);
	if (copy == NULL)
		return (-1);
	grown = realloc(*paths, (*count + 1) * sizeof(*grown));
	if (grown == NULL) {
		free(copy);
		return (-1);
	}
	*paths = grown;
	(*paths)[*count] = copy;
	(*count)++;
	return (0);
}

static void
scan_free_paths(char **paths, size_t count)
{
	size_t	i;

	for (i = 0; i < count; i++)
		free(paths[i]);
	free(paths);
}

static int	scan_file(const char *, int);
static int	scan_object(const char *, int, int);
static int	scan_walk(const char *, int, int, const char *);

static int
scan_walk_dir(const char *dirpath, int verbose)
{
	char		child[PATH_MAX];
	char		**children;
	DIR		*dir;
	struct dirent	*entry;
	size_t		i;
	size_t		nchildren;

	dir = opendir(dirpath);
	if (dir == NULL)
		return (0);
	nchildren = 0;
	children = NULL;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		if (scan_path_join(dirpath, entry->d_name, child,
		    sizeof(child)) != 0)
			continue;
		if (scan_push_path(&children, &nchildren, child) != 0) {
			closedir(dir);
			scan_free_paths(children, nchildren);
			return (-1);
		}
	}
	closedir(dir);
	if (nchildren > 1)
		qsort(children, nchildren, sizeof(*children), scan_path_cmp);
	for (i = 0; i < nchildren; i++) {
		if (scan_walk(children[i], verbose, 0, NULL) != 0) {
			scan_free_paths(children, nchildren);
			return (-1);
		}
	}
	scan_free_paths(children, nchildren);
	return (0);
}

static int
scan_walk(const char *path, int verbose, int is_root, const char *root_path)
{
	struct stat	st;
	const char	*report;

	report = is_root ? root_path : path;
	if (scan_object(report, verbose, is_root))
		printf("\n");
	if (lstat(path, &st) != 0)
		return (0);
	if (S_ISLNK(st.st_mode))
		return (0);
	if (!S_ISDIR(st.st_mode))
		return (0);
	return (scan_walk_dir(path, verbose));
}

/*
 * Classify a path as a regular file, directory, or symlink.
 */
int
scan_classify_path(const char *path, scan_kind_t *kind)
{
	struct stat	st;

	if (path == NULL || kind == NULL)
		return (-1);
	if (lstat(path, &st) != 0)
		return (-1);
	if (S_ISDIR(st.st_mode))
		*kind = SCAN_KIND_DIRECTORY;
	else if (S_ISLNK(st.st_mode))
		*kind = SCAN_KIND_SYMLINK;
	else if (S_ISREG(st.st_mode))
		*kind = SCAN_KIND_FILE;
	else
		return (-1);
	return (0);
}

/*
 * Print a one-tab section header; red on a TTY when the finding is flagged.
 */
static void
scan_print_flag_header(const char *label, int flagged)
{
	if (flagged && isatty(STDOUT_FILENO))
		printf("\t" ANSI_RED "%s" ANSI_RESET "\n", label);
	else
		printf("\t%s\n", label);
}

static void
scan_print_symlink_header(void)
{
	if (isatty(STDOUT_FILENO))
		printf("\t" ANSI_YELLOW "symlink" ANSI_RESET "\n");
	else
		printf("\tsymlink\n");
}

static void
scan_print_yellow_header(const char *label)
{
	if (isatty(STDOUT_FILENO))
		printf("\t" ANSI_YELLOW "%s" ANSI_RESET "\n", label);
	else
		printf("\t%s\n", label);
}

static int
scan_path_has_symlink_component(const char *path)
{
	char		buf[PATH_MAX];
	struct stat	st;
	size_t		i;
	size_t		j;

	if (path == NULL || path[0] == '\0')
		return (0);
	j = 0;
	buf[0] = '\0';
	if (path[0] == '/') {
		buf[0] = '/';
		buf[1] = '\0';
		j = 1;
	}
	i = (path[0] == '/') ? 1 : 0;
	while (path[i] != '\0') {
		while (path[i] == '/')
			i++;
		if (path[i] == '\0')
			break;
		if (j > 0 && buf[j - 1] != '/') {
			if (j + 1 >= sizeof(buf))
				return (0);
			buf[j++] = '/';
		}
		while (path[i] != '\0' && path[i] != '/') {
			if (j + 1 >= sizeof(buf))
				return (0);
			buf[j++] = path[i++];
		}
		buf[j] = '\0';
		if (lstat(buf, &st) == 0 && S_ISLNK(st.st_mode))
			return (1);
	}
	return (0);
}

static void
scan_print_path_lines(const char *path, int is_symlink)
{
	char	resolved[PATH_MAX];
	int	show_symlink;

	if (realpath(path, resolved) == NULL) {
		printf("%s\n", path);
		scan_print_resolved_path_line(path, "");
		return;
	}
	if (strcmp(path, resolved) == 0) {
		printf("%s\n", path);
		return;
	}
	show_symlink = is_symlink || scan_path_has_symlink_component(path);
	printf("%s\n", path);
	if (show_symlink)
		scan_print_symlink_header();
	printf("%s\n", resolved);
}

static void
scan_print_entitlement(const char *name)
{
	printf("\t\t%s\n", name);
}

static void
scan_print_inode(ino_t ino)
{
	if (isatty(STDOUT_FILENO))
		printf("\t" ANSI_YELLOW "inode" ANSI_RESET "\n");
	else
		printf("\tinode\n");
	printf("\t\t%llu\n", (unsigned long long)ino);
}

static char
scan_mode_type(mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFBLK:
		return ('b');
	case S_IFCHR:
		return ('c');
	case S_IFDIR:
		return ('d');
	case S_IFIFO:
		return ('p');
	case S_IFLNK:
		return ('l');
	case S_IFREG:
		return ('-');
	case S_IFSOCK:
		return ('s');
	default:
		return ('?');
	}
}

static void
scan_format_mode(mode_t mode, char *buf, size_t buflen)
{
	char		type;

	if (buflen < 11) {
		if (buflen > 0)
			buf[0] = '\0';
		return;
	}
	type = scan_mode_type(mode);
	snprintf(buf, buflen, "%c%c%c%c%c%c%c%c%c%c",
	    type,
	    (mode & S_IRUSR) ? 'r' : '-',
	    (mode & S_IWUSR) ? 'w' : '-',
	    (mode & S_IXUSR) ?
	    ((mode & S_ISUID) ? 's' : 'x') :
	    ((mode & S_ISUID) ? 'S' : '-'),
	    (mode & S_IRGRP) ? 'r' : '-',
	    (mode & S_IWGRP) ? 'w' : '-',
	    (mode & S_IXGRP) ?
	    ((mode & S_ISGID) ? 's' : 'x') :
	    ((mode & S_ISGID) ? 'S' : '-'),
	    (mode & S_IROTH) ? 'r' : '-',
	    (mode & S_IWOTH) ? 'w' : '-',
	    (mode & S_IXOTH) ?
	    ((mode & S_ISVTX) ? 't' : 'x') :
	    ((mode & S_ISVTX) ? 'T' : '-'));
}

static void
scan_format_owner(uid_t uid, char *buf, size_t len)
{
	struct passwd	*pw;

	pw = getpwuid(uid);
	if (pw != NULL && pw->pw_name != NULL) {
		strlcpy(buf, pw->pw_name, len);
		return;
	}
	snprintf(buf, len, "%lu", (unsigned long)uid);
}

static void
scan_format_group(gid_t gid, char *buf, size_t len)
{
	struct group	*gr;

	gr = getgrgid(gid);
	if (gr != NULL && gr->gr_name != NULL) {
		strlcpy(buf, gr->gr_name, len);
		return;
	}
	snprintf(buf, len, "%lu", (unsigned long)gid);
}

static int
scan_has_setid(const struct stat *st)
{
	return ((st->st_mode & S_ISUID) != 0 ||
	    (st->st_mode & S_ISGID) != 0);
}

static int
scan_has_world_writable(const struct stat *st)
{
	return ((st->st_mode & S_IWOTH) != 0);
}

static void
scan_print_setid_details(const struct stat *st)
{
	char		detail[256];
	char		group[64];
	char		modebuf[16];
	char		owner[64];
	int		has_sgid;
	int		has_suid;
	mode_t		perms;

	has_suid = (st->st_mode & S_ISUID) != 0;
	has_sgid = (st->st_mode & S_ISGID) != 0;
	if (!has_suid && !has_sgid)
		return;
	if (has_suid && has_sgid)
		scan_print_flag_header("setuid, setgid", 1);
	else if (has_suid)
		scan_print_flag_header("setuid", 1);
	else
		scan_print_flag_header("setgid", 1);
	scan_format_mode(st->st_mode, modebuf, sizeof(modebuf));
	perms = st->st_mode & 07777;
	scan_format_owner(st->st_uid, owner, sizeof(owner));
	scan_format_group(st->st_gid, group, sizeof(group));
	snprintf(detail, sizeof(detail), "%s %04lo %s:%s",
	    modebuf, (unsigned long)perms, owner, group);
	printf("\t\t%s\n", detail);
}

static int
scan_entitlements_findings(const char *path, int verbose, int load_flagged,
    plist_keys_t *keys_out)
{
	macho_entitlements_t	ent;
	int			has_dyld;
	int			has_lv;
	int			rc;

	memset(keys_out, 0, sizeof(*keys_out));
	if (!verbose) {
		macho_filetype_t	ftype;

		if (macho_filetype_of(path, &ftype) != 0 ||
		    ftype != MACHO_FILE_EXECUTE)
			return (0);
	}
	memset(&ent, 0, sizeof(ent));
	rc = macho_entitlements_for_path(path, &ent);
	if (rc < 0 || rc == 0 || ent.len == 0)
		return (0);
	if (plist_keys_from_xml((const char *)ent.data, ent.len, keys_out) != 0) {
		macho_entitlements_free(&ent);
		return (0);
	}
	has_dyld = plist_keys_has(keys_out, ENT_ALLOW_DYLD);
	has_lv = plist_keys_has(keys_out, ENT_DISABLE_LV);
	macho_entitlements_free(&ent);
	if (verbose)
		return (keys_out->count > 0);
	if (has_dyld && has_lv)
		return (1);
	if (load_flagged && keys_out->count > 0)
		return (1);
	plist_keys_free(keys_out);
	return (0);
}

typedef struct scan_macho_ctx {
	char	scanned_path[PATH_MAX];
	char	loader_dir[PATH_MAX];
	char	executable_dir[PATH_MAX];
} scan_macho_ctx_t;

static int
scan_dirname_last(char *path)
{
	char	*slash;

	slash = strrchr(path, '/');
	if (slash == NULL)
		return (-1);
	if (slash == path) {
		path[1] = '\0';
		return (0);
	}
	*slash = '\0';
	return (0);
}

typedef struct scan_writable_lib {
	char		resolved[PATH_MAX];
	struct stat	st;
} scan_writable_lib_t;

typedef struct scan_writable_libs {
	scan_writable_lib_t	*items;
	size_t			 count;
} scan_writable_libs_t;

static void
scan_writable_libs_free(scan_writable_libs_t *libs)
{
	if (libs == NULL)
		return;
	free(libs->items);
	memset(libs, 0, sizeof(*libs));
}

static int
scan_writable_libs_push(scan_writable_libs_t *libs, const char *resolved,
    const struct stat *st)
{
	scan_writable_lib_t	*grown;
	size_t			i;

	for (i = 0; i < libs->count; i++) {
		if (strcmp(libs->items[i].resolved, resolved) == 0)
			return (0);
	}
	grown = realloc(libs->items,
	    (libs->count + 1) * sizeof(*grown));
	if (grown == NULL)
		return (-1);
	libs->items = grown;
	libs->items[libs->count].st = *st;
	if (strlcpy(libs->items[libs->count].resolved, resolved,
	    sizeof(libs->items[libs->count].resolved)) >=
	    sizeof(libs->items[libs->count].resolved))
		return (-1);
	libs->count++;
	return (0);
}

static int
scan_lib_is_risky(const char *path, const struct stat *st)
{
	if (!S_ISREG(st->st_mode))
		return (0);
	if ((st->st_mode & S_IWOTH) != 0)
		return (1);
	if (access(path, W_OK) != 0)
		return (0);
	if ((st->st_mode & S_IWGRP) != 0)
		return (1);
	return (0);
}

static int
scan_bundle_macos_dir(const char *path, char *out, size_t outlen)
{
	const char	*last;
	const char	*marker;
	size_t		prefix;

	last = NULL;
	for (marker = path; (marker = strstr(marker, ".app/Contents/")) != NULL;
	    last = marker, marker++)
		;
	if (last == NULL)
		return (-1);
	prefix = (size_t)(last - path) + (size_t)4;
	if (snprintf(out, outlen, "%.*s/Contents/MacOS", (int)prefix,
	    path) >= (int)outlen)
		return (-1);
	return (0);
}

static int
scan_bundle_main_from_plist(const char *macos_dir, char *out, size_t outlen)
{
	char		contents[PATH_MAX];
	char		exec_name[PATH_MAX];
	char		*data;
	macho_filetype_t	ftype;
	size_t		len;
	ssize_t		nread;
	int		fd;

	if (snprintf(contents, sizeof(contents), "%s/../Info.plist",
	    macos_dir) >= (int)sizeof(contents))
		return (-1);
	scan_collapse_slashes(contents);
	fd = open(contents, O_RDONLY);
	if (fd < 0)
		return (-1);
	data = NULL;
	len = 0;
	for (;;) {
		char	*grown;

		grown = realloc(data, len + 4096);
		if (grown == NULL) {
			free(data);
			close(fd);
			return (-1);
		}
		data = grown;
		nread = read(fd, data + len, 4096);
		if (nread < 0) {
			free(data);
			close(fd);
			return (-1);
		}
		if (nread == 0)
			break;
		len += (size_t)nread;
	}
	close(fd);
	if (len == 0) {
		free(data);
		return (-1);
	}
	if (plist_string_for_key(data, len, "CFBundleExecutable", exec_name,
	    sizeof(exec_name)) != 0) {
		free(data);
		return (-1);
	}
	free(data);
	if (snprintf(out, outlen, "%s/%s", macos_dir, exec_name) >= (int)outlen)
		return (-1);
	if (macho_filetype_of(out, &ftype) != 0 || ftype != MACHO_FILE_EXECUTE)
		return (-1);
	return (0);
}

static int
scan_bundle_main_from_macos(const char *macos_dir, char *out, size_t outlen)
{
	DIR		*dir;
	macho_filetype_t	ftype;
	struct dirent	*entry;
	char		candidate[PATH_MAX];
	int		count;

	dir = opendir(macos_dir);
	if (dir == NULL)
		return (-1);
	count = 0;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;
		if (snprintf(candidate, sizeof(candidate), "%s/%s", macos_dir,
		    entry->d_name) >= (int)sizeof(candidate))
			continue;
		if (macho_filetype_of(candidate, &ftype) != 0 ||
		    ftype != MACHO_FILE_EXECUTE)
			continue;
		if (strlcpy(out, candidate, outlen) >= outlen) {
			closedir(dir);
			return (-1);
		}
		count++;
		if (count > 1) {
			closedir(dir);
			return (-1);
		}
	}
	closedir(dir);
	return (count == 1 ? 0 : -1);
}

static int
scan_bundle_main_executable(const char *path, char *out, size_t outlen)
{
	char	macos_dir[PATH_MAX];

	if (scan_bundle_macos_dir(path, macos_dir, sizeof(macos_dir)) != 0)
		return (-1);
	if (scan_bundle_main_from_plist(macos_dir, out, outlen) == 0)
		return (0);
	return (scan_bundle_main_from_macos(macos_dir, out, outlen));
}

static void
scan_macho_ctx_fill(const char *path, scan_macho_ctx_t *ctx)
{
	char		dirpath[PATH_MAX];
	char		exe_path[PATH_MAX];
	char		*dir;
	macho_filetype_t	ftype;

	memset(ctx, 0, sizeof(*ctx));
	strlcpy(ctx->scanned_path, path, sizeof(ctx->scanned_path));
	strlcpy(dirpath, path, sizeof(dirpath));
	dir = dirname(dirpath);
	strlcpy(ctx->loader_dir, dir, sizeof(ctx->loader_dir));
	if (macho_filetype_of(path, &ftype) == 0 &&
	    ftype == MACHO_FILE_EXECUTE) {
		strlcpy(ctx->executable_dir, ctx->loader_dir,
		    sizeof(ctx->executable_dir));
		return;
	}
	if (scan_bundle_main_executable(path, exe_path, sizeof(exe_path)) == 0) {
		strlcpy(dirpath, exe_path, sizeof(dirpath));
		dir = dirname(dirpath);
		strlcpy(ctx->executable_dir, dir, sizeof(ctx->executable_dir));
		return;
	}
	strlcpy(ctx->executable_dir, ctx->loader_dir,
	    sizeof(ctx->executable_dir));
}

static int
scan_rpath_resolve(const char *rpath, const scan_macho_ctx_t *ctx, char *out,
    size_t outlen)
{
	const char	*base;
	const char	*suffix;

	if (strncmp(rpath, "@executable_path", 16) == 0) {
		base = ctx->executable_dir;
		suffix = rpath + 16;
	} else if (strncmp(rpath, "@loader_path", 12) == 0) {
		base = ctx->loader_dir;
		suffix = rpath + 12;
	} else if (rpath[0] == '/') {
		return (strlcpy(out, rpath, outlen) < outlen ? 0 : -1);
	} else
		return (-1);
	if (*suffix == '\0')
		suffix = "";
	if (snprintf(out, outlen, "%s%s", base, suffix) >= (int)outlen)
		return (-1);
	scan_collapse_slashes(out);
	return (0);
}

static int
scan_lib_resolve(const char *name, const scan_macho_ctx_t *ctx,
    const macho_rpath_info_t *rpath_info, char *out, size_t outlen)
{
	char		base[PATH_MAX];
	char		rest[PATH_MAX];
	struct stat	st;
	size_t		i;

	if (strncmp(name, "@rpath/", 7) == 0) {
		if (rpath_info == NULL)
			return (-1);
		if (strlcpy(rest, name + 7, sizeof(rest)) >= sizeof(rest))
			return (-1);
		for (i = 0; i < rpath_info->rpaths.count; i++) {
			if (scan_rpath_resolve(rpath_info->rpaths.items[i], ctx,
			    base, sizeof(base)) != 0)
				continue;
			if (snprintf(out, outlen, "%s/%s", base, rest) >=
			    (int)outlen)
				continue;
			scan_collapse_slashes(out);
			if (stat(out, &st) == 0 && S_ISREG(st.st_mode))
				return (0);
		}
		return (-1);
	}
	if (scan_rpath_resolve(name, ctx, out, outlen) != 0)
		return (-1);
	if (stat(out, &st) != 0 || !S_ISREG(st.st_mode))
		return (-1);
	return (0);
}

static int
scan_lib_findings(const char *path, int verbose, const scan_macho_ctx_t *ctx,
    const macho_rpath_info_t *load_info, scan_writable_libs_t *out,
    int *flagged)
{
	macho_filetype_t	ftype;
	macho_strlist_t		libs;
	char			resolved[PATH_MAX];
	struct stat		st;
	size_t			i;

	memset(out, 0, sizeof(*out));
	*flagged = 0;
	if (!verbose) {
		if (macho_filetype_of(path, &ftype) != 0 ||
		    ftype != MACHO_FILE_EXECUTE)
			return (0);
	}
	memset(&libs, 0, sizeof(libs));
	if (macho_libs_for_path(path, &libs) <= 0) {
		macho_libs_free(&libs);
		return (0);
	}
	for (i = 0; i < libs.count; i++) {
		if (scan_lib_resolve(libs.items[i], ctx, load_info, resolved,
		    sizeof(resolved)) != 0)
			continue;
		if (stat(resolved, &st) != 0 || !S_ISREG(st.st_mode))
			continue;
		if (!scan_lib_is_risky(resolved, &st))
			continue;
		if (scan_writable_libs_push(out, resolved, &st) != 0) {
			macho_libs_free(&libs);
			scan_writable_libs_free(out);
			return (-1);
		}
	}
	macho_libs_free(&libs);
	if (out->count == 0)
		return (0);
	*flagged = 1;
	return (1);
}

static int
scan_rpath_dir_risky(const char *rpath)
{
	struct stat	st;
	char		path[PATH_MAX];

	strlcpy(path, rpath, sizeof(path));
	for (;;) {
		if (stat(path, &st) == 0) {
			if (!S_ISDIR(st.st_mode))
				return (0);
			return ((st.st_mode & S_IWOTH) != 0);
		}
		if (errno != ENOENT)
			return (0);
		if (scan_dirname_last(path) != 0)
			return (0);
	}
}

static int
scan_rpath_has_risky(const scan_macho_ctx_t *ctx,
    const macho_rpath_info_t *info)
{
	char	resolved[PATH_MAX];
	size_t	i;

	for (i = 0; i < info->rpaths.count; i++) {
		if (scan_rpath_resolve(info->rpaths.items[i], ctx, resolved,
		    sizeof(resolved)) != 0)
			continue;
		if (scan_rpath_dir_risky(resolved))
			return (1);
	}
	return (0);
}

static int
scan_has_entitlement(const char *path, const char *key)
{
	macho_entitlements_t	ent;
	plist_keys_t		keys;
	int			has;
	int			rc;

	memset(&keys, 0, sizeof(keys));
	memset(&ent, 0, sizeof(ent));
	rc = macho_entitlements_for_path(path, &ent);
	if (rc < 0 || rc == 0 || ent.len == 0)
		return (0);
	if (plist_keys_from_xml((const char *)ent.data, ent.len, &keys) != 0) {
		macho_entitlements_free(&ent);
		return (0);
	}
	has = plist_keys_has(&keys, key);
	plist_keys_free(&keys);
	macho_entitlements_free(&ent);
	return (has);
}

static int
scan_load_findings(const char *path, int verbose, const scan_macho_ctx_t *ctx,
    macho_rpath_info_t *info, int *rpath_findings, int *rpath_flagged,
    int *relpath_findings, int *relpath_flagged)
{
	macho_filetype_t	ftype;
	int			has_lv;
	int			has_risky;
	int			is_execute;

	memset(info, 0, sizeof(*info));
	*rpath_findings = 0;
	*rpath_flagged = 0;
	*relpath_findings = 0;
	*relpath_flagged = 0;
	is_execute = 1;
	if (!verbose) {
		if (macho_filetype_of(path, &ftype) != 0 ||
		    ftype != MACHO_FILE_EXECUTE)
			is_execute = 0;
	}
	if (macho_rpath_info_for_path(path, info) <= 0)
		return (0);
	has_risky = scan_rpath_has_risky(ctx, info);
	has_lv = scan_has_entitlement(path, ENT_DISABLE_LV);
	if (verbose) {
		if (info->rpaths.count > 0 || info->deps.count > 0) {
			*rpath_findings = 1;
			*rpath_flagged = (info->deps.count > 0 && has_risky);
		}
	} else if (is_execute && info->deps.count > 0 && has_risky && has_lv) {
		*rpath_findings = 1;
		*rpath_flagged = 1;
	}
	if (info->relpaths.count > 0) {
		if (verbose) {
			*relpath_findings = 1;
			*relpath_flagged = has_lv;
		} else if (is_execute && has_lv) {
			*relpath_findings = 1;
			*relpath_flagged = 1;
		}
	}
	if (*rpath_findings || *relpath_findings)
		return (1);
	macho_rpath_info_free(info);
	return (0);
}

static void
scan_print_entitlements_list(const plist_keys_t *keys, int flagged)
{
	size_t	i;

	if (keys->count == 0)
		return;
	scan_print_flag_header("entitlements", flagged);
	for (i = 0; i < keys->count; i++)
		scan_print_entitlement(keys->keys[i]);
}

static void
scan_print_mode_detail(const struct stat *st)
{
	char		detail[256];
	char		group[64];
	char		modebuf[16];
	char		owner[64];
	mode_t		perms;

	scan_format_mode(st->st_mode, modebuf, sizeof(modebuf));
	perms = st->st_mode & 07777;
	scan_format_owner(st->st_uid, owner, sizeof(owner));
	scan_format_group(st->st_gid, group, sizeof(group));
	snprintf(detail, sizeof(detail), "%s %04lo %s:%s",
	    modebuf, (unsigned long)perms, owner, group);
	printf("\t\t%s\n", detail);
}

static void
scan_print_world_writable(const struct stat *st)
{
	scan_print_flag_header("writable-by-others", 1);
	scan_print_mode_detail(st);
}

static void
scan_print_writable_lib(const char *path, const struct stat *st)
{
	char	display[PATH_MAX];
	const char	*shown;

	if (realpath(path, display) != NULL)
		shown = display;
	else
		shown = path;
	printf("\t\t%s\n", shown);
	scan_print_resolved_path_line(shown, "\t\t");
	scan_print_mode_detail(st);
}

static void
scan_print_writable_libs_list(const scan_writable_libs_t *libs, int flagged)
{
	size_t	i;

	if (libs->count == 0)
		return;
	scan_print_flag_header("writable-libraries", flagged);
	for (i = 0; i < libs->count; i++)
		scan_print_writable_lib(libs->items[i].resolved,
		    &libs->items[i].st);
}

static void
scan_print_dir_section(const struct stat *st, int verbose)
{
	int	finding;
	int	sticky;
	int	world_writable;

	world_writable = scan_has_world_writable(st);
	sticky = (st->st_mode & S_ISVTX) != 0;
	finding = world_writable && !sticky;
	if (verbose) {
		if (finding) {
			scan_print_flag_header("writable-by-others, sticky bit", 1);
			scan_print_mode_detail(st);
		} else {
			scan_print_flag_header("directory permissions", 0);
			scan_print_mode_detail(st);
		}
		return;
	}
	if (world_writable) {
		scan_print_flag_header("writable-by-others, sticky bit", 1);
		scan_print_mode_detail(st);
	}
}

static int
scan_root_has_finding(const char *path, int verbose)
{
	struct stat	lst;
	struct stat	st;

	if (verbose)
		return (1);
	if (lstat(path, &lst) == 0 && S_ISLNK(lst.st_mode))
		return (1);
	if (stat(path, &st) != 0)
		return (0);
	if (!S_ISDIR(st.st_mode))
		return (0);
	return (scan_has_world_writable(&st));
}

static int
scan_root_wants_inode(int verbose, int is_symlink, const struct stat *st)
{
	int	sticky;
	int	world_writable;

	if (!verbose)
		return (1);
	if (is_symlink)
		return (1);
	if (st == NULL || !S_ISDIR(st->st_mode))
		return (0);
	world_writable = scan_has_world_writable(st);
	sticky = (st->st_mode & S_ISVTX) != 0;
	return (world_writable && !sticky);
}

/*
 * Report the scan root when it has findings: symlink target or directory
 * permission issues (default), or always in verbose mode.
 */
static int
scan_print_root(const char *path, int verbose)
{
	struct stat	lst;
	struct stat	st;
	int		is_symlink;

	if (!scan_root_has_finding(path, verbose))
		return (0);
	if (lstat(path, &lst) != 0)
		return (1);
	is_symlink = S_ISLNK(lst.st_mode);
	scan_print_path_lines(path, is_symlink);
	if (stat(path, &st) != 0)
		return (1);
	if (scan_root_wants_inode(verbose, is_symlink,
	    S_ISDIR(st.st_mode) ? &st : NULL))
		scan_print_inode(lst.st_ino);
	if (!S_ISDIR(st.st_mode))
		return (1);
	scan_print_dir_section(&st, verbose);
	return (1);
}

static int
scan_symlink_resolve(const char *path, char *out, size_t outlen)
{
	char		buf[PATH_MAX];
	char		link[PATH_MAX];
	char		*dir;
	ssize_t		n;

	n = readlink(path, link, sizeof(link) - 1);
	if (n < 0)
		return (-1);
	link[n] = '\0';
	if (link[0] == '/')
		return (strlcpy(out, link, outlen) < outlen ? 0 : -1);
	strlcpy(buf, path, sizeof(buf));
	dir = dirname(buf);
	if (snprintf(out, outlen, "%s/%s", dir, link) >= (int)outlen)
		return (-1);
	scan_collapse_slashes(out);
	return (0);
}

static int
scan_creatable_parent(const char *target, char *parent, size_t parentlen,
    struct stat *st)
{
	char	path[PATH_MAX];

	strlcpy(path, target, sizeof(path));
	for (;;) {
		if (access(path, F_OK) == 0) {
			if (access(path, W_OK) != 0)
				return (-1);
			if (stat(path, st) != 0)
				return (-1);
			return (strlcpy(parent, path, parentlen) < parentlen ?
			    0 : -1);
		}
		if (errno != ENOENT)
			return (-1);
		if (scan_dirname_last(path) != 0)
			return (-1);
	}
}

static int
scan_user_can_create_at(const char *target)
{
	struct stat	st;
	char		parent[PATH_MAX];

	return (scan_creatable_parent(target, parent, sizeof(parent), &st) ==
	    0);
}

static void
scan_print_missing_target(const char *target)
{
	scan_print_yellow_header("missing");
	printf("\t\t%s\n", target);
	scan_print_resolved_path_line(target, "\t\t");
}

static void
scan_print_creatable_parent_detail(const char *parent, const struct stat *st)
{
	char		detail[PATH_MAX + 64];
	char		group[64];
	char		modebuf[16];
	char		owner[64];
	char		resolved[PATH_MAX];
	const char	*detail_path;
	mode_t		perms;

	scan_format_mode(st->st_mode, modebuf, sizeof(modebuf));
	perms = st->st_mode & 07777;
	scan_format_owner(st->st_uid, owner, sizeof(owner));
	scan_format_group(st->st_gid, group, sizeof(group));
	detail_path = parent;
	if (scan_path_needs_resolve(parent) &&
	    scan_path_display_resolve(parent, resolved, sizeof(resolved)) == 0 &&
	    strcmp(parent, resolved) != 0) {
		printf("\t\t%s\n", parent);
		detail_path = resolved;
	}
	snprintf(detail, sizeof(detail), "%s %s %04lo %s:%s",
	    detail_path, modebuf, (unsigned long)perms, owner, group);
	printf("\t\t%s\n", detail);
}

static void
scan_print_creatable_target(const char *target)
{
	struct stat	st;
	char		parent[PATH_MAX];

	scan_print_flag_header("creatable", 1);
	printf("\t\t%s\n", target);
	scan_print_resolved_path_line(target, "\t\t");
	if (scan_creatable_parent(target, parent, sizeof(parent), &st) != 0)
		return;
	scan_print_creatable_parent_detail(parent, &st);
}

static int
scan_rpath_entry_risky(const char *rpath, const scan_macho_ctx_t *ctx,
    char *resolved, size_t reslen)
{
	if (scan_rpath_resolve(rpath, ctx, resolved, reslen) != 0)
		return (0);
	return (scan_rpath_dir_risky(resolved));
}

static void
scan_print_libs_list(const macho_strlist_t *libs)
{
	size_t	i;

	if (libs->count == 0)
		return;
	scan_print_flag_header("libraries", 0);
	for (i = 0; i < libs->count; i++)
		printf("\t\t%s\n", libs->items[i]);
}

static void
scan_print_verbose_file_meta(const char *path)
{
	macho_kind_t		mkind;
	macho_strlist_t		libs;

	if (macho_kind_of(path, &mkind) != 0)
		mkind = MACHO_KIND_NONE;
	if (mkind != MACHO_KIND_NONE) {
		memset(&libs, 0, sizeof(libs));
		if (macho_libs_for_path(path, &libs) > 0)
			scan_print_libs_list(&libs);
		macho_libs_free(&libs);
	}
	printf("\tKIND: file\n");
	if (mkind == MACHO_KIND_NONE)
		printf("\tMACHO: no\n");
	else
		printf("\tMACHO: yes\n");
}

static void
scan_print_relpath_list(const macho_rpath_info_t *info, int flagged)
{
	size_t	i;

	if (info->relpaths.count == 0)
		return;
	scan_print_flag_header("relative-path", flagged);
	for (i = 0; i < info->relpaths.count; i++)
		printf("\t\t%s\n", info->relpaths.items[i]);
}

static void
scan_print_rpath_list(const macho_rpath_info_t *info,
    const scan_macho_ctx_t *ctx, int verbose, int flagged)
{
	struct stat	st;
	char		resolved[PATH_MAX];
	size_t		i;
	int		shown;

	shown = 0;
	for (i = 0; i < info->rpaths.count; i++) {
		if (!verbose &&
		    !scan_rpath_entry_risky(info->rpaths.items[i], ctx,
		    resolved, sizeof(resolved)))
			continue;
		if (!shown) {
			scan_print_flag_header("rpath", flagged);
			shown = 1;
		}
		printf("\t\t%s\n", info->rpaths.items[i]);
	}
	for (i = 0; i < info->deps.count; i++) {
		if (!shown) {
			scan_print_flag_header("rpath", flagged);
			shown = 1;
		}
		printf("\t\t%s\n", info->deps.items[i]);
	}
	if (!shown)
		return;
	for (i = 0; i < info->rpaths.count; i++) {
		if (!verbose &&
		    !scan_rpath_entry_risky(info->rpaths.items[i], ctx,
		    resolved, sizeof(resolved)))
			continue;
		if (scan_rpath_resolve(info->rpaths.items[i], ctx, resolved,
		    sizeof(resolved)) != 0)
			continue;
		if (stat(resolved, &st) == 0 && S_ISDIR(st.st_mode))
			continue;
		scan_print_missing_target(resolved);
		if (scan_user_can_create_at(resolved))
			scan_print_creatable_target(resolved);
	}
}

static void
scan_print_symlink_lines(const char *path, const char *target)
{
	char	display[PATH_MAX];
	const char	*shown;

	printf("%s\n", path);
	scan_print_symlink_header();
	if (realpath(target, display) != NULL)
		shown = display;
	else
		shown = target;
	printf("%s\n", shown);
	scan_print_resolved_path_line(shown, "");
}

static int
scan_file_findings(const char *path, int verbose, const struct stat *st)
{
	macho_rpath_info_t	load_info;
	plist_keys_t		keys;
	scan_macho_ctx_t	mctx;
	scan_writable_libs_t	writable_libs;
	int			ent_flagged;
	int			ent_findings;
	int			has_findings;
	int			has_setid;
	int			lib_findings;
	int			lib_flagged;
	int			load_flagged;
	int			relpath_findings;
	int			relpath_flagged;
	int			rpath_findings;
	int			rpath_flagged;
	int			world_writable;

	has_findings = 0;
	has_setid = scan_has_setid(st);
	world_writable = scan_has_world_writable(st);
	scan_macho_ctx_fill(path, &mctx);
	scan_load_findings(path, verbose, &mctx, &load_info, &rpath_findings,
	    &rpath_flagged, &relpath_findings, &relpath_flagged);
	lib_findings = scan_lib_findings(path, verbose, &mctx, &load_info,
	    &writable_libs, &lib_flagged);
	load_flagged = rpath_flagged || relpath_flagged || lib_flagged;
	ent_findings = scan_entitlements_findings(path, verbose, load_flagged,
	    &keys);
	if (verbose || load_flagged)
		ent_flagged = plist_keys_has(&keys, ENT_ALLOW_DYLD) ||
		    plist_keys_has(&keys, ENT_DISABLE_LV);
	else
		ent_flagged = plist_keys_has(&keys, ENT_ALLOW_DYLD) &&
		    plist_keys_has(&keys, ENT_DISABLE_LV);
	if (has_setid)
		has_findings = 1;
	if (world_writable)
		has_findings = 1;
	if (ent_findings)
		has_findings = 1;
	if (rpath_findings)
		has_findings = 1;
	if (relpath_findings)
		has_findings = 1;
	if (lib_findings)
		has_findings = 1;
	if (!has_findings) {
		plist_keys_free(&keys);
		macho_rpath_info_free(&load_info);
		scan_writable_libs_free(&writable_libs);
		if (!verbose)
			return (0);
		scan_print_verbose_file_meta(path);
		return (1);
	}
	scan_print_setid_details(st);
	if (world_writable)
		scan_print_world_writable(st);
	if (ent_findings)
		scan_print_entitlements_list(&keys, ent_flagged);
	if (rpath_findings)
		scan_print_rpath_list(&load_info, &mctx, verbose, rpath_flagged);
	if (relpath_findings)
		scan_print_relpath_list(&load_info, relpath_flagged);
	if (lib_findings)
		scan_print_writable_libs_list(&writable_libs, lib_flagged);
	plist_keys_free(&keys);
	macho_rpath_info_free(&load_info);
	scan_writable_libs_free(&writable_libs);
	if (verbose)
		scan_print_verbose_file_meta(path);
	return (1);
}

static int
scan_symlink(const char *path, int verbose, int is_root)
{
	struct stat	lst;
	struct stat	tst;
	char		target[PATH_MAX];
	int		creatable;
	int		missing;

	if (lstat(path, &lst) != 0 || !S_ISLNK(lst.st_mode))
		return (0);
	if (scan_symlink_resolve(path, target, sizeof(target)) != 0)
		return (0);
	missing = (stat(target, &tst) != 0);
	if (!missing) {
		if (S_ISDIR(tst.st_mode) && is_root)
			return (scan_print_root(path, verbose));
		if (S_ISREG(tst.st_mode) && is_root) {
			scan_print_symlink_lines(path, target);
			scan_print_inode(lst.st_ino);
			scan_file_findings(path, verbose, &tst);
			if (verbose)
				printf("\tKIND: symlink\n");
			return (1);
		}
		if (S_ISREG(tst.st_mode))
			return (scan_file(path, verbose));
		return (0);
	}
	creatable = scan_user_can_create_at(target);
	if (!verbose && !creatable)
		return (0);
	scan_print_symlink_lines(path, target);
	scan_print_inode(lst.st_ino);
	scan_print_missing_target(target);
	if (creatable)
		scan_print_creatable_target(target);
	if (verbose)
		printf("\tKIND: symlink\n");
	return (1);
}

static int
scan_stat_file(const char *path, struct stat *st)
{
	if (lstat(path, st) != 0)
		return (-1);
	if (S_ISLNK(st->st_mode)) {
		if (stat(path, st) != 0)
			return (-1);
	}
	if (!S_ISREG(st->st_mode))
		return (-1);
	return (0);
}

static int
scan_file(const char *path, int verbose)
{
	macho_rpath_info_t	load_info;
	plist_keys_t		keys;
	scan_macho_ctx_t	mctx;
	scan_writable_libs_t	writable_libs;
	struct stat		lst;
	struct stat		st;
	int			ent_findings;
	int			has_findings;
	int			has_setid;
	int			is_symlink;
	int			lib_findings;
	int			lib_flagged;
	int			load_flagged;
	int			relpath_findings;
	int			relpath_flagged;
	int			rpath_findings;
	int			rpath_flagged;
	int			world_writable;

	is_symlink = 0;
	if (lstat(path, &lst) == 0 && S_ISLNK(lst.st_mode))
		is_symlink = 1;
	if (scan_stat_file(path, &st) != 0)
		return (0);
	has_setid = scan_has_setid(&st);
	world_writable = scan_has_world_writable(&st);
	scan_macho_ctx_fill(path, &mctx);
	scan_load_findings(path, verbose, &mctx, &load_info, &rpath_findings,
	    &rpath_flagged, &relpath_findings, &relpath_flagged);
	lib_findings = scan_lib_findings(path, verbose, &mctx, &load_info,
	    &writable_libs, &lib_flagged);
	load_flagged = rpath_flagged || relpath_flagged || lib_flagged;
	ent_findings = scan_entitlements_findings(path, verbose, load_flagged,
	    &keys);
	plist_keys_free(&keys);
	macho_rpath_info_free(&load_info);
	scan_writable_libs_free(&writable_libs);
	has_findings = verbose || has_setid || world_writable || ent_findings ||
	    rpath_findings || relpath_findings || lib_findings;
	if (!has_findings)
		return (0);
	scan_print_path_lines(path, is_symlink);
	scan_print_inode(st.st_ino);
	scan_file_findings(path, verbose, &st);
	return (1);
}

static int
scan_object(const char *path, int verbose, int is_root)
{
	scan_kind_t	kind;

	if (scan_classify_path(path, &kind) != 0)
		return (0);
	if (is_root && kind == SCAN_KIND_DIRECTORY)
		return (scan_print_root(path, verbose));
	if (kind == SCAN_KIND_DIRECTORY)
		return (0);
	if (kind == SCAN_KIND_SYMLINK)
		return (scan_symlink(path, verbose, is_root));
	return (scan_file(path, verbose));
}

/*
 * Scan one path or every object under a directory tree.
 */
int
scan_target(const char *path, int verbose)
{
	char	*orig;
	char	*resolved;
	int	rc;

	orig = scan_normalize_dup(path);
	if (orig == NULL)
		return (-1);
	resolved = scan_resolve_dup(path);
	if (resolved == NULL) {
		free(orig);
		return (-1);
	}
	rc = scan_walk(resolved, verbose, 1, orig);
	free(resolved);
	free(orig);
	return (rc);
}
