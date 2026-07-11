/*
 * scan.c - Path classification, recursive enumeration, and scan reporting.
 */

#include "scan.h"

#include "macho.h"
#include "plist.h"

#include <dirent.h>
#include <errno.h>
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
	if (stat(path, &st) != 0)
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
	struct group	*gr;
	struct passwd	*pw;
	char		detail[256];
	char		modebuf[16];
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
	pw = getpwuid(st->st_uid);
	gr = getgrgid(st->st_gid);
	snprintf(detail, sizeof(detail), "%s %04lo %s:%s",
	    modebuf, (unsigned long)perms,
	    pw != NULL ? pw->pw_name : "?",
	    gr != NULL ? gr->gr_name : "?");
	printf("\t\t%s\n", detail);
}

static int
scan_entitlements_findings(const char *path, int verbose, int rpath_flagged,
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
	if (rpath_flagged && keys_out->count > 0)
		return (1);
	plist_keys_free(keys_out);
	return (0);
}

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

static int
scan_rpath_resolve(const char *rpath, const char *macho_path, char *out,
    size_t outlen)
{
	char		dirpath[PATH_MAX];
	char		*dir;
	const char	*suffix;

	if (strncmp(rpath, "@executable_path", 16) == 0)
		suffix = rpath + 16;
	else if (strncmp(rpath, "@loader_path", 12) == 0)
		suffix = rpath + 12;
	else if (rpath[0] == '/')
		return (strlcpy(out, rpath, outlen) < outlen ? 0 : -1);
	else
		return (-1);
	if (*suffix == '\0')
		suffix = "";
	strlcpy(dirpath, macho_path, sizeof(dirpath));
	dir = dirname(dirpath);
	if (snprintf(out, outlen, "%s%s", dir, suffix) >= (int)outlen)
		return (-1);
	scan_collapse_slashes(out);
	return (0);
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
scan_rpath_has_risky(const char *macho_path, const macho_rpath_info_t *info)
{
	char	resolved[PATH_MAX];
	size_t	i;

	for (i = 0; i < info->rpaths.count; i++) {
		if (scan_rpath_resolve(info->rpaths.items[i], macho_path,
		    resolved, sizeof(resolved)) != 0)
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
scan_rpath_findings(const char *path, int verbose, macho_rpath_info_t *info,
    int *flagged)
{
	macho_filetype_t	ftype;
	int			has_risky;

	memset(info, 0, sizeof(*info));
	*flagged = 0;
	if (!verbose) {
		if (macho_filetype_of(path, &ftype) != 0 ||
		    ftype != MACHO_FILE_EXECUTE)
			return (0);
	}
	if (macho_rpath_info_for_path(path, info) <= 0)
		return (0);
	if (info->deps.count == 0) {
		if (!verbose || info->rpaths.count == 0) {
			macho_rpath_info_free(info);
			return (0);
		}
	}
	has_risky = scan_rpath_has_risky(path, info);
	if (verbose) {
		*flagged = (info->deps.count > 0 && has_risky);
		return (info->rpaths.count > 0 || info->deps.count > 0);
	}
	if (info->deps.count == 0 || !has_risky) {
		macho_rpath_info_free(info);
		return (0);
	}
	if (!scan_has_entitlement(path, ENT_DISABLE_LV)) {
		macho_rpath_info_free(info);
		return (0);
	}
	*flagged = 1;
	return (1);
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
	struct group	*gr;
	struct passwd	*pw;
	char		detail[256];
	char		modebuf[16];
	mode_t		perms;

	scan_format_mode(st->st_mode, modebuf, sizeof(modebuf));
	perms = st->st_mode & 07777;
	pw = getpwuid(st->st_uid);
	gr = getgrgid(st->st_gid);
	snprintf(detail, sizeof(detail), "%s %04lo %s:%s",
	    modebuf, (unsigned long)perms,
	    pw != NULL ? pw->pw_name : "?",
	    gr != NULL ? gr->gr_name : "?");
	printf("\t\t%s\n", detail);
}

static void
scan_print_world_writable(const struct stat *st)
{
	scan_print_flag_header("writable-by-others", 1);
	scan_print_mode_detail(st);
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
				return (0);
			if (stat(path, st) != 0)
				return (0);
			return (strlcpy(parent, path, parentlen) < parentlen ?
			    0 : -1);
		}
		if (errno != ENOENT)
			return (0);
		if (scan_dirname_last(path) != 0)
			return (0);
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
	struct group	*gr;
	struct passwd	*pw;
	char		detail[PATH_MAX + 64];
	char		modebuf[16];
	char		resolved[PATH_MAX];
	const char	*detail_path;
	mode_t		perms;

	scan_format_mode(st->st_mode, modebuf, sizeof(modebuf));
	perms = st->st_mode & 07777;
	pw = getpwuid(st->st_uid);
	gr = getgrgid(st->st_gid);
	detail_path = parent;
	if (scan_path_needs_resolve(parent) &&
	    scan_path_display_resolve(parent, resolved, sizeof(resolved)) == 0 &&
	    strcmp(parent, resolved) != 0) {
		printf("\t\t%s\n", parent);
		detail_path = resolved;
	}
	snprintf(detail, sizeof(detail), "%s %s %04lo %s:%s",
	    detail_path, modebuf, (unsigned long)perms,
	    pw != NULL ? pw->pw_name : "?",
	    gr != NULL ? gr->gr_name : "?");
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
scan_rpath_entry_risky(const char *rpath, const char *macho_path,
    char *resolved, size_t reslen)
{
	if (scan_rpath_resolve(rpath, macho_path, resolved, reslen) != 0)
		return (0);
	return (scan_rpath_dir_risky(resolved));
}

static void
scan_print_rpath_list(const macho_rpath_info_t *info, const char *macho_path,
    int verbose, int flagged)
{
	struct stat	st;
	char		resolved[PATH_MAX];
	size_t		i;
	int		shown;

	shown = 0;
	for (i = 0; i < info->rpaths.count; i++) {
		if (!verbose &&
		    !scan_rpath_entry_risky(info->rpaths.items[i], macho_path,
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
		    !scan_rpath_entry_risky(info->rpaths.items[i], macho_path,
		    resolved, sizeof(resolved)))
			continue;
		if (scan_rpath_resolve(info->rpaths.items[i], macho_path,
		    resolved, sizeof(resolved)) != 0)
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
	macho_kind_t		mkind;
	macho_rpath_info_t	rpath_info;
	plist_keys_t		keys;
	int			ent_flagged;
	int			ent_findings;
	int			has_findings;
	int			has_setid;
	int			rpath_findings;
	int			rpath_flagged;
	int			world_writable;

	has_findings = 0;
	has_setid = scan_has_setid(st);
	world_writable = scan_has_world_writable(st);
	rpath_findings = scan_rpath_findings(path, verbose, &rpath_info,
	    &rpath_flagged);
	ent_findings = scan_entitlements_findings(path, verbose, rpath_flagged,
	    &keys);
	if (verbose || rpath_flagged)
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
	if (!has_findings) {
		plist_keys_free(&keys);
		macho_rpath_info_free(&rpath_info);
		if (!verbose)
			return (0);
		if (macho_kind_of(path, &mkind) != 0)
			mkind = MACHO_KIND_NONE;
		printf("\tKIND: file\n");
		if (mkind == MACHO_KIND_NONE)
			printf("\tMACHO: no\n");
		else
			printf("\tMACHO: yes\n");
		return (1);
	}
	scan_print_setid_details(st);
	if (world_writable)
		scan_print_world_writable(st);
	if (ent_findings)
		scan_print_entitlements_list(&keys, ent_flagged);
	if (rpath_findings)
		scan_print_rpath_list(&rpath_info, path, verbose, rpath_flagged);
	plist_keys_free(&keys);
	macho_rpath_info_free(&rpath_info);
	if (verbose) {
		if (macho_kind_of(path, &mkind) != 0)
			mkind = MACHO_KIND_NONE;
		printf("\tKIND: file\n");
		if (mkind == MACHO_KIND_NONE)
			printf("\tMACHO: no\n");
		else
			printf("\tMACHO: yes\n");
	}
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
	macho_rpath_info_t	rpath_info;
	plist_keys_t		keys;
	struct stat		lst;
	struct stat		st;
	int			ent_findings;
	int			has_findings;
	int			has_setid;
	int			is_symlink;
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
	rpath_findings = scan_rpath_findings(path, verbose, &rpath_info,
	    &rpath_flagged);
	ent_findings = scan_entitlements_findings(path, verbose, rpath_flagged,
	    &keys);
	plist_keys_free(&keys);
	macho_rpath_info_free(&rpath_info);
	has_findings = verbose || has_setid || world_writable || ent_findings ||
	    rpath_findings;
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
