// SPDX-License-Identifier: GPL-2.0
/*
 * Per-UID path privacy filter shared by the pathname-based syscalls.
 *
 * The C library applies an identical decision to the named entry points and to
 * its generic syscall() multiplexer, but a caller that emits an inline syscall
 * reaches the kernel without passing through any of that. This mirror runs the
 * same rules at the VFS boundary so the outcome no longer depends on how the
 * request was made.
 *
 * The filter is intentionally conservative: it only ever hides a small, fixed
 * set of environment-specific nodes from ordinary application processes, and
 * fails open on any unexpected input.
 */

#include <linux/hidden_paths.h>

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>

/* First application UID (AID_APP_START). Below this are OS/system processes. */
#define FIRST_APP_UID 10000

/*
 * True when @segment appears in @path as a complete '/'-delimited component, so
 * "su" matches "/sbin/su" but not "/sys/.../subsystem_vendor" -- a plain
 * substring test there would hide a node libdrm needs to enumerate the GPU.
 */
static bool path_has_segment(const char *path, const char *segment)
{
	size_t n = strlen(segment);
	const char *p;

	if (n == 0)
		return false;

	for (p = strstr(path, segment); p; p = strstr(p + n, segment)) {
		bool at_start = (p == path) || (p[-1] == '/');
		bool at_end = (p[n] == '\0') || (p[n] == '/');

		if (at_start && at_end)
			return true;
	}
	return false;
}

/* As above, but matches any component starting with @prefix ("magisk*"). */
static bool path_has_segment_prefix(const char *path, const char *prefix)
{
	size_t n = strlen(prefix);
	const char *p;

	if (n == 0)
		return false;

	for (p = strstr(path, prefix); p; p = strstr(p + n, prefix)) {
		if ((p == path) || (p[-1] == '/'))
			return true;
	}
	return false;
}

static bool ends_with(const char *path, const char *suffix)
{
	size_t lp = strlen(path);
	size_t ls = strlen(suffix);

	return lp >= ls && strcmp(path + lp - ls, suffix) == 0;
}

/* Per-socket inspection tables; a locked device denies these to app processes. */
static bool is_proc_net(const char *path)
{
	const char *target = NULL;
	const char *p;

	if (strncmp(path, "/proc/net/", 10) == 0) {
		target = path + 10;
	} else if (strncmp(path, "/proc/", 6) == 0) {
		p = path + 6;
		if (strncmp(p, "self/", 5) == 0)
			p += 5;
		else if (strncmp(p, "thread-self/", 12) == 0)
			p += 12;
		else {
			while (*p >= '0' && *p <= '9')
				p++;
			if (*p == '/')
				p++;
		}
		if (strncmp(p, "net/", 4) == 0)
			target = p + 4;
	}

	if (target) {
		if (strcmp(target, "tcp") == 0 || strcmp(target, "tcp6") == 0 ||
		    strcmp(target, "udp") == 0 || strcmp(target, "udp6") == 0)
			return true;
	}
	return false;
}

/* Board/firmware description tables absent on the emulated hardware. */
static bool is_dmi_path(const char *path)
{
	return strncmp(path, "/sys/devices/virtual/dmi/", 25) == 0 ||
	       strncmp(path, "/sys/class/dmi/", 15) == 0 ||
	       strncmp(path, "/sys/firmware/dmi/", 18) == 0 ||
	       strncmp(path, "/sys/devices/virtual/thermal/", 29) == 0 ||
	       strncmp(path, "/sys/class/thermal/", 19) == 0;
}

/* A block device's backing_file reveals an image-backed volume. */
static bool is_block_backing_file(const char *path)
{
	return strncmp(path, "/sys/", 5) == 0 && ends_with(path, "/backing_file");
}

/* A NIC hardware address reached through the host bus topology. */
static bool is_bus_net_address(const char *path)
{
	return strncmp(path, "/sys/", 5) == 0 && strstr(path, "/pci") &&
	       strstr(path, "/net/") && ends_with(path, "/address");
}

/* Non-standard root entries and known elevation binaries. */
static bool is_suspicious_root_file(const char *path)
{
	/* Standard partitions -- never filtered. */
	if (strncmp(path, "/data/", 6) == 0 || strncmp(path, "/storage/", 9) == 0 ||
	    strncmp(path, "/sdcard/", 8) == 0 || strncmp(path, "/system/", 8) == 0 ||
	    strncmp(path, "/vendor/", 8) == 0 || strncmp(path, "/product/", 9) == 0 ||
	    strncmp(path, "/system_ext/", 12) == 0 || strncmp(path, "/apex/", 6) == 0 ||
	    strncmp(path, "/dev/", 5) == 0 || strncmp(path, "/mnt/", 5) == 0)
		return false;

	if (strcmp(path, "/boot") == 0 || strncmp(path, "/boot/", 6) == 0 ||
	    strcmp(path, "/init") == 0 || strncmp(path, "/init.", 6) == 0 ||
	    strcmp(path, "/init.environ.rc") == 0 || strcmp(path, "/init.rc") == 0 ||
	    strcmp(path, "/init.x86.rc") == 0 || strncmp(path, "/fstab.", 7) == 0 ||
	    strcmp(path, "/data_mirror") == 0 || strncmp(path, "/data_mirror/", 13) == 0 ||
	    strcmp(path, "/postinstall") == 0 || strncmp(path, "/postinstall/", 13) == 0 ||
	    strcmp(path, "/debug_ramdisk") == 0 || strncmp(path, "/debug_ramdisk/", 15) == 0 ||
	    strcmp(path, "/second_stage_resources") == 0 ||
	    strstr(path, "init.lineage") || strstr(path, "fstab.lineage") ||
	    strstr(path, "init.zenith") || strstr(path, "fstab.zenith"))
		return true;

	/* Relative forms (resolved against the caller's working directory). */
	if (strcmp(path, "boot") == 0 || strcmp(path, "init") == 0 ||
	    strcmp(path, "init.environ.rc") == 0 || strcmp(path, "init.rc") == 0 ||
	    strcmp(path, "init.x86.rc") == 0 || strncmp(path, "init.", 5) == 0 ||
	    strncmp(path, "fstab.", 6) == 0 || strcmp(path, "data_mirror") == 0 ||
	    strcmp(path, "postinstall") == 0 || strcmp(path, "debug_ramdisk") == 0 ||
	    strcmp(path, "second_stage_resources") == 0)
		return true;

	/* Elevation binaries, matched on whole path components only. */
	if (path_has_segment(path, "su") || path_has_segment_prefix(path, "magisk"))
		return true;

	return false;
}

int bionic_hidden_path_errno(const char *name)
{
	/* Fail open on anything unexpected. */
	if (!name)
		return 0;

	/* Only ordinary application processes are subject to the filter. */
	if (from_kuid(&init_user_ns, current_uid()) < FIRST_APP_UID)
		return 0;

	if (is_proc_net(name))
		return -EACCES;

	if (is_suspicious_root_file(name) || is_dmi_path(name) ||
	    is_block_backing_file(name) || is_bus_net_address(name))
		return -ENOENT;

	return 0;
}
