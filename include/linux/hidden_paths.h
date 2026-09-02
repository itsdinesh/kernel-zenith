/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Per-UID path privacy filter shared by the pathname-based syscalls.
 *
 * Userspace applies the same filter in the C library, but a caller can reach
 * the kernel directly through an inline syscall and bypass that copy. Applying
 * the decision here, at the single point every syscall funnels through, closes
 * that gap regardless of how the request was issued.
 */
#ifndef _LINUX_HIDDEN_PATHS_H
#define _LINUX_HIDDEN_PATHS_H

#include <linux/types.h>

/*
 * Returns the negative errno the caller should report for @name, or 0 to let
 * the access proceed. Only ordinary application processes are affected; system
 * UIDs and any unexpected input take the 0 (allow) fast path.
 */
int bionic_hidden_path_errno(const char *name);

/*
 * True when the current process is an ordinary application (UID >= app start),
 * i.e. subject to the privacy filters below. System UIDs return false.
 * Used to gate content sanitisation of world-readable /proc nodes that carry
 * no per-file permission of their own (cmdline, version, cpuinfo, mounts).
 */
bool bionic_filter_current(void);

/*
 * For the mount tables (/proc/<pid>/mount{s,info}): true when a mount entry with
 * mount-point leaf name @mnt_name backed by @devname should be omitted from an
 * application's view because it is specific to this environment (staging binds,
 * boot volume, image loop devices). Either argument may be NULL.
 */
bool bionic_hide_mount(const char *mnt_name, const char *devname);

/*
 * Substitute a neutral device name for @devname when the real one identifies
 * host-class storage (e.g. a raw SATA/NVMe node). Returns @devname unchanged
 * when no substitution applies, so it is always safe to print the result.
 */
const char *bionic_mount_devname(const char *devname);

#endif /* _LINUX_HIDDEN_PATHS_H */
