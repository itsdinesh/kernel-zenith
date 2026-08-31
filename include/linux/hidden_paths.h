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

/*
 * Returns the negative errno the caller should report for @name, or 0 to let
 * the access proceed. Only ordinary application processes are affected; system
 * UIDs and any unexpected input take the 0 (allow) fast path.
 */
int bionic_hidden_path_errno(const char *name);

#endif /* _LINUX_HIDDEN_PATHS_H */
