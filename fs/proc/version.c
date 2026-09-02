// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/hidden_paths.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include "internal.h"

static int version_proc_show(struct seq_file *m, void *v)
{
	/*
	 * Present the banner without the build account/host and toolchain
	 * details to application processes. The release string is left as-is
	 * so it continues to match uname().
	 */
	if (bionic_filter_current()) {
		seq_printf(m, "%s version %s (android-build@localhost) (clang) %s\n",
			utsname()->sysname,
			utsname()->release,
			utsname()->version);
		return 0;
	}

	seq_printf(m, linux_proc_banner,
		utsname()->sysname,
		utsname()->release,
		utsname()->version);
	return 0;
}

static int __init proc_version_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("version", 0, NULL, version_proc_show);
	pde_make_permanent(pde);
	return 0;
}
fs_initcall(proc_version_init);
