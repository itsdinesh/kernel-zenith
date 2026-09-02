// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/hidden_paths.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include "internal.h"

/* Boot parameters that identify the boot loader or the host platform. */
static bool cmdline_token_hidden(const char *tok, size_t len)
{
	static const char * const hidden[] = {
		"stack_depot_disable", "cgroup_disable", "loop.max_part",
		"BOOT_IMAGE", "syscall_hardening", "button.lid_init_state",
		"ROOT=", "SRC=", "androidboot.bootctrl_bootcfg",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(hidden); i++) {
		size_t hl = strlen(hidden[i]);

		if (len >= hl && strncmp(tok, hidden[i], hl) == 0)
			return true;
	}
	return false;
}

static void cmdline_show_filtered(struct seq_file *m)
{
	const char *p = saved_command_line;
	bool first = true;

	while (*p) {
		const char *tok;

		while (*p == ' ')
			p++;
		if (!*p)
			break;
		tok = p;
		while (*p && *p != ' ')
			p++;

		if (cmdline_token_hidden(tok, p - tok))
			continue;

		if (!first)
			seq_putc(m, ' ');
		seq_write(m, tok, p - tok);
		first = false;
	}
	seq_putc(m, '\n');
}

static int cmdline_proc_show(struct seq_file *m, void *v)
{
	if (bionic_filter_current()) {
		cmdline_show_filtered(m);
		return 0;
	}

	seq_puts(m, saved_command_line);
	seq_putc(m, '\n');
	return 0;
}

static int __init proc_cmdline_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("cmdline", 0, NULL, cmdline_proc_show);
	pde_make_permanent(pde);
	pde->size = saved_command_line_len + 1;
	return 0;
}
fs_initcall(proc_cmdline_init);
