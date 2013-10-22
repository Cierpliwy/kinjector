/*-----------------------------------------------------------------------------
    This file is part of Simple Linux Kernel Fault Injector.
    Copyright (C) 2013  Przemysław Lenart <przemek.lenart@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see [http://www.gnu.org/licenses/].
-----------------------------------------------------------------------------*/

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "parser.h"
#include "injection.h"
#include "kinjector.h"
#include "execute.h"

MODULE_AUTHOR("Przemysław Lenart <przemek.lenart@gmail.com>");
MODULE_DESCRIPTION("Linux kernel injector");
MODULE_VERSION("0.2");
MODULE_LICENSE("GPL");

/* --- GLOBALS ------------------------------------------------------------- */ 
static LIST_HEAD(ki_injection_list); /* List of all trigger based injections */
static char *ki_msg = "No command";  /* Last message sent to user */
static size_t ki_pos = 0;            /* Last position in command buffer */

/* --- PROCFS -------------------------------------------------------------- */
/*
 * Function reading input form user in form of a command.
 */
ssize_t ki_write(struct file *filp, const char *buffer, size_t len,
                 loff_t *f_pos)
{
        struct ki_injection *injection;

        /* Allocate memory for a message and copy it to kernel space */
        char *msg = kmalloc(len + 1, GFP_KERNEL);
        if (!msg) return -ENOMEM;
        if (copy_from_user(msg, buffer, len)) {
                kfree(msg);
                return -EFAULT;
        }
        msg[len] = '\0';

        /* Allocate memory for injection structure and initialize it */
        injection = kmalloc(sizeof(*injection), GFP_KERNEL);
        if (!injection) {
                kfree(msg);
                return -ENOMEM;
        }
        ki_init_injection(injection);

        /* Parse command and if succeeded execute it */ 
        printk(MODULE_PRINTK_DBG "Got command: %s", msg);
       
        if (!ki_parse(msg, len, &ki_pos, injection, &ki_msg)) goto fail;
        if (!ki_validate_injection(injection, &ki_msg)) goto fail;
        if (!ki_execute_injection(injection, &ki_injection_list, &ki_msg)) 
                goto fail;
        goto success;

fail:
        /* Injection not used... free it */
        ki_free_injection(injection);

success:
        /* Free buffer, whole message was read */
        kfree(msg);
        return len;
}

/*
 * Sequence file's start iterator
 */
static void *ki_seq_start(struct seq_file *s, loff_t *pos)
{
        if (*pos == 0) return SEQ_START_TOKEN;
        return seq_list_start(&ki_injection_list, *pos - 1);
}

/*
 * Sequence file's next iterator
 */
static void *ki_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
        if (v == SEQ_START_TOKEN) 
                return seq_list_start(&ki_injection_list, *pos - 1);
       
        return seq_list_next(v, &ki_injection_list, pos);
}

/*
 * We don't need to free anything after iteration
 */
static void ki_seq_stop(struct seq_file *s, void *v)
{

}

/*
 * Show element which sequence iterator is pointing at
 */
static int ki_seq_show(struct seq_file *s, void *v)
{
        if (v == SEQ_START_TOKEN)
                seq_printf(s, "%lu: %s\n", ki_pos, ki_msg);
        else {  
                long actualcalls;
                struct ki_injection *injection;
                injection = list_entry(((struct list_head*)v), 
                                         struct ki_injection, list);
                actualcalls = injection->calls - injection->skipped_inj;
                if (actualcalls < 0) actualcalls = 0;

                seq_printf(s, "TRIGGER 0x%lx (%s+%ld) CALLS %ld/%ld\n", 
                           injection->trigger.addr + injection->trigger_offset,
                           injection->trigger.name ? injection->trigger.name : "?",
                           injection->trigger_offset,
                           actualcalls,
                           injection->max_inj);
        }

        return 0;
}

/*
 * Sequence operations structure
 */
static struct seq_operations ki_seq_ops = {
        .start = ki_seq_start,
        .next  = ki_seq_next,
        .stop  = ki_seq_stop,
        .show  = ki_seq_show
};

/*
 * We are using sequence file's custom open function.
 */
static int ki_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &ki_seq_ops);
}

/*
 * We are using custom function for getting input and sequence file for an
 * output
 */
static struct file_operations ki_file_ops = { 
        .owner   = THIS_MODULE,
        .open    = ki_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
        .write   = ki_write
};

/* --- ENTRY POINT --------------------------------------------------------- */
static int __init init_kernelinjector(void)
{
        /* Creating proc file for handling commands */
        if (!proc_create(MODULE_NAME_STR, 0666, NULL, &ki_file_ops)) {
                printk(MODULE_PRINTK_ERR "Couldn't create procfs file\n");
                return -ENOMEM;
        }

        return 0;
}

static void  __exit exit_kernelinjector(void)
{
        /* Remove proc entry and all injections */
        remove_proc_entry(MODULE_NAME_STR, NULL);
        ki_free_injection_list(&ki_injection_list);
}

module_init(init_kernelinjector);
module_exit(exit_kernelinjector);
