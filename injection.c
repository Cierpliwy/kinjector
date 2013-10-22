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

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/module.h>
#include "injection.h"
#include "kinjector.h"

/*
 * Initialize kernel injection structure
 */
void ki_init_injection(struct ki_injection *injection)
{
        memset(injection, 0, sizeof(*injection));
}

/*
 * Free kernel injection structure
 */
void ki_free_injection(struct ki_injection *injection)
{
        if (injection->kp.addr) unregister_kprobe(&injection->kp);
        if (injection->target.name) kfree(injection->target.name);
        if (injection->trigger.name) kfree(injection->trigger.name);
        if (injection->module_name) kfree(injection->module_name);
        kfree(injection);
}

/*
 * Free all kernel injections from a list
 */
void ki_free_injection_list(struct list_head *list)
{
        struct list_head *pos, *n;
        struct ki_injection *injection;
        list_for_each_safe(pos, n, list) {
                injection = list_entry(pos, struct ki_injection, list);
                list_del(pos);
                ki_free_injection(injection);
        }
}

/*
 * Print injection structure to syslog
 */
static void ki_print_injection(struct ki_injection *injection)
{
        printk(MODULE_PRINTK_DBG "Kernel injection: \n");
        
        if (injection->target.name)
                printk(MODULE_PRINTK_DBG "Target: %s +(%ld)\n", 
                       injection->target.name, injection->target_offset);
        else
                printk(MODULE_PRINTK_DBG "Target: %lx +(%ld)\n", 
                       injection->target.addr, injection->target_offset);

        if (injection->trigger.name)
                printk(MODULE_PRINTK_DBG "Trigger: %s +(%ld)\n", 
                       injection->trigger.name, injection->trigger_offset);
        else
                printk(MODULE_PRINTK_DBG "Trigger: %lx +(%ld)\n", 
                       injection->trigger.addr, injection->trigger_offset);

        if (injection->module_name)
                printk(MODULE_PRINTK_DBG "Module: %s\n", 
                       injection->module_name);

        printk(MODULE_PRINTK_DBG "Max injections: %ld\n", injection->max_inj);
        printk(MODULE_PRINTK_DBG "Skipped injections: %ld\n", 
               injection->skipped_inj);
        printk(MODULE_PRINTK_DBG "Bitflip: %ld\n", injection->bitflip);

        printk(MODULE_PRINTK_DBG "Flags: ");
        if (injection->flags & KI_FLG_STACK) printk(KERN_CONT "STACK |");
        if (injection->flags & KI_FLG_REGS) printk(KERN_CONT "REGS |");
        if (injection->flags & KI_FLG_DATA) printk(KERN_CONT "DATA |");
        if (injection->flags & KI_FLG_RODATA) printk(KERN_CONT "RODATA |");
        if (injection->flags & KI_FLG_CODE) printk(KERN_CONT "CODE |");
        if (injection->flags & KI_FLG_CLEAR) printk(KERN_CONT "CLEAR |");
        printk(KERN_CONT "\n");
}

/*
 * Validate injection structure.
 * Return true on success. Information about eventual failure is passed
 * to msg variable.
 */
bool ki_validate_injection(struct ki_injection *injection, char **msg)
{
        /* Print injection structure */
        ki_print_injection(injection);

        /* Check clear flag first */
        if (injection->flags & KI_FLG_CLEAR) return true;

        /* If we have a module get its pointer */
        if (injection->module_name) {
                mutex_lock(&module_mutex);
                injection->module = find_module(injection->module_name);
                mutex_unlock(&module_mutex);
                
                if (!injection->module) {
                        *msg = "Module not found";
                        return false;
                }
        }

        /* If we have a target symbol, get it's address */
        if (injection->target.name) {
                injection->target.addr 
                        = kallsyms_lookup_name(injection->target.name);
                if (!injection->target.addr) {
                        *msg = "Injection symbol not found";
                        return false;
                }
        }
     
        /* We cannot do direct injection without bitflip specified */
        if (injection->target.addr) {
                if (!injection->bitflip) {
                        *msg = "INJECT_INTO requires BITFLIP";
                        return false;
                }
        }

        /* If we have trigger symbol, get it's address */
        if (injection->trigger.name) {
                injection->trigger.addr 
                        = kallsyms_lookup_name(injection->trigger.name);
                if (!injection->trigger.addr) {
                        *msg = "Trigger symbol not found";
                        return false;
                }
        }

        /* BITFLIP requires target */
        if (injection->bitflip && !injection->target.addr) {
                *msg = "BITFLIP requires INJECT_INTO";
                return false;
        }

        /* STACK | REGS require trigger */
        if ((injection->flags & (KI_FLG_STACK | KI_FLG_REGS)) &&
             !injection->trigger.addr) {
                *msg = "CODE, REGS require TRIGGER";
                return false;
        }

        /* RODATA | DATA | CODE require MODULE */
        if ((injection->flags & (KI_FLG_RODATA | KI_FLG_DATA | KI_FLG_CODE)) &&
             !injection->module) {
                *msg = "RODATA, DATA, CODE require MODULE";
                return false;
        }

        /* Inject offset require injection target */
        if (injection->target_offset && !injection->target.addr) {
                *msg = "INJECT_OFFSET require INJECT_INTO";
                return false;
        }

        /* Trigger offset require trigger */
        if (injection->trigger_offset && !injection->trigger.addr) {
                *msg = "TRIGGER_OFFSET require TRIGGER";
                return false;
        }

        /* Max number of injections must be positive */
        if (injection->max_inj < 0) {
                *msg = "MAX_INJECTIONS must be >= 0";
                return false;
        }

        /* If maximum number of injections is specified, trigger
         * must exist.
         */
        if (injection->max_inj && !injection->trigger.addr) {
                *msg = "MAX_INJECTIONS require TRIGGER";
                return false;
        }

        /* Number of skipped injections must be positive */
        if (injection->skipped_inj < 0) {
                *msg = "SKIPPED_INJECTIONS must be >= 0";
                return false;
        }

        /* If a number of skipped injections is specified, trigger
         * must exist.
         */
        if (injection->skipped_inj && !injection->trigger.addr) {
                *msg = "SKIPPED_INJECTIONS require TRIGGER";
                return false;
        }

        return true;
}

