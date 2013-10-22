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

#ifndef KI_INJECTION_H
#define KI_INJECTION_H

#include <linux/kprobes.h>
#include <linux/list.h>
struct module;

/* --- INJECTION STRUCTURES -------------------------------------------------- */
/*
 * Symbol structure. If name is filled address will be automatically resolved
 * by kallsym_lookup function.
 */
struct ki_symbol
{
        unsigned long  addr;
        char          *name;
};

/*
 * Kernel injection flags
 */
enum ki_flags_e
{
        KI_FLG_STACK  = 1,
        KI_FLG_REGS   = 2,
        KI_FLG_DATA   = 4,
        KI_FLG_RODATA = 8,
        KI_FLG_CODE   = 16,
        KI_FLG_CLEAR  = 32
};

/*
 * Injection structure
 */
struct ki_injection
{
        struct ki_symbol target;
        long             target_offset;
        struct ki_symbol trigger;
        long             trigger_offset;
        struct module    *module;
        char             *module_name;
        long             bitflip;
        long             max_inj;
        long             skipped_inj;
        long             calls;
        enum ki_flags_e  flags;
        struct kprobe    kp;
        struct list_head list;
};

/* --- INJECTION UTILITY FUNCTIONS ---------------------------------------- */
void ki_init_injection(struct ki_injection *injection);
void ki_free_injection(struct ki_injection *injection);
void ki_free_injection_list(struct list_head *list);
bool ki_validate_injection(struct ki_injection *injection, char **msg);

#endif /*KI_INJECTION_H*/
