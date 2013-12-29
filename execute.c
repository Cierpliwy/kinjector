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
#include <linux/kprobes.h>
#include <linux/random.h>
#include <linux/module.h>
#include <linux/stddef.h>
#include "execute.h"
#include "injection.h"
#include "kinjector.h"

/* --- DEFINES ------------------------------------------------------------ */
#define IS_REG(byte, reg, name) \
    if ((byte) >= offsetof(struct pt_regs, reg) && \
        (byte) < offsetof(struct pt_regs, reg) + reg_size) reg_name = name

/* Runtime debug flag */
static int ki_debug = 0;

/* --- FUNCTIONS ---------------------------------------------------------- */
/*
 * Invert specific bit under an address
 */
static void ki_bitflip(unsigned long addr, unsigned char bit)
{
        bool rw;
        char byte;
        unsigned int level;
        pte_t *pte;

        rw = true;
        pte = lookup_address(addr, &level);
        if (!(pte->pte & _PAGE_RW)) {
                pte->pte |= _PAGE_RW;
                rw = false;
        }
        
        printk(MODULE_PRINTK_ERR "\tBITFLIP 0x%lx:%d (%pF)\n", addr, bit, 
               (void*)addr);

        if (!ki_debug) {
            byte = *(char*)(addr);
            byte ^= 1 << bit;
            *(char*)(addr) = byte;
        }

        if (!rw) pte->pte &= ~_PAGE_RW;
}

/*
 * Invert one bit in a sequence of count bytes starting under addr.
 */
static void ki_bitflip_rand(unsigned long addr, long count)
{
        unsigned long injection;
        unsigned char random[sizeof(unsigned long)+1];

        get_random_bytes_arch(random, sizeof(unsigned long)+1);
        injection = addr + (*(unsigned long*)random % count);

        ki_bitflip(injection, random[sizeof(unsigned long)] % 8);
}

/*
 * Invert one bit in registers
 */
static void ki_bitflip_regs(struct pt_regs *regs)
{
        /* Select byte and bit to modify */
        unsigned int byte;
        unsigned char random[sizeof(unsigned int)+1];
        char *reg_name;
        unsigned int reg_size;

        reg_name = "?";
        reg_size = sizeof(regs->ax);

        get_random_bytes_arch(random, sizeof(unsigned int)+1);
        byte = *((unsigned int*)random) % sizeof(*regs);

        /* Get register name */
        IS_REG(byte, r15, "R15");
        IS_REG(byte, r14, "R14");
        IS_REG(byte, r13, "R13");
        IS_REG(byte, r12, "R12");
        IS_REG(byte, bp, "RBP");
        IS_REG(byte, bx, "RBX");
        IS_REG(byte, r11, "R11");
        IS_REG(byte, r10, "R10");
        IS_REG(byte, r9, "R9");
        IS_REG(byte, r8, "R8");
        IS_REG(byte, ax, "RAX");
        IS_REG(byte, cx, "RCX");
        IS_REG(byte, dx, "RDX");
        IS_REG(byte, si, "RSI");
        IS_REG(byte, di, "RDI");
        IS_REG(byte, orig_ax, "ORIG_RAX");
        IS_REG(byte, ip, "RIP");
        IS_REG(byte, cs, "CS");
        IS_REG(byte, flags, "FLAGS");
        IS_REG(byte, sp, "RSP");
        IS_REG(byte, ss, "SS");
        
        printk(MODULE_PRINTK_ERR "\tREG: %s 0x%lx+%u\n", reg_name,
                                  (unsigned long)(regs), byte);

        ki_bitflip((unsigned long)(regs) + byte,
                   random[sizeof(unsigned int)] % 8);
}

/*
 * Do immediate injection based on injection structure
 */
static void ki_do_injection(struct ki_injection *injection,
                            struct pt_regs *regs)
{
        ki_debug = injection->debug;

        if (injection->target.addr) {
                unsigned long addr = injection->target.addr;
                addr += injection->target_offset;
                
                printk(MODULE_PRINTK_ERR "\tTARGET 0x%lx (%s+%ld)\n",
                       addr,
                       injection->target.name ? injection->target.name : "?",
                       injection->target_offset);

                ki_bitflip_rand(addr, injection->bitflip);
        }

        if (regs) {
                if (injection->flags & KI_FLG_REGS) {
                        ki_bitflip_regs(regs);
                }
                if (injection->flags & KI_FLG_STACK) {
                        printk(MODULE_PRINTK_ERR "\tSTACK 0x%lx:10\n",
                               (unsigned long) (regs->sp));
                        ki_bitflip_rand(regs->sp, 10);
                }
        }

        if (injection->module) {
                if (injection->flags & KI_FLG_DATA) {
                        unsigned long addr;
                        long size;
                        addr = (unsigned long) 
                               (injection->module->module_core) +
                               injection->module->core_ro_size;
                        size = injection->module->core_size -
                               injection->module->core_ro_size;

                        printk(MODULE_PRINTK_ERR "\tDATA 0x%lx:%ld\n", addr, 
                                                                       size);
                        ki_bitflip_rand(addr, size);
                }
                if (injection->flags & KI_FLG_RODATA) {
                        unsigned long addr;
                        long size;
                        addr = (unsigned long) 
                               (injection->module->module_core) +
                               injection->module->core_text_size;
                        size = injection->module->core_ro_size - 
                               injection->module->core_text_size;

                        printk(MODULE_PRINTK_ERR "\tRODATA 0x%lx:%ld\n", addr
                                                                       , size);
                        ki_bitflip_rand(addr, size);
                }
                if (injection->flags & KI_FLG_CODE) {
                        unsigned long addr;
                        long size;
                        addr = (unsigned long)
                               (injection->module->module_core);
                        size = injection->module->core_text_size;

                        printk(MODULE_PRINTK_ERR "\tCODE 0x%lx:%ld\n", addr
                                                                     , size);
                        ki_bitflip_rand(addr, size);
                }
        }
}

/*
 * Kprobe handler for trigger based injections
 */
static int ki_kp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
        struct ki_injection *injection = container_of(p, struct ki_injection, kp);
        
        /* Handle injection limits */
        if (injection->max_inj && injection->calls >= injection->skipped_inj + injection->max_inj)
                return 0;
        
        injection->calls++;

        /* Handle skipped injections */
        if (injection->skipped_inj && injection->calls <= injection->skipped_inj)
                return 0;

        /* Execute injection */
        printk(MODULE_PRINTK_ERR "--- INJECTION START ---\n");
        printk(MODULE_PRINTK_ERR "\tTRIGGER 0x%lx (%s+%ld)\n",
               injection->trigger.addr + injection->trigger_offset,
               injection->trigger.name ? injection->trigger.name : "?",
               injection->trigger_offset);

        ki_do_injection(injection, regs);
        printk(MODULE_PRINTK_ERR "--- INJECTION END ---\n");

        return 0;
}



/*
 * Execute kernel injection. Injection structure should be validated before
 * usage. If injection is trigger based it added to the injection list.
 * Returns true on success
 */
bool ki_execute_injection(struct ki_injection *injection, 
                          struct list_head *injection_list,
                          char **msg)
{
        /* If clear is passed do clear */
        if (injection->flags & KI_FLG_CLEAR) {
                ki_free_injection_list(injection_list);
                ki_free_injection(injection);
                return true;
        }

        /* If trigger is passed use kprobes */
        if (injection->trigger.addr) {
                injection->kp.addr = (kprobe_opcode_t*) (injection->trigger.addr);
                injection->kp.addr += injection->trigger_offset;
                injection->kp.pre_handler = ki_kp_pre_handler;
               
                /* Register it */
                if (register_kprobe(&injection->kp) != 0) {
                        injection->kp.addr = NULL;
                        *msg = "Cannot register kprobe";
                        return false;
                }

                /* Add to the list */
                list_add(&injection->list, injection_list);
                return true;
        }
        
        /* Immediate injection */
        printk(MODULE_PRINTK_ERR "--- INJECTION START ---\n");
        ki_do_injection(injection, NULL);
        printk(MODULE_PRINTK_ERR "--- INJECTION END ---\n");
        ki_free_injection(injection);
        return true;
}

