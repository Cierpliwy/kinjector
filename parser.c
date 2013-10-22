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

#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "parser.h"
#include "injection.h"
#include "kinjector.h"

/* --- KEYWORDS ------------------------------------------------------------ */
#define KEYWORD(x) (x), sizeof (x) - 1
static const char ki_key_bitflip[]            = "BITFLIP";
static const char ki_key_clear[]              = "CLEAR";
static const char ki_key_code[]               = "CODE";
static const char ki_key_data[]               = "DATA";
static const char ki_key_inject_into[]        = "INJECT_INTO";
static const char ki_key_inject_offset[]      = "INJECT_OFFSET";
static const char ki_key_max_injections[]     = "MAX_INJECTIONS";
static const char ki_key_module[]             = "MODULE";
static const char ki_key_regs[]               = "REGS";
static const char ki_key_rodata[]             = "RODATA";
static const char ki_key_skipped_injections[] = "SKIPPED_INJECTIONS";
static const char ki_key_stack[]              = "STACK";
static const char ki_key_trigger[]            = "TRIGGER";
static const char ki_key_trigger_offset[]     = "TRIGGER_OFFSET";

/* --- FUNCTIONS ----------------------------------------------------------- */
/*
 * Parse hexadecimal value.
 * Buffer must be writeable to skip memory copying.
 * Returns true on success.
 */
static bool ki_parse_hex(char* buffer, size_t *pos, unsigned long *hex)
{
        size_t startpos = *pos;
        printk(MODULE_PRINTK_DBG "Parse hex: %s", buffer + *pos);

        /* Find end of a string */
        while (!iscntrl(buffer[*pos])) {
                if (!isxdigit(buffer[*pos])) break;
                ++*pos;
        }

        /* If string is not empty, insert temporary NULL value in it's end
         * and try to parse a value */
        if (*pos != startpos) {
                bool result;
                char c = buffer[*pos];
                buffer[*pos] = '\0';
                result = kstrtoul(buffer + startpos, 16, hex);
                buffer[*pos] = c;
                return (result == 0);
        }

        return false;
}


/*
 * Parse decimal value.
 * Buffer must be writeable to skip memory copying.
 * Returns true on success.
 */
static bool ki_parse_dec(char* buffer, size_t *pos, long *dec)
{
        size_t startpos = *pos;
        printk(MODULE_PRINTK_DBG "Parse dec: %s", buffer + *pos);

        /* Find end of a string */
        while (!iscntrl(buffer[*pos])) {
                if (!(isdigit(buffer[*pos]) || buffer[*pos] == '-')) break;
                ++*pos;
        }
        
        /* If string is not empty, insert temporary NULL value in it's end
         * and try to parse a value */
        if (*pos != startpos) {
                bool result;
                char c = buffer[*pos];
                buffer[*pos] = '\0';
                result = kstrtol(buffer + startpos, 10, dec);
                buffer[*pos] = c;
                return (result == 0);
        }

        return false;
}

/*
 * Parse symbol.
 * Returns true on success.
 */
static bool ki_parse_sym(const char *buffer, size_t *pos, char **result)
{
        size_t startpos = *pos;
        printk(MODULE_PRINTK_DBG "Parse sym: %s", buffer + *pos);

        /* Check if string is correct and find it's end */
        while (!iscntrl(buffer[*pos]) && buffer[*pos] != ' ') {
                if (!(isalnum(buffer[*pos]) || buffer[*pos] == '.' ||
                    buffer[*pos] == '_')) return false;
                ++*pos;
        }

        /* Allocate string */
        *result = kmalloc(*pos - startpos + 1, GFP_KERNEL);
        if (!*result) return false;

        /* Copy string */
        strncpy(*result, buffer + startpos, *pos - startpos);
        (*result)[*pos - startpos] = '\0';

        return true;
}

/*
 * Parse hexadecimal prefix
 * Returns true on success
 */
static bool ki_parse_hex_prefix(const char *buffer, size_t *pos)
{
        printk(MODULE_PRINTK_DBG "Parse hex_prefix: %s", buffer + *pos);
        if (buffer[*pos] == '0' && buffer[*pos+1] == 'x') {
                *pos += 2;
                return true;
        }
        return false;
}

/*
 * Parse symbol or hexadecimal value with prefix
 * Buffer must be writeable to skip memory copying.
 * Returns true on success
 */
static bool ki_parse_sym_or_addr(char *buffer, size_t *pos,
                          struct ki_symbol *symbol)
{
        size_t startpos = *pos;
        printk(MODULE_PRINTK_DBG "Parse sym_or_addr: %s", buffer + *pos);

        /* If we have hexadecimal prefix, it's address */
        if (ki_parse_hex_prefix(buffer, &startpos)) {
                *pos = startpos;
                return ki_parse_hex(buffer, pos, &symbol->addr);
        }

        return ki_parse_sym(buffer, pos, &symbol->name);
}

/*
 * Parse keyword.
 * Returns true on success.
 */
static bool ki_parse_keyword(const char *buffer, size_t len, size_t *pos,
                      const char *keyword, size_t keyword_len)
{
        if (*pos + keyword_len > len) return false;
        if (strncmp(buffer + *pos, keyword, keyword_len) != 0) return false;
        *pos += keyword_len;
        return true;
}

/*
 * Skips one space character
 */
static bool ki_parse_skip_space(const char *buffer, size_t *pos)
{
        if (buffer[*pos] != ' ') return false;
        ++*pos;
        return true;
}

/*
 * Parse BITFLIP keyword
 * Returns true on success.
 */
static bool ki_parse_bitflip(char *buffer, size_t len, size_t *pos,
                      char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_bitflip))) {
                *msg = "BITFLIP keyword expected";
                return false;
        }
        
        if (!ki_parse_skip_space(buffer, pos)) {
                *msg = "BITFLIP number of bytes argument expected";
                return false;
        }

        if (!ki_parse_dec(buffer, pos, &injection->bitflip)) {
                *msg = "Wrong BITFLIP argument";
                return false;
        }

        return true;
}

/*
 * Parse CLEAR keyword.
 * Returns true on success.
 */
static bool ki_parse_clear(const char *buffer, size_t len, size_t *pos,
                           char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_clear))) {
                *msg = "CLEAR keyword expected";
                return false;
        }

        injection->flags |= KI_FLG_CLEAR;        
        return true;
}

/*
 * Parse CODE keyword.
 * Returns true on success.
 */
static bool ki_parse_code(const char *buffer, size_t len, size_t *pos,
                          char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_code))) {
                *msg = "CODE keyword expected";
                return false;
        }
        
        injection->flags |= KI_FLG_CODE;
        return true;
}

/*
 * Parse DATA keyword.
 * Returns true on success.
 */
static bool ki_parse_data(const char *buffer, size_t len, size_t *pos,
                          char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_data))) {
                *msg = "DATA keyword expected";
                return false;
        }
        
        injection->flags |= KI_FLG_DATA;
        return true;
}

/*
 * Parse INJECT_INTO keyword
 * Returns true on success.
 */
static bool ki_parse_inject_into(char *buffer, size_t len, size_t *pos,
                                 char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_inject_into))) {
                *msg = "INJECT_INTO keyword expected";
                return false;
        }
        
        if (!ki_parse_skip_space(buffer, pos)) {
                *msg = "INJECT_INTO symbol or address expected";
                return false;
        }
        
        if (injection->target.addr || injection->target.name) {
                *msg = "INJECT_INTO symbol or argument already specified";
                return false;
        }

        if (!ki_parse_sym_or_addr(buffer, pos, &injection->target)) {
                *msg = "Wrong INJECT_INTO symbol or argument";
                return false;
        }

        return true;
}

/*
 * Parse INJECT_OFFSET keyword 
 * Returns true on success.
 */
static bool ki_parse_inject_offset(char *buffer, size_t len, size_t *pos,
                                   char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_inject_offset))) {
                *msg = "INJECT_OFFSET keyword expected";
                return false;
        }
        
        if (!ki_parse_skip_space(buffer, pos)) {
                *msg = "INJECT_OFFSET decimal offset expected";
                return false;
        }

        if (!ki_parse_dec(buffer, pos, &injection->target_offset)) {
                *msg = "Wrong INJECT_OFFSET argument";
                return false;
        }

        return true;
}

/*
 * Parse MAX_INJECTIONS keyword
 * Returns true on success.
 */
static bool ki_parse_max_injections(char *buffer, size_t len, size_t *pos,
                                    char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_max_injections))) {
                *msg = "MAX_INJECTIONS keyword expected";
                return false;
        }
        
        if (!ki_parse_skip_space(buffer, pos)) {
                *msg = "MAX_INJECTIONS number argument expected";
                return false;
        }

        if (!ki_parse_dec(buffer, pos, &injection->max_inj)) {
                *msg = "Wrong MAX_INJECTIONS argument";
                return false;
        }

        return true;
}

/*
 * Parse MODULE keyword
 * Returns true on success.
 */
static bool ki_parse_module(const char *buffer, size_t len, size_t *pos,
                            char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_module))) {
                *msg = "MODULE keyword expected";
                return false;
        }
        
        if (!ki_parse_skip_space(buffer, pos)) {
                *msg = "MODULE name expected";
                return false;
        }

        if (injection->module_name) {
                *msg = "MODULE name already specified";
                return false;
        }

        if (!ki_parse_sym(buffer, pos, &injection->module_name)) {
                *msg = "Wrong MODULE name";
                return false;
        }

        return true;
}

/*
 * Parse REGS keyword.
 * Returns true on success.
 */
static bool ki_parse_regs(const char *buffer, size_t len, size_t *pos,
                          char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_regs))) {
                *msg = "REGS keyword expected";
                return false;
        }
        
        injection->flags |= KI_FLG_REGS;
        return true;
}

/*
 * Parse RODATA keyword.
 * Returns true on success.
 */
static bool ki_parse_rodata(const char *buffer, size_t len, size_t *pos,
                            char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_rodata))) {
                *msg = "RODATA keyword expected";
                return false;
        }
        
        injection->flags |= KI_FLG_RODATA;
        return true;
}

/*
 * Parse SKIPPED_INJECTIONS keyword 
 * Returns true on success.
 */
static bool ki_parse_skipped_injections(char *buffer, size_t len, size_t *pos,
                                        char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_skipped_injections))) {
                *msg = "SKIPPED_INJECTIONS keyword expected";
                return false;
        }
        
        if (!ki_parse_skip_space(buffer, pos)) {
                *msg = "SKIPPED_INJECTIONS number expected";
                return false;
        }

        if (!ki_parse_dec(buffer, pos, &injection->skipped_inj)) {
                *msg = "Wrong SKIPPED_INJECTIONS argument";
                return false;
        }

        return true;
}

/*
 * Parse STACK keyword.
 * Returns true on success.
 */
static bool ki_parse_stack(const char *buffer, size_t len, size_t *pos,
                           char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_stack))) {
                *msg = "STACK keyword expected";
                return false;
        }
        
        injection->flags |= KI_FLG_STACK;
        return true;
}

/*
 * Parse TRIGGER keyword
 * Returns true on success.
 */
static bool ki_parse_trigger(char *buffer, size_t len, size_t *pos,
                             char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_trigger))) {
                *msg = "TRIGGER keyword expected";
                return false;
        }
        
        if (!ki_parse_skip_space(buffer, pos)) {
                *msg = "TRIGGER symbol or address expected";
                return false;
        }
        
        if (injection->trigger.addr || injection->trigger.name) {
                *msg = "TRIGGER symbol or argument already specified";
                return false;
        }

        if (!ki_parse_sym_or_addr(buffer, pos, &injection->trigger)) {
                *msg = "Wrong TRIGGER symbol or argument";
                return false;
        }

        return true;
}

/*
 * Parse TRIGGER_OFFSET keyword
 * Returns true on success.
 */
static bool ki_parse_trigger_offset(char *buffer, size_t len, size_t *pos,
                                    char** msg, struct ki_injection *injection)
{
        if (!ki_parse_keyword(buffer, len, pos, 
                             KEYWORD(ki_key_trigger_offset))) {
                *msg = "TRIGGER_OFFSET keyword expected";
                return false;
        }
        
        if (!ki_parse_skip_space(buffer, pos)) {
                *msg = "TRIGGER_OFFSET decimal number expected";
                return false;
        }

        if (!ki_parse_dec(buffer, pos, &injection->trigger_offset)) {
                *msg = "Wrong TRIGGER_OFFSET argument";
                return false;
        }

        return true;
}

/*
 * Check if 'ckpos' character after current position is a 'c' character.
 * Returns true on success.
 */
static bool ki_parse_check_char(char* buffer, size_t len, size_t curpos, 
                                size_t ckpos, char c)
{
        /* Check if char is not out of bound */
        if (curpos + ckpos >= len) return false;
        if (buffer[curpos + ckpos] != c) return false;
        return true;
}

/*
 * Main parser function.
 * Returns true on success.
 */
bool ki_parse(char *buffer, size_t len, size_t *pos, 
              struct ki_injection *injection, char **msg)
{
        *pos = 0;

        while (!iscntrl(buffer[*pos])) {
                /* Eat all white characters */
                while (isspace(buffer[*pos])) ++*pos;
                printk(MODULE_PRINTK_DBG "Left: %s", buffer + *pos);

                switch (buffer[*pos]) {
                case 'B':
                        if (!ki_parse_bitflip(buffer, len, pos, msg, injection))
                                return false;
                        break;
                case 'C':
                        if (ki_parse_check_char(buffer, len, *pos, 1, 'L')) {
                                if (!ki_parse_clear(buffer, len, pos, msg,
                                                    injection))
                                        return false;
                                else break;
                        }
                        if (!ki_parse_code(buffer, len, pos, msg, injection))
                                return false;
                        break;
                case 'D':
                        if (!ki_parse_data(buffer, len, pos, msg, injection))
                                return false;
                        break;
                case 'I':
                        if (ki_parse_check_char(buffer, len, *pos, 7, 'I')) {
                                if (!ki_parse_inject_into(buffer, len, pos, msg,
                                                          injection))
                                        return false;
                                else break;
                        }

                        if (!ki_parse_inject_offset(buffer, len, pos, msg, 
                                                    injection))
                                return false;
                        break;
                case 'M':
                        if (ki_parse_check_char(buffer, len, *pos, 1, 'A')) {
                                if (!ki_parse_max_injections(buffer, len, pos, msg,
                                                             injection))
                                        return false;
                                else break;
                        }

                        if (!ki_parse_module(buffer, len, pos, msg, injection))
                                return false;
                        break;
                case 'R':
                        if (ki_parse_check_char(buffer, len, *pos, 1, 'E')) {
                                if (!ki_parse_regs(buffer, len, pos, msg, 
                                                   injection))
                                        return false;
                                else break;
                        }

                        if (!ki_parse_rodata(buffer, len, pos, msg, injection))
                                return false;
                        break;
                case 'S':
                        if (ki_parse_check_char(buffer, len, *pos, 1, 'K')) {
                                if (!ki_parse_skipped_injections(buffer, len, 
                                                                 pos, msg, 
                                                                 injection))
                                        return false;
                                else break;
                        }

                        if (!ki_parse_stack(buffer, len, pos, msg, injection))
                                return false;
                        break;
                case 'T':
                        if (ki_parse_check_char(buffer, len, *pos, 7, '_')) {
                                if (!ki_parse_trigger_offset(buffer, len, 
                                                             pos, msg, 
                                                             injection))
                                        return false;
                                else break;
                        }

                        if (!ki_parse_trigger(buffer, len, pos, msg, 
                                              injection))
                                return false;
                        break;
                default:
                        *msg = "Unexpected keyword";
                        return false;
                }
        }

        *msg = "OK";
        return true;
}


