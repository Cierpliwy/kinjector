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

#ifndef KI_PARSER_H
#define KI_PARSER_H

#include <linux/types.h>
struct ki_symbol;
struct ki_injection;

/* --- PARSER FUNCTIONS --------------------------------------------------- */
bool ki_parse(char *buffer, size_t len, size_t *pos, 
              struct ki_injection *injection, char **msg);

#endif /*KI_PARSER_H*/
