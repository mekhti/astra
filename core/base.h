/*
 * Astra Core
 * http://cesbo.com/astra
 *
 * Copyright (C) 2012-2015, Andrey Dyldin <and@cesbo.com>
 *                    2015, Artem Kharitonov <artem@sysert.ru>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ASC_BASE_H_
#define _ASC_BASE_H_ 1

#include <config.h>
#include <version.h>

// TODO:
#define WITH_LUA 1

#ifdef _WIN32
#   ifndef _WIN32_WINNT
#       define _WIN32_WINNT 0x0501
#   endif
#   include <winsock2.h>
#   include <windows.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <setjmp.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WITH_LUA
#   include <lua/lua.h>
#   include <lua/lualib.h>
#   include <lua/lauxlib.h>

#   define lua_stack_debug(_lua) \
    printf("%s:%d %s(): stack:%d\n", __FILE__, __LINE__, __FUNCTION__, lua_gettop(_lua))

#   define lua_foreach(_lua, _idx) for(lua_pushnil(_lua); lua_next(_lua, _idx); lua_pop(_lua, 1))
#endif

typedef struct module_data_t module_data_t;

#define ASC_ARRAY_SIZE(_a) (sizeof(_a)/sizeof(_a[0]))
#define ASC_FREE(_o, _m) if(_o != NULL) { _m(_o); _o = NULL; }

#define __OFFSET_16(_b, _s) ((uint16_t)((_b)[_s]) << (16 - (_s * 8) - 8))
#define BUFFER_TO_U16(_b) (                                                                     \
    __OFFSET_16(_b, 0) |                                                                        \
    __OFFSET_16(_b, 1) )

#define __OFFSET_24(_b, _s) ((uint32_t)((_b)[_s]) << (24 - (_s * 8) - 8))
#define BUFFER_TO_U24(_b) (                                                                     \
    __OFFSET_24(_b, 0) |                                                                        \
    __OFFSET_24(_b, 1) |                                                                        \
    __OFFSET_24(_b, 2) )

#define __OFFSET_32(_b, _s) ((uint32_t)((_b)[_s]) << (32 - (_s * 8) - 8))
#define BUFFER_TO_U32(_b) (                                                                     \
    __OFFSET_32(_b, 0) |                                                                        \
    __OFFSET_32(_b, 1) |                                                                        \
    __OFFSET_32(_b, 2) |                                                                        \
    __OFFSET_32(_b, 3))

#define U16_TO_BUFFER(_u, _b)                                                                   \
    do {                                                                                        \
        uint8_t *const __PTR = _b;                                                              \
        const uint16_t __U16_TO_BUFFER = (uint16_t)_u;                                          \
        __PTR[0] = (__U16_TO_BUFFER >> 8) & 0xFF;                                               \
        __PTR[1] = (__U16_TO_BUFFER     ) & 0xFF;                                               \
    } while(0)

#define U32_TO_BUFFER(_u, _b)                                                                   \
    do {                                                                                        \
        uint8_t *const __PTR = _b;                                                              \
        const uint32_t __U32_TO_BUFFER = (uint32_t)_u;                                          \
        __PTR[0] = (__U32_TO_BUFFER >> 24) & 0xFF;                                              \
        __PTR[1] = (__U32_TO_BUFFER >> 16) & 0xFF;                                              \
        __PTR[2] = (__U32_TO_BUFFER >>  8) & 0xFF;                                              \
        __PTR[3] = (__U32_TO_BUFFER      ) & 0xFF;                                              \
    } while(0)

#define __uarg(_x) {(void)_x;}

#if defined(__GNUC_GNU_INLINE__) \
    || (defined(__GNUC__) && !defined(__GNUC_STDC_INLINE__))
    /* workaround for older GCC versions */
#   define __asc_inline inline
#else
#   define __asc_inline extern inline
#endif

#ifndef __wur
#   define __wur __attribute__((__warn_unused_result__))
#endif

#define __fmt_printf(__index, __first) __attribute__((__format__(__printf__, __index, __first)))
#define __func_pure __attribute__((__pure__))
#define __func_const __attribute__((__const__))
#define __noreturn __attribute__((__noreturn__))

/*
 * __     __            _
 * \ \   / /__ _ __ ___(_) ___  _ __
 *  \ \ / / _ \ '__/ __| |/ _ \| '_ \
 *   \ V /  __/ |  \__ \ | (_) | | | |
 *    \_/ \___|_|  |___/_|\___/|_| |_|
 *
 */

#define __VSTR(_x) #_x
#define _VSTR(_x) __VSTR(_x)
#define _VERSION _VSTR(ASTRA_VERSION_MAJOR) "." \
                 _VSTR(ASTRA_VERSION_MINOR)

#ifdef DEBUG
#   define _VDEBUG " debug"
#else
#   define _VDEBUG
#endif

#define ASTRA_VERSION_STR _VERSION _VDEBUG

#endif /* _ASC_BASE_H_ */
