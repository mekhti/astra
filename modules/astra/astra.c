/*
 * Astra Module: Base
 * http://cesbo.com/astra
 *
 * Copyright (C) 2012-2015, Andrey Dyldin <and@cesbo.com>
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

/*
 * Set of the astra methods and variables for lua
 *
 * Variables:
 *      astra.version
 *                  - string, astra version string
 *      astra.debug - boolean, is a debug version
 *
 * Methods:
 *      astra.info()
 *                  - print information about modules
 *      astra.abort()
 *                  - abort execution
 *      astra.exit()
 *                  - normal exit from astra
 */

#include <astra.h>
#include <modules.h>

static int _astra_abort(lua_State *L)
{
    __uarg(L);
    asc_abort();
    return 0;
}

static int _astra_info(lua_State *L)
{
    lua_newtable(L);

    // System
    lua_newtable(L);

    lua_pushstring(L, ASTRA_VERSION_STR);
    lua_setfield(L, -2, "version");

    lua_pushstring(L, APP_OS);
    lua_setfield(L, -2, "os");

    lua_pushstring(L, LUA_VERSION_MAJOR "." LUA_VERSION_MINOR "." LUA_VERSION_RELEASE);
    lua_setfield(L, -2, "lua");

#ifdef APP_SSE
    lua_pushboolean(L, true);
#else
    lua_pushboolean(L, false);
#endif
    lua_setfield(L, -2, "sse");

#if defined(__i386__) || defined(__x86_64__)
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__ (  "cpuid"
                          : "=a" (eax)
                          , "=b" (ebx)
                          , "=c" (ecx)
                          , "=d" (edx)
                          : "a"  (1));

    char cpuid[128];

#   if defined(__i386__)
    const int bits = 32;
#   else
    const int bits = 64;
#   endif

    sprintf(cpuid, "x86 %dbit 0x%08X 0x%08X 0x%08X 0x%08X", bits, eax, ebx, ecx, edx);
    lua_pushstring(L, cpuid);
    lua_setfield(L, -2, "cpu");

#elif defined(__arm__)
    lua_pushstring(L, "arm");
    lua_setfield(L, -2, "cpu");

#elif defined(__mips__)
    lua_pushstring(L, "mips");
    lua_setfield(L, -2, "cpu");

#else
    lua_pushstring(L, "unknown");
    lua_setfield(L, -2, "cpu");

#endif

#if defined(WITH_POLL)
    lua_pushstring(L, "poll");
#elif defined(WITH_SELECT)
    lua_pushstring(L, "select");
#elif defined(WITH_KQUEUE)
    lua_pushstring(L, "kqueue");
#elif defined(WITH_EPOLL)
    lua_pushstring(L, "epoll");
#else
#   error "event"
#endif
    lua_setfield(L, -2, "event");

    lua_setfield(L, -2, "system");

    lua_newtable(L);
    for(unsigned int i = 0; i < ASC_ARRAY_SIZE(asc_modules); ++i)
    {
        const asc_module_t *m = asc_modules[i];
        if(m->name)
        {
            const int item_count = luaL_len(lua, -1) + 1;
            lua_pushinteger(lua, item_count);
            lua_pushstring(L, m->name());
            lua_settable(lua, -3);
        }
    }
    lua_setfield(L, -2, "modules");

    return 1;
}

static int __module_open(lua_State *L)
{
    static luaL_Reg astra_api[] =
    {
        { "abort", _astra_abort },
        { "info", _astra_info },
        { NULL, NULL }
    };

    luaL_newlib(L, astra_api);

    lua_pushboolean(lua,
#ifdef DEBUG
                    1
#else
                    0
#endif
                    );

    lua_setfield(lua, -2, "debug");

    lua_pushstring(lua, ASTRA_VERSION_STR);
    lua_setfield(lua, -2, "version");

    lua_setglobal(L, "astra");

    return 1;
}

const asc_module_t asc_module_astra =
{
    .open = __module_open,
    .name = NULL,
};
