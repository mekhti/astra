/*
 * Astra Core
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

#include "assert.h"
#include "lua.h"
#include "log.h"
#include <modules.h>

lua_State *lua = NULL;

static int asc_panic(lua_State *L)
{
    asc_log_set_stdout(true);
    asc_log_error("[main] error in call to Lua API. %s", lua_tostring(L, -1));
    asc_abort();
    return 0;
}

void asc_lua_core_init(int argc, const char **argv)
{
    lua = luaL_newstate();
    asc_assert(lua != NULL, "luaL_newstate()");
    lua_atpanic(lua, &asc_panic);
    luaL_openlibs(lua);

    lua_pushstring(lua, "Astra v." ASTRA_VERSION_STR " [" LUA_VERSION "]" );
    lua_setglobal(lua, "_VERSION");

    /* change package.path */
    lua_getglobal(lua, "package");

#ifndef _WIN32
#   define ASC_PATH_SEP "/"
#else
#   define ASC_PATH_SEP "\\"
#endif

    lua_pushfstring(lua, "." ASC_PATH_SEP "?.lua");
    lua_setfield(lua, -2, "path");
    lua_pushstring(lua, "");
    lua_setfield(lua, -2, "cpath");
    lua_pop(lua, 1);

    /* argv table */
    lua_newtable(lua);
    for(int i = 1; i < argc; ++i)
    {
        lua_pushinteger(lua, i);
        lua_pushstring(lua, argv[i]);
        lua_settable(lua, -3);
    }
    lua_setglobal(lua, "argv");

    /* load modules */
    for(unsigned int i = 0; i < ASC_ARRAY_SIZE(asc_modules); i++)
        asc_modules[i]->open(lua);
}

static int __collectgarbage(lua_State *L)
{
    __uarg(L);
    return 0;
}

void asc_lua_core_destroy(void)
{
    lua_pushcfunction(lua, __collectgarbage);
    lua_setglobal(lua, "collectgarbage");
    ASC_FREE(lua, lua_close);
}

void asc_abort(void)
{
    asc_log_set_stdout(true);
    asc_log_error("[main] abort execution");
    if(lua)
    {
        lua_Debug ar;
        int level = 1;
        while(lua_getstack(lua, level, &ar))
        {
            lua_getinfo(lua, "nSl", &ar);
            asc_log_error("%d: %s:%d -- %s [%s]",
                level, ar.short_src, ar.currentline, (ar.name) ? ar.name : "<unknown>", ar.what);
            ++level;
        }
    }

    abort();
}

bool module_option_number(const char *name, int *number)
{
    if(lua_type(lua, MODULE_OPTIONS_IDX) != LUA_TTABLE)
        return false;

    lua_getfield(lua, MODULE_OPTIONS_IDX, name);
    const int type = lua_type(lua, -1);
    bool result = false;

    if(type == LUA_TNUMBER)
    {
        *number = lua_tonumber(lua, -1);
        result = true;
    }
    else if(type == LUA_TSTRING)
    {
        const char *str = lua_tostring(lua, -1);
        *number = atoi(str);
        result = true;
    }
    else if(type == LUA_TBOOLEAN)
    {
        *number = lua_toboolean(lua, -1);
        result = true;
    }

    lua_pop(lua, 1);
    return result;
}

bool module_option_string(const char *name, const char **string, size_t *length)
{
    if(lua_type(lua, MODULE_OPTIONS_IDX) != LUA_TTABLE)
        return false;

    lua_getfield(lua, MODULE_OPTIONS_IDX, name);
    const int type = lua_type(lua, -1);
    bool result = false;

    if(type == LUA_TSTRING)
    {
        if(length)
            *length = luaL_len(lua, -1);
        *string = lua_tostring(lua, -1);
        result = true;
    }


    lua_pop(lua, 1);
    return result;
}

bool module_option_boolean(const char *name, bool *boolean)
{
    if(lua_type(lua, MODULE_OPTIONS_IDX) != LUA_TTABLE)
        return false;

    lua_getfield(lua, MODULE_OPTIONS_IDX, name);
    const int type = lua_type(lua, -1);
    bool result = false;

    if(type == LUA_TNUMBER)
    {
        *boolean = (lua_tonumber(lua, -1) != 0) ? true : false;
        result = true;
    }
    else if(type == LUA_TSTRING)
    {
        const char *str = lua_tostring(lua, -1);
        *boolean = (!strcmp(str, "true") || !strcmp(str, "on") || !strcmp(str, "1"));
        result = true;
    }
    else if(type == LUA_TBOOLEAN)
    {
        *boolean = lua_toboolean(lua, -1);
        result = true;
    }

    lua_pop(lua, 1);
    return result;
}
