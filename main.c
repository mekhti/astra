/*
 * Astra Main App
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

#include <astra.h>

#ifndef _WIN32
#   include <signal.h>
#endif

#include <setjmp.h>

jmp_buf main_loop;

bool is_sighup = false;

static int lua_astra_exit(lua_State *L)
{
    __uarg(L);
#ifndef _WIN32
    longjmp(main_loop, 1);
#else
    exit(0);
#endif
    return 0;
}

static int lua_astra_reload(lua_State *L)
{
    __uarg(L);
    longjmp(main_loop, 2);
    return 0;
}

#ifndef _WIN32
static void signal_handler(int signum)
{
    switch(signum)
    {
        case SIGHUP:
            asc_log_hup();
            is_sighup = true;
            return;
        case SIGPIPE:
            return;
        default:
            lua_astra_exit(NULL);
    }
}
#else
static bool WINAPI signal_handler(DWORD signum)
{
    switch(signum)
    {
        case CTRL_C_EVENT:
            lua_astra_exit(NULL);
            break;
        case CTRL_BREAK_EVENT:
            lua_astra_exit(NULL);
            break;
        default:
            break;
    }
    return true;
}
#endif

int main(int argc, const char **argv)
{
    static const char *arg_log = NULL;
    static bool arg_no_stdout = false;
    static bool arg_debug = false;
    static bool arg_color = false;

#ifndef _WIN32
    static const char *arg_syslog = NULL;
    static bool arg_daemon = false;
    static const char *arg_pid = NULL;
#endif

    for(int i = 1; i < argc; ++i)
    {
        const char *a = argv[i];

        if(!strcmp(a, "--log") && argc > i + 1)
        {
            arg_log = argv[i + 1];
            i += 1;
        }
        else if(!strcmp(a, "--no-stdout"))
        {
            arg_no_stdout = true;
        }
        else if(!strcmp(a, "--debug"))
        {
            arg_debug = true;
        }
        else if(!strcmp(a, "--color"))
        {
            arg_color = true;
        }
        else if(!strcmp(a, "-v") || !strcmp(a, "--version"))
        {
            printf("Astra v." ASTRA_VERSION_STR "\n");
            return 0;
        }

#ifndef _WIN32
        else if(!strcmp(a, "--syslog") && argc > i + 1)
        {
            arg_syslog = argv[i + 1];
            i += 1;
        }
        else if(!strcmp(a, "--daemon"))
        {
            arg_daemon = true;
        }
        else if(!strcmp(a, "--pid") && argc > i + 1)
        {
            arg_pid = argv[i + 1];
            i += 1;
        }
#endif
    }

#ifndef _WIN32
    pid_t pid;

    if(arg_daemon)
    {
        arg_no_stdout = true;

        pid = fork();
        if(pid == -1)
        {
            printf("daemon: fork() error [%s]\n", strerror(errno));
            return 1;
        }

        if(pid != 0)
            return 0;

        pid = setsid();
        if(pid == -1)
        {
            printf("daemon: setsid() error [%s]\n", strerror(errno));
            return 1;
        }
    }
    else
    {
        pid = getpid();
    }

    if(arg_pid)
    {
        if(access(arg_pid, W_OK) == 0)
            unlink(arg_pid);

        static char tmp_pidfile[256];
        snprintf(tmp_pidfile, sizeof(tmp_pidfile), "%s.XXXXXX", arg_pid);
        int fd = mkstemp(tmp_pidfile);
        if(fd == -1)
        {
            printf("pid: mkstemp() error [%s]\n", strerror(errno));
            return 1;
        }

        static char pid_text[8];
        int size = snprintf(pid_text, sizeof(pid_text), "%d\n", pid);
        if(write(fd, pid_text, size) == -1)
        {
            printf("pid: write() error [%s]\n", strerror(errno));
            close(fd);
            if(access(tmp_pidfile, W_OK) == 0)
                unlink(tmp_pidfile);
            return 1;
        }
        fchmod(fd, 0644);
        close(fd);

        const int link_ret = link(tmp_pidfile, arg_pid);
        unlink(tmp_pidfile);
        if(link_ret == -1)
        {
            printf("pid: link() error [%s]\n", strerror(errno));
            return 1;
        }
    }
#endif

#ifndef _WIN32
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGQUIT, signal_handler);
#else
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)signal_handler, true);
#endif

astra_reload_entry:

    /* init */
    asc_srand();
    asc_log_core_init();
    asc_thread_core_init();
    asc_timer_core_init();
    asc_socket_core_init();
    asc_event_core_init();
    asc_lua_core_init(argc, argv);

    lua_getglobal(lua, "astra");
    if(lua_istable(lua, -1))
    {
        lua_pushcfunction(lua, lua_astra_exit);
        lua_setfield(lua, -2, "exit");

        lua_pushcfunction(lua, lua_astra_reload);
        lua_setfield(lua, -2, "reload");
    }
    lua_pop(lua, 1); // astra

    if(arg_log)
        asc_log_set_file(arg_log);
    if(arg_no_stdout)
        asc_log_set_stdout(false);
    if(arg_debug)
        asc_log_set_debug(true);
    if(arg_color)
        asc_log_set_color(true);

#ifndef _WIN32
    if(arg_syslog)
        asc_log_set_syslog(arg_syslog);
#endif

    asc_log_info("[main] Starting Astra v." ASTRA_VERSION_STR);

    /* start */
    const int main_loop_status = setjmp(main_loop);
    if(main_loop_status == 0)
    {
        uint64_t current_time = asc_utime();
        uint64_t gc_check_timeout = current_time;

        while(true)
        {
            bool idle = true;

            if(!asc_event_core_loop())
                idle = false;
            if(!asc_timer_core_loop())
                idle = false;
            if(!asc_thread_core_loop())
                idle = false;

            if(is_sighup)
            {
                is_sighup = false;

                lua_getglobal(lua, "on_sighup");
                if(lua_isfunction(lua, -1))
                {
                    lua_call(lua, 0, 0);
                    idle = false;
                }
                else
                    lua_pop(lua, 1);
            }

            if(idle)
            {
                current_time = asc_utime();
                if(gc_check_timeout + 1 * 1000 * 1000 < current_time)
                {
                    gc_check_timeout = current_time;
                    lua_gc(lua, LUA_GCCOLLECT, 0);
                }

                asc_usleep(1000);
            }
        }
    }

    /* destroy */
    asc_lua_core_destroy();
    asc_event_core_destroy();
    asc_socket_core_destroy();
    asc_timer_core_destroy();
    asc_thread_core_destroy();

    asc_log_info("[main] %s", (main_loop_status == 2) ? "Reload" : "Exit");
    asc_log_core_destroy();

    if(main_loop_status == 2)
        goto astra_reload_entry;

#ifndef _WIN32
    if(arg_pid)
    {
        if(access(arg_pid, W_OK) == 0)
            unlink(arg_pid);
    }
#endif

    return 0;
}
