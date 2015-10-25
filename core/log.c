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

#include "log.h"

#ifndef _WIN32
#include <syslog.h>
#endif
#include <stdarg.h>

static struct
{
    bool color;
    bool debug;

    bool sout;

    int fd;
    char *filename;

#ifndef _WIN32
    char *syslog;
#endif
} __log;

#ifndef _WIN32
static int _syslog_type[] = {
    LOG_INFO, LOG_ERR, LOG_WARNING, LOG_DEBUG
};
#endif

__fmt_printf(2, 0)
static void _log(asc_log_type_t type, const char *msg, va_list ap)
{
    size_t message_len = 0;

    string_buffer_t *buffer = string_buffer_alloc();
    string_buffer_addvastring(buffer, msg, ap);

    asc_log_item_t *item = (asc_log_item_t *)malloc(sizeof(asc_log_item_t));
    item->type = type;
    item->timestamp = time(NULL);
    item->message = string_buffer_release(buffer, &message_len);

#ifndef _WIN32
    if(__log.syslog)
        syslog(_syslog_type[type], "%s", item->message);
#endif

    if(__log.sout || __log.fd)
    {
        size_t m_len = 0;
        char timestamp[18];
        struct tm *sct = localtime(&item->timestamp);
        m_len = strftime(timestamp, sizeof(timestamp), "%b %d %X: ", sct);

        const char *m_type = NULL;

        static const char _log_info[] = "INFO: ";
        static const char _log_error[] = "ERROR: ";
        static const char _log_warning[] = "WARNING: ";
        static const char _log_debug[] = "DEBUG: ";

        const char *m_color = NULL;

        static const char _log_color_red[] = "\x1b[31m";
        static const char _log_color_green[] = "\x1b[32m";
        static const char _log_color_yellow[] = "\x1b[33m";

        switch(type)
        {
            case ASC_LOG_INFO:
            {
                m_type = _log_info;
                m_len += sizeof(_log_info) - 1;
                m_color = _log_color_green;
                break;
            }
            case ASC_LOG_ERROR:
            {
                m_type = _log_error;
                m_len += sizeof(_log_error) - 1;
                m_color = _log_color_red;
                break;
            }
            case ASC_LOG_WARNING:
            {
                m_type = _log_warning;
                m_len += sizeof(_log_warning) - 1;
                m_color = _log_color_yellow;
                break;
            }
            case ASC_LOG_DEBUG:
            {
                m_type = _log_debug;
                m_len += sizeof(_log_debug) - 1;
                break;
            }
        }

        m_len += message_len + 1 /* "\n" */ ;

#define NO_RETURN(_fn) { const int __r = _fn; __uarg(__r); };

#ifndef _WIN32
        if(__log.color && m_color && isatty(STDOUT_FILENO))
        {
            m_len += 9;

            char *m = (char *)malloc(m_len + 1);
            sprintf(m, "%s%s%s%s\n\x1b[0m", m_color, timestamp, m_type, item->message);

            if(__log.sout)
            {
                NO_RETURN(write(STDOUT_FILENO, m, m_len));
            }

            if(__log.fd)
            {
                NO_RETURN(write(__log.fd, &m[5], m_len - 9));
            }

            free(m);
        }
        else
#endif
        {
            char *m = (char *)malloc(m_len + 1);
            sprintf(m, "%s%s%s\n", timestamp, m_type, item->message);

            if(__log.sout)
            {
                NO_RETURN(write(STDOUT_FILENO, m, m_len));
            }

            if(__log.fd)
            {
                NO_RETURN(write(__log.fd, m, m_len));
            }

            free(m);
        }
    }
}

void asc_log_info(const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    _log(ASC_LOG_INFO, msg, ap);
    va_end(ap);
}

void asc_log_error(const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    _log(ASC_LOG_ERROR, msg, ap);
    va_end(ap);
}

void asc_log_warning(const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    _log(ASC_LOG_WARNING, msg, ap);
    va_end(ap);
}

void asc_log_debug(const char *msg, ...)
{
    if(!__log.debug)
        return;

    va_list ap;
    va_start(ap, msg);
    _log(ASC_LOG_DEBUG, msg, ap);
    va_end(ap);
}

bool asc_log_is_debug(void)
{
    return __log.debug;
}

void asc_log_core_init(void)
{
    memset(&__log, 0, sizeof(__log));
    __log.sout = true;
}

void asc_log_core_destroy(void)
{
    if(__log.fd != 1)
        close(__log.fd);

#ifndef _WIN32
    if(__log.syslog)
    {
        closelog();
        free(__log.syslog);
    }
#endif

    if(__log.filename)
        free(__log.filename);

    memset(&__log, 0, sizeof(__log));
}

void asc_log_hup(void)
{
    if(__log.fd > 1)
    {
        close(__log.fd);
        __log.fd = 0;
    }

    if(!__log.filename)
        return;

    __log.fd = open(__log.filename, O_WRONLY | O_CREAT | O_APPEND,
#ifndef _WIN32
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#else
                    S_IRUSR | S_IWUSR);
#endif

    if(__log.fd == -1)
    {
        __log.fd = 0;
        __log.sout = true;
        asc_log_error("[core/log] failed to open %s (%s)", __log.filename, strerror(errno));
    }
}

void asc_log_set_stdout(bool val)
{
    __log.sout = val;
}

void asc_log_set_debug(bool val)
{
    __log.debug = val;
}

void asc_log_set_color(bool val)
{
    __log.color = val;
}

void asc_log_set_file(const char *val)
{
    if(__log.filename)
    {
        free(__log.filename);
        __log.filename = NULL;
    }

    if(val)
        __log.filename = strdup(val);

    asc_log_hup();
}

#ifndef _WIN32
void asc_log_set_syslog(const char *val)
{
    if(__log.syslog)
    {
        closelog();
        free(__log.syslog);
        __log.syslog = NULL;
    }

    if(!val)
        return;

    __log.syslog = strdup(val);
    openlog(__log.syslog, LOG_PID | LOG_CONS, LOG_USER);
}
#endif
