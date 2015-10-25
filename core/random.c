/*
 * Astra Core
 * http://cesbo.com/astra
 *
 * Copyright (C) 2015, Andrey Dyldin <and@cesbo.com>
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

#include "random.h"

void asc_srand(void)
{
    unsigned long a = clock();
    unsigned long b = time(NULL);
#ifndef _WIN32
    unsigned long c = getpid();
#else
    unsigned long c = GetCurrentProcessId();
#endif

    a = a - b;  a = a - c;  a = a ^ (c >> 13);
    b = b - c;  b = b - a;  b = b ^ (a << 8);
    c = c - a;  c = c - b;  c = c ^ (b >> 13);
    a = a - b;  a = a - c;  a = a ^ (c >> 12);
    b = b - c;  b = b - a;  b = b ^ (a << 16);
    c = c - a;  c = c - b;  c = c ^ (b >> 5);
    a = a - b;  a = a - c;  a = a ^ (c >> 3);
    b = b - c;  b = b - a;  b = b ^ (a << 10);
    c = c - a;  c = c - b;  c = c ^ (b >> 15);

    srand(c);
}

void random_key(uint8_t *buffer, size_t size)
{
    uint32_t r = 0;
    for(size_t i = 0; i < size; ++i)
    {
        int ii = i % 4;
        if(ii == 0)
            r = (uint32_t)rand();
        buffer[i] = (uint8_t)((r >> (8 * ii)) & 0xFF);
    }
}
