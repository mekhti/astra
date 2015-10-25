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

#ifndef _ASC_RAND_H_
#define _ASC_RAND_H_ 1

#include "base.h"

void asc_srand(void);

void random_key(uint8_t *buffer, size_t size);

#endif /* _ASC_RAND_H_ */
