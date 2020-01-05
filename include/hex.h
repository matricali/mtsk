/*
 * This file is part of the mtsk distribution
 * (https://github.com/matricali/mtsk).
 *
 * Copyright (c) 2019 Jorge Matricali.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __MTSK_HEX_H
#define __MTSK_HEX_H

void hex_dump(const void *in, size_t len);

void hex_to_bin(const char *in, size_t len, unsigned char *out);

void hex_from_bin(const unsigned char *in, size_t len, char *out);

#endif /* __MTSK_HEX_H */
