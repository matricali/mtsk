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

#include <stdio.h>

void hex_to_bin(const char *in, size_t len, unsigned char *out)
{
	static const unsigned char TBL[] = {
		0,  1,	2,  3,	4,  5,	6,  7,	8,  9,	58, 59, 60, 61,
		62, 63, 64, 10, 11, 12, 13, 14, 15, 71, 72, 73, 74, 75,
		76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
		90, 91, 92, 93, 94, 95, 96, 10, 11, 12, 13, 14, 15
	};

	static const unsigned char *LOOKUP = TBL - 48;

	const char *end = in + len;

	while (in < end) {
		*(out) = LOOKUP[*(in++)] << 4;
		*(out++) |= LOOKUP[*(in++)];
	}
}

void hex_from_bin(const unsigned char *in, size_t len, char *out)
{
	static const char CHARS[] = "0123456789abcdef0123456789ABCDEF";

	for (int i = 0; i < len; ++i) {
		*(out++) = CHARS[in[i] >> 4];
		*(out++) = CHARS[in[i] & 0x0f];
	}
}

void hex_dump(const void *in, size_t len)
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < len; ++i) {
		printf("%02X ", ((unsigned char *)in)[i]);
		if (((unsigned char *)in)[i] >= ' ' &&
		    ((unsigned char *)in)[i] <= '~') {
			ascii[i % 16] = ((unsigned char *)in)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == len) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i + 1 == len) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
