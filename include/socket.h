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

#ifndef __MTSK_SOCKET_H
#define __MTSK_SOCKET_H

void mtsk_socket_write(int sockfd, const void *src, size_t len);

ssize_t mtsk_socket_read(int sockfd, void *dst, size_t len);

int mtsk_socket_connect(uint32_t ip, uint16_t port, uint32_t timeout);

#endif /* __MTSK_SOCKET_H */
