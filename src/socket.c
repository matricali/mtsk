/*
 * This file is part of the mtsk distribution
 * (https://github.com/matricali/zokete).
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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "hex.h"

void mtsk_socket_write(int sockfd, const void *src, size_t len)
{
	printf("Sending %zu bytes...\n", len);
	hex_dump(src, len);
	send(sockfd, src, len, 0);
}

ssize_t mtsk_socket_read(int sockfd, void *dst, size_t len)
{
	ssize_t ret = recv(sockfd, dst, len, 0);

	if (ret < 0) {
		perror("recv");
		return ret;
	}

	printf("Received %zu bytes...\n", ret);
	hex_dump(dst, ret);

	return ret;
}

int mtsk_socket_connect(uint32_t ip, uint16_t port, uint32_t timeout)
{
	struct sockaddr_in addr;
	int sockfd, ret;

	sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ip;

	ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

	if (ret < 0) {
		perror("connect");
		return -1;
	}

	puts("Connected...");
	return sockfd;
}
