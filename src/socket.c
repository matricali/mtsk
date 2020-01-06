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

#ifdef DEBUG_RAW_PACKETS
#include "hex.h"
#endif

void mtsk_socket_write(int sockfd, const void *src, size_t len)
{
#ifdef DEBUG_RAW_PACKETS
	printf("Sending %zu bytes...\n", len);
	hex_dump(src, len);
#endif
	send(sockfd, src, len, 0);
}

ssize_t mtsk_socket_read(int sockfd, void *dst, size_t len)
{
	ssize_t ret = recv(sockfd, dst, len, 0);

	if (ret < 0) {
		perror("recv");
		return ret;
	}

#ifdef DEBUG_RAW_PACKETS
	printf("Received %zu bytes...\n", ret);
	hex_dump(dst, ret);
#endif

	return ret;
}

int mtsk_socket_connect(uint32_t ip, uint16_t port, uint32_t timeout)
{
	struct sockaddr_in addr;
	int sockfd, ret;
	fd_set fdset;

	sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	fcntl(sockfd, F_SETFL, O_NONBLOCK);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ip;

	ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

	FD_ZERO(&fdset);
	FD_SET(sockfd, &fdset);

	/* Connection timeout */
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = timeout;

	if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1) {
		int so_error;
		socklen_t len = sizeof so_error;

		getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
		if (so_error != 0) {
			close(sockfd);
			sockfd = 0;
			return -1; // Connection refused
		}
	} else {
		close(sockfd);
		sockfd = 0;
		return -2; // Connection timeout
	}

	/* Set to blocking mode again... */
	if ((ret = fcntl(sockfd, F_GETFL, NULL)) < 0) {
		close(sockfd);
		sockfd = 0;
		return -3; // EFCNTL;
	}
	long arg = 0;
	arg &= (~O_NONBLOCK);
	if ((ret = fcntl(sockfd, F_SETFL, arg)) < 0) {
		close(sockfd);
		sockfd = 0;
		return -4; // EFCNTL
	}

	return sockfd;
}
