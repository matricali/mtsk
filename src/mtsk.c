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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "hex.h"
#include "md5.h"
#include "socket.h"

unsigned char pkt_login[] = { 0x06, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x00 };
unsigned char pkt_login_rpl_1[] = { 0x05, 0x21, 0x64, 0x6f, 0x6e, 0x65, 0x25 };
unsigned char pkt_login_rpl_2[] = { 0x3d, 0x72, 0x65, 0x74, 0x3d };
unsigned char pkt_done[] = { 0x05, 0x21, 0x64, 0x6f, 0x6e, 0x65, 0x00 };

int mtsk_routeros_command_login(int sockfd, const char *username,
				const char *password)
{
	char buf[1024] = { 0 };
	unsigned char bdata[16] = { 0 };
	unsigned char digest[16];
	int nbytes = 0;

	mtsk_socket_write(sockfd, &pkt_login, 8);
	nbytes = mtsk_socket_read(sockfd, &buf, 1024);

	if (nbytes < 45)
		return -1;

	if (strncmp((const char *)pkt_login_rpl_1, buf, 7) != 0)
		return -2;

	if (strncmp((const char *)pkt_login_rpl_2, &buf[7], 5) != 0)
		return -3;

	hex_to_bin(&buf[12], 32, bdata);

	printf("-------CHALLENGE-------\n");
	hex_dump(&bdata[0], 16);
	printf("-----------------------\n");

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, "\x00", 1);
	MD5_Update(&ctx, password, strlen(password));
	MD5_Update(&ctx, &bdata, 16);
	MD5_Final(digest, &ctx);

	size_t username_len = strlen(username);
	char pkt[100] = { 0x06, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0 };
	pkt[7] = 6 + username_len;
	strncpy(&pkt[8], "=name=", 6);
	strncpy(&pkt[14], username, username_len);
	pkt[14 + username_len] = 0x2c; // 44
	strncpy(&pkt[15 + username_len], "=response=00", 12);
	hex_from_bin(digest, 16, &pkt[27 + username_len]);

	int final_len = 27 + username_len + 32;
	pkt[final_len++] = 0;

	mtsk_socket_write(sockfd, &pkt, final_len);

	nbytes = mtsk_socket_read(sockfd, &buf, 1024);

	if (nbytes < 7)
		return -4;

	if (strncmp((const char *)pkt_done, buf, 7) != 0)
		return -5;

	return 0;
}

int main(int argc, char **argv)
{
	puts("mtsk - MikroTik RouterOS API bruteforce v0.1");
	puts("https://github.com/matricali/mtsk");
	puts("");

	if (argc < 5) {
		printf("Invalid parameters!\n"
		       "usage: %s TARGET PORT USERNAME PASSWORD\n\n",
		       argv[0]);
		exit(EXIT_FAILURE);
	}

	char *target = NULL;
	uint16_t port = 8728;
	char *username = "admin";
	char *password = "";

	target = strdup(argv[1]);
	port = atoi(argv[2]);
	username = strdup(argv[3]);
	password = strdup(argv[4]);

	printf("Probing %s...\n", target);

	int sockfd = mtsk_socket_connect(inet_addr(target), port, 500000);

	if (sockfd > 0) {
		int ret =
			mtsk_routeros_command_login(sockfd, username, password);
		if (ret == 0) {
			puts("Login successful!");
			close(sockfd);
			exit(EXIT_SUCCESS);
		} else {
			puts("Cannot login.");
		}
	}

	close(sockfd);

	return EXIT_FAILURE;
}
