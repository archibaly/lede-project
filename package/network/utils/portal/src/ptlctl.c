/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id: ptlctl.c 901 2006-01-17 18:58:13Z mina $ */
/** @file ptlctl.c
    @brief Monitoring and control of portal, client part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    trivially modified for portal
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include "ptlctl.h"


/* N.B. this is ptlctl.h s_config, not conf.h s_config */
s_config config;

static void usage(void);
static void init_config(void);
static void parse_commandline(int, char **);
static int connect_to_server(const char[]);
static int send_request(int, const char[]);
static void ptlctl_action(const char[], const char[], const char[]);
static void ptlctl_print(const char[]);
static void ptlctl_status(void);
static void ptlctl_clients(void);
static void ptlctl_json(void);
static void ptlctl_stop(void);
static void ptlctl_block(void);
static void ptlctl_unblock(void);
static void ptlctl_allow(void);
static void ptlctl_unallow(void);
static void ptlctl_trust(void);
static void ptlctl_untrust(void);
static void ptlctl_auth(void);
static void ptlctl_deauth(void);
static void ptlctl_loglevel(void);
static void ptlctl_username(void);
static void ptlctl_password(void);

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when ptlctl is run with -h or with an unknown option
 */
static void
usage(void)
{
	printf("Usage: ptlctl [options] command [arguments]\n");
	printf("\n");
	printf("options:\n");
	printf("  -s <path>           Path to the socket\n");
	printf("  -h                  Print usage\n");
	printf("\n");
	printf("commands:\n");
	printf("  status              View the status of portal\n");
	printf("  clients             Display machine-readable client list\n");
	printf("  json             	  Display machine-readable client list in json format\n");
	printf("  stop                Stop the running portal\n");
	printf("  auth mac|ip|token   Authenticate user with specified mac, ip or token\n");
	printf("  deauth mac|ip|token Deauthenticate user with specified mac, ip or token\n");
	printf("  block mac           Block the given MAC address\n");
	printf("  unblock mac         Unblock the given MAC address\n");
	printf("  allow mac           Allow the given MAC address\n");
	printf("  unallow mac         Unallow the given MAC address\n");
	printf("  trust mac           Trust the given MAC address\n");
	printf("  untrust mac         Untrust the given MAC address\n");
	printf("  loglevel n          Set logging level to n\n");
	printf("  password pass       Set gateway password\n");
	printf("  username name       Set gateway username\n");
	printf("\n");
}

/** @internal
 *
 * Init default values in config struct
 */
static void
init_config(void)
{
	config.socket = strdup(DEFAULT_SOCK);
	config.command = NDSCTL_UNDEF;
}

/** @internal
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void
parse_commandline(int argc, char **argv)
{
	extern int optind;
	int c;

	while (-1 != (c = getopt(argc, argv, "s:h"))) {
		switch(c) {
		case 'h':
			usage();
			exit(1);
			break;

		case 's':
			if (optarg) {
				free(config.socket);
				config.socket = strdup(optarg);
			}
			break;

		default:
			usage();
			exit(1);
			break;
		}
	}

	if ((argc - optind) <= 0) {
		usage();
		exit(1);
	}

	if (strcmp(*(argv + optind), "status") == 0) {
		config.command = NDSCTL_STATUS;
	} else if (strcmp(*(argv + optind), "clients") == 0) {
		config.command = NDSCTL_CLIENTS;
	} else if (strcmp(*(argv + optind), "json") == 0) {
		config.command = NDSCTL_JSON;
	}

	else if (strcmp(*(argv + optind), "stop") == 0) {
		config.command = NDSCTL_STOP;
	} else if (strcmp(*(argv + optind), "block") == 0) {
		config.command = NDSCTL_BLOCK;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify a "
					"MAC address to block\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "unblock") == 0) {
		config.command = NDSCTL_UNBLOCK;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify a "
					"MAC address to unblock\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "allow") == 0) {
		config.command = NDSCTL_ALLOW;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify a "
					"MAC address to allow\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "unallow") == 0) {
		config.command = NDSCTL_UNALLOW;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify a "
					"MAC address to unallow\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "trust") == 0) {
		config.command = NDSCTL_TRUST;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify a "
					"MAC address to trust\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "untrust") == 0) {
		config.command = NDSCTL_UNTRUST;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify a "
					"MAC address to untrust\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "auth") == 0) {
		config.command = NDSCTL_AUTH;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify an IP "
					"address to auth\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "deauth") == 0) {
		config.command = NDSCTL_DEAUTH;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify an IP "
					"or a Mac address to deauth\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "loglevel") == 0) {
		config.command = NDSCTL_LOGLEVEL;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify an integer "
					"loglevel to loglevel\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "password") == 0) {
		config.command = NDSCTL_PASSWORD;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify a password\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else if (strcmp(*(argv + optind), "username") == 0) {
		config.command = NDSCTL_USERNAME;
		if ((argc - (optind + 1)) <= 0) {
			fprintf(stderr, "ptlctl: Error: You must specify a username\n");
			usage();
			exit(1);
		}
		config.param = strdup(*(argv + optind + 1));
	} else {
		fprintf(stderr, "ptlctl: Error: Invalid command \"%s\"\n", *(argv + optind));
		usage();
		exit(1);
	}
}

static int
connect_to_server(const char sock_name[])
{
	int sock;
	struct sockaddr_un	sa_un;

	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un,
				strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		fprintf(stderr, "ptlctl: portal probably not started (Error: %s)\n", strerror(errno));
		exit(1);
	}

	return sock;
}

static int
send_request(int sock, const char request[])
{
	ssize_t	len, written;

	len = 0;
	while (len != strlen(request)) {
		written = write(sock, (request + len), strlen(request) - len);
		if (written == -1) {
			fprintf(stderr, "Write to portal failed: %s\n",
					strerror(errno));
			exit(1);
		}
		len += written;
	}

	return((int)len);
}

/* Perform a ptlctl action, with server response Yes or No.
 * Action given by cmd, followed by config.param.
 * Responses printed to stdout, as formatted by ifyes or ifno.
 * config.param interpolated in format with %s directive if desired.
 */
static void
ptlctl_action(const char cmd[], const char ifyes[], const char ifno[])
{
	int sock;
	char buffer[4096];
	char request[128];
	int len, rlen;

	sock = connect_to_server(config.socket);

	snprintf(request, sizeof(request)-strlen(NDSCTL_TERMINATOR),
			 "%s %s", cmd, config.param);
	strcat(request, NDSCTL_TERMINATOR);

	len = send_request(sock, request);

	len = 0;
	memset(buffer, 0, sizeof(buffer));
	while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
									   (sizeof(buffer) - len))) > 0)) {
		len += rlen;
	}

	if(rlen<0) {
		fprintf(stderr, "ptlctl: Error reading socket: %s\n", strerror(errno));
	}

	if (strcmp(buffer, "Yes") == 0) {
		printf(ifyes, config.param);
	} else if (strcmp(buffer, "No") == 0) {
		printf(ifno, config.param);
	} else {
		fprintf(stderr, "ptlctl: Error: portal sent an abnormal "
				"reply.\n");
	}

	shutdown(sock, 2);
	close(sock);
}

/* Perform a ptlctl action, printing to stdout the server response.
 *  Action given by cmd.
 */
static void
ptlctl_print(const char cmd[])
{
	int sock;
	char buffer[4096];
	char request[32];
	int len;

	sock = connect_to_server(config.socket);

	snprintf(request, sizeof(request)-strlen(NDSCTL_TERMINATOR), "%s", cmd);
	strcat(request, NDSCTL_TERMINATOR);

	len = send_request(sock, request);

	while ((len = read(sock, buffer, sizeof(buffer)-1)) > 0) {
		buffer[len] = '\0';
		printf("%s", buffer);
	}

	if(len<0) {
		fprintf(stderr, "ptlctl: Error reading socket: %s\n", strerror(errno));
	}

	shutdown(sock, 2);
	close(sock);
}

static void
ptlctl_clients(void)
{
	ptlctl_print("clients");
}

static void
ptlctl_json(void)
{
	ptlctl_print("json");
}

static void
ptlctl_status(void)
{
	ptlctl_print("status");
}

static void
ptlctl_stop(void)
{
	ptlctl_print("stop");
}

void
ptlctl_loglevel(void)
{
	ptlctl_action("loglevel",
				  "Log level set to %s.\n",
				  "Failed to set log level to %s.\n");
}

void
ptlctl_password(void)
{
	ptlctl_action("password",
				  "Password set to %s.\n",
				  "Failed to set password to %s.\n");
}

void
ptlctl_username(void)
{
	ptlctl_action("username",
				  "Username set to %s.\n",
				  "Failed to set username to %s.\n");
}

void
ptlctl_deauth(void)
{
	ptlctl_action("deauth",
				  "Client %s deauthenticated.\n",
				  "Client %s not found.\n");
}

void
ptlctl_auth(void)
{
	ptlctl_action("auth",
				  "Client %s authenticated.\n",
				  "Failed to authenticate client %s.\n");
}

void
ptlctl_block(void)
{
	ptlctl_action("block",
				  "MAC %s blocked.\n",
				  "Failed to block MAC %s.\n");
}

void
ptlctl_unblock(void)
{
	ptlctl_action("unblock",
				  "MAC %s unblocked.\n",
				  "Failed to unblock MAC %s.\n");
}

void
ptlctl_allow(void)
{
	ptlctl_action("allow",
				  "MAC %s allowed.\n",
				  "Failed to allow MAC %s.\n");
}

void
ptlctl_unallow(void)
{
	ptlctl_action("unallow",
				  "MAC %s unallowed.\n",
				  "Failed to unallow MAC %s.\n");
}

void
ptlctl_trust(void)
{
	ptlctl_action("trust",
				  "MAC %s trusted.\n",
				  "Failed to trust MAC %s.\n");
}

void
ptlctl_untrust(void)
{
	ptlctl_action("untrust",
				  "MAC %s untrusted.\n",
				  "Failed to untrust MAC %s.\n");
}

int
main(int argc, char **argv)
{
	/* Init configuration */
	init_config();
	parse_commandline(argc, argv);

	switch(config.command) {
	case NDSCTL_STATUS:
		ptlctl_status();
		break;

	case NDSCTL_CLIENTS:
		ptlctl_clients();
		break;

	case NDSCTL_JSON:
		ptlctl_json();
		break;

	case NDSCTL_STOP:
		ptlctl_stop();
		break;

	case NDSCTL_BLOCK:
		ptlctl_block();
		break;

	case NDSCTL_UNBLOCK:
		ptlctl_unblock();
		break;

	case NDSCTL_ALLOW:
		ptlctl_allow();
		break;

	case NDSCTL_UNALLOW:
		ptlctl_unallow();
		break;

	case NDSCTL_TRUST:
		ptlctl_trust();
		break;

	case NDSCTL_UNTRUST:
		ptlctl_untrust();
		break;

	case NDSCTL_AUTH:
		ptlctl_auth();
		break;

	case NDSCTL_DEAUTH:
		ptlctl_deauth();
		break;

	case NDSCTL_LOGLEVEL:
		ptlctl_loglevel();
		break;

	case NDSCTL_PASSWORD:
		ptlctl_password();
		break;

	case NDSCTL_USERNAME:
		ptlctl_username();
		break;

	default:
		/* XXX NEVER REACHED */
		fprintf(stderr, "Unknown opcode: %d\n", config.command);
		exit(1);
		break;
	}
	exit(0);
}
