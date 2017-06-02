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

/* $Id: ptlctl_thread.c 969 2006-02-23 17:09:32Z papril $ */
/** @file ptlctl_thread.c
    @brief Monitoring and control of nodogsplash, server part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    trivially modified for nodogsplash
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
#include <signal.h>
#include <errno.h>

#include "common.h"
#include "httpd.h"
#include "util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "safe.h"
#include "client_list.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "gateway.h"

#include "ptlctl_thread.h"

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;
extern	pthread_mutex_t	config_mutex;

static void *thread_ptlctl_handler(void *);
static void ptlctl_status(int);
static void ptlctl_clients(int);
static void ptlctl_json(int);
static void ptlctl_stop(int);
static void ptlctl_block(int, char *);
static void ptlctl_unblock(int, char *);
static void ptlctl_allow(int, char *);
static void ptlctl_unallow(int, char *);
static void ptlctl_trust(int, char *);
static void ptlctl_untrust(int, char *);
static void ptlctl_auth(int, char *);
static void ptlctl_deauth(int, char *);
static void ptlctl_loglevel(int, char *);
static void ptlctl_password(int, char *);
static void ptlctl_username(int, char *);

/** Launches a thread that monitors the control socket for request
@param arg Must contain a pointer to a string containing the Unix domain socket to open
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void*
thread_ptlctl(void *arg)
{
	int	sock,    fd;
	char	*sock_name;
	struct 	sockaddr_un	sa_un;
	int result;
	pthread_t	tid;
	socklen_t len;

	debug(LOG_DEBUG, "Starting ptlctl.");

	memset(&sa_un, 0, sizeof(sa_un));
	sock_name = (char *)arg;
	debug(LOG_DEBUG, "Socket name: %s", sock_name);

	if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
		/* TODO: Die handler with logging.... */
		debug(LOG_ERR, "PTLCTL socket name too long");
		exit(1);
	}

	debug(LOG_DEBUG, "Creating socket");
	sock = socket(PF_UNIX, SOCK_STREAM, 0);

	debug(LOG_DEBUG, "Got server socket %d", sock);

	/* If it exists, delete... Not the cleanest way to deal. */
	unlink(sock_name);

	debug(LOG_DEBUG, "Filling sockaddr_un");
	strcpy(sa_un.sun_path, sock_name); /* XXX No size check because we
				      * check a few lines before. */
	sa_un.sun_family = AF_UNIX;

	debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path,
		  strlen(sock_name));

	/* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
	if (bind(sock, (struct sockaddr *)&sa_un, strlen(sock_name)
			 + sizeof(sa_un.sun_family))) {
		debug(LOG_ERR, "Could not bind control socket: %s",
			  strerror(errno));
		pthread_exit(NULL);
	}

	if (listen(sock, 5)) {
		debug(LOG_ERR, "Could not listen on control socket: %s",
			  strerror(errno));
		pthread_exit(NULL);
	}

	while (1) {

		memset(&sa_un, 0, sizeof(sa_un));
		len = (socklen_t) sizeof(sa_un); /* <<< ADDED BY DPLACKO */
		if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1) {
			debug(LOG_ERR, "Accept failed on control socket: %s",
				  strerror(errno));
		} else {
			debug(LOG_DEBUG, "Accepted connection on ptlctl socket %d (%s)", fd, sa_un.sun_path);
			result = pthread_create(&tid, NULL, &thread_ptlctl_handler, (void *) (size_t) fd);
			if (result != 0) {
				debug(LOG_ERR, "FATAL: Failed to create a new thread (ptlctl handler) - exiting");
				termination_handler(0);
			}
			pthread_detach(tid);
		}
	}

	return NULL;
}


static void *
thread_ptlctl_handler(void *arg)
{
	int fd, done, i;
	char request[MAX_BUF];
	ssize_t read_bytes, len;

	debug(LOG_DEBUG, "Entering thread_ptlctl_handler....");

	fd = (int) (size_t) arg;

	debug(LOG_DEBUG, "Read bytes and stuff from %d", fd);

	/* Init variables */
	read_bytes = 0;
	done = 0;
	memset(request, 0, sizeof(request));

	/* Read.... */
	while (!done && read_bytes < (sizeof(request) - 1)) {
		len = read(fd, request + read_bytes, sizeof(request) - read_bytes);

		/* Have we gotten a command yet? */
		for (i = read_bytes; i < (read_bytes + len); i++) {
			if (request[i] == '\r' || request[i] == '\n') {
				request[i] = '\0';
				done = 1;
			}
		}

		/* Increment position */
		read_bytes += len;
	}

	debug(LOG_DEBUG, "ptlctl request received: [%s]", request);

	if (strncmp(request, "status", 6) == 0) {
		ptlctl_status(fd);
	} else if (strncmp(request, "clients", 7) == 0) {
		ptlctl_clients(fd);
	} else if (strncmp(request, "json", 4) == 0) {
		ptlctl_json(fd);
	} else if (strncmp(request, "stop", 4) == 0) {
		ptlctl_stop(fd);
	} else if (strncmp(request, "block", 5) == 0) {
		ptlctl_block(fd, (request + 6));
	} else if (strncmp(request, "unblock", 7) == 0) {
		ptlctl_unblock(fd, (request + 8));
	} else if (strncmp(request, "allow", 5) == 0) {
		ptlctl_allow(fd, (request + 6));
	} else if (strncmp(request, "unallow", 7) == 0) {
		ptlctl_unallow(fd, (request + 8));
	} else if (strncmp(request, "trust", 5) == 0) {
		ptlctl_trust(fd, (request + 6));
	} else if (strncmp(request, "untrust", 7) == 0) {
		ptlctl_untrust(fd, (request + 8));
	} else if (strncmp(request, "auth", 4) == 0) {
		ptlctl_auth(fd, (request + 5));
	} else if (strncmp(request, "deauth", 6) == 0) {
		ptlctl_deauth(fd, (request + 7));
	} else if (strncmp(request, "loglevel", 8) == 0) {
		ptlctl_loglevel(fd, (request + 9));
	} else if (strncmp(request, "password", 8) == 0) {
		ptlctl_password(fd, (request + 9));
	} else if (strncmp(request, "username", 8) == 0) {
		ptlctl_username(fd, (request + 9));
	}

	if (!done) {
		debug(LOG_ERR, "Invalid ptlctl request.");
		shutdown(fd, 2);
		close(fd);
		pthread_exit(NULL);
	}

	debug(LOG_DEBUG, "ptlctl request processed: [%s]", request);

	shutdown(fd, 2);
	close(fd);
	debug(LOG_DEBUG, "Exiting thread_ptlctl_handler....");

	return NULL;
}

static void
ptlctl_status(int fd)
{
	char *status = NULL;
	int len = 0;

	status = get_status_text();
	len = strlen(status);

	write(fd, status, len);

	free(status);
}

static void
ptlctl_clients(int fd)
{
	char * status = NULL;
	int len = 0;

	status = get_clients_text();
	len = strlen(status);

	write(fd, status, len);

	free(status);
}

static void
ptlctl_json(int fd)
{
	char * status = NULL;
	int len = 0;

	status = get_clients_json();
	len = strlen(status);

	write(fd, status, len);

	free(status);
}

/** A bit of an hack, self kills.... */
static void
ptlctl_stop(int fd)
{
	pid_t	pid;

	pid = getpid();
	kill(pid, SIGINT);
}

static void
ptlctl_auth(int fd, char *arg)
{
	t_client	*client;
	char *ip, *mac;
	debug(LOG_DEBUG, "Entering ptlctl_auth...");

	LOCK_CLIENT_LIST();
	/* arg can be IP or MAC address of client */
	debug(LOG_DEBUG, "Argument: %s (@%x)", arg, arg);

	/* We get the client or return... */
	if ((client = client_list_find_by_ip(arg)) != NULL);
	else if ((client = client_list_find_by_mac(arg)) != NULL);
	else if ((client = client_list_find_by_token(arg)) != NULL);
	else {
		debug(LOG_DEBUG, "Client not found.");
		UNLOCK_CLIENT_LIST();
		write(fd, "No", 2);
		return;
	}

	/* We have a client.  Get both ip and mac address and authenticate */
	ip = safe_strdup(client->ip);
	mac = safe_strdup(client->mac);
	UNLOCK_CLIENT_LIST();

	auth_client_action(ip, mac, AUTH_MAKE_AUTHENTICATED);

	free(ip);
	free(mac);
	write(fd, "Yes", 3);

	debug(LOG_DEBUG, "Exiting ptlctl_auth...");
}

static void
ptlctl_deauth(int fd, char *arg)
{
	t_client	*client;
	char *ip, *mac;
	debug(LOG_DEBUG, "Entering ptlctl_deauth...");

	LOCK_CLIENT_LIST();
	/* arg can be IP or MAC address of client */
	debug(LOG_DEBUG, "Argument: %s (@%x)", arg, arg);

	/* We get the client or return... */
	if ((client = client_list_find_by_ip(arg)) != NULL);
	else if ((client = client_list_find_by_mac(arg)) != NULL);
	else if ((client = client_list_find_by_token(arg)) != NULL);
	else {
		debug(LOG_DEBUG, "Client not found.");
		UNLOCK_CLIENT_LIST();
		write(fd, "No", 2);
		return;
	}

	/* We have the client.  Get both ip and mac address and deauthenticate */
	ip = safe_strdup(client->ip);
	mac = safe_strdup(client->mac);
	UNLOCK_CLIENT_LIST();

	auth_client_action(ip, mac, AUTH_MAKE_DEAUTHENTICATED);

	free(ip);
	free(mac);
	write(fd, "Yes", 3);

	debug(LOG_DEBUG, "Exiting ptlctl_deauth...");
}

static void
ptlctl_block(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ptlctl_block...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!add_to_blocked_mac_list(arg) && !iptables_block_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_block.");
}

static void
ptlctl_unblock(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ptlctl_unblock...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!remove_from_blocked_mac_list(arg) && !iptables_unblock_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_unblock.");
}

static void
ptlctl_allow(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ptlctl_allow...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!add_to_allowed_mac_list(arg) && !iptables_allow_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_allow.");
}

static void
ptlctl_unallow(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ptlctl_unallow...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!remove_from_allowed_mac_list(arg) && !iptables_unallow_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_unallow.");
}

static void
ptlctl_trust(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ptlctl_trust...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!add_to_trusted_mac_list(arg) && !iptables_trust_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_trust.");
}

static void
ptlctl_untrust(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ptlctl_untrust...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!remove_from_trusted_mac_list(arg) && !iptables_untrust_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_untrust.");
}

static void
ptlctl_loglevel(int fd, char *arg)
{
	int level = atoi(arg);

	debug(LOG_DEBUG, "Entering ptlctl_loglevel...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);


	if (!set_log_level(level)) {
		write(fd, "Yes", 3);
		debug(LOG_NOTICE, "Set debug loglevel to %d.", level);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_loglevel.");
}

static void
ptlctl_password(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ptlctl_password...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);


	if (!set_password(arg)) {
		write(fd, "Yes", 3);
		debug(LOG_NOTICE, "Set password to %s.", arg);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_password.");
}

static void
ptlctl_username(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ptlctl_username...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);


	if (!set_username(arg)) {
		write(fd, "Yes", 3);
		debug(LOG_NOTICE, "Set username to %s.", arg);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ptlctl_username.");
}
