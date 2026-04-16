/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - DHCP server daemon
 * Copyright (c) 2025 Roy Marples <roy@marples.name>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef DHCPSD_H
#define DHCPSD_H

#include <stddef.h>

struct link_ctx;
struct dhcp_ctx;
struct eloop;
struct if_head;
struct srv_ctx;
struct plugin;
#ifdef HAVE_CASPER
typedef struct cap_channel cap_channel_t;
#endif

struct ctx {
	int ctx_argc;
	char **ctx_argv;
	struct dhcp_ctx *ctx_dhcp;
	struct eloop *ctx_eloop;
	struct if_head *ctx_ifaces;

	struct srv_ctx *ctx_priv;
	struct srv_ctx *ctx_unpriv;
	struct plugin *ctx_plugins;
	size_t ctx_nplugins;

	unsigned int ctx_options;
#define DHCPSD_RUN	(1U << 0) /* Set by forked stuff */
#define DHCPSD_EXITING	(1U << 1) /* process will exit */
#define DHCPSD_MAIN	(1U << 2) /* Main process */
#define DHCPSD_PRIV	(1U << 3) /* Privileged helper */
#define DHCPSD_UNPRIV	(1U << 4) /* Unprivileged helper */
#define DHCPSD_LAUNCHER (1U << 5) /* Launcher process */
#define DHCPSD_WAITIF	(1U << 6) /* wait for interfaces */

	struct link_ctx *ctx_link;
	int ctx_fork_fd;
	int ctx_pf_inet_fd;
#ifdef IFLR_ACTIVE
	int ctx_pf_link_fd;
#endif
#ifdef HAVE_CASPER
	cap_channel_t *ctx_capnet;
#endif
};

struct interface;

int dhcpsd_dropperms(int);
ssize_t dhcpsd_configure_pools(struct interface *);

/*
 * This is defined by the OS specific link mechanism:
 * route(4) or rtnetlink(7)
 */
int link_open(struct ctx *);
void link_free(struct ctx *);

#endif /* CTX_H */
