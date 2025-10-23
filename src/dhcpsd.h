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

struct ifaddrs;
struct dhcp_ctx;
struct eloop;
struct if_head;
struct svc_ctx;
struct plugin;
#ifdef HAVE_CASPER
typedef struct cap_channel cap_channel_t;
#endif

struct ctx {
	struct ifaddrs *ctx_ifa;
	struct dhcp_ctx *ctx_dhcp;
	struct eloop *ctx_eloop;
	struct if_head *ctx_ifaces;

	struct svc_ctx *ctx_unpriv;
	struct plugin *ctx_plugins;
	size_t ctx_nplugins;

	unsigned int ctx_options;
#define DHCPSD_RUN    (1U << 0) /* Set by forked stuff */
#define DHCPSD_MAIN   (1U << 1) /* Main process */
#define DHCPSD_UNPRIV (1U << 2) /* Unprivileged helper */

	int ctx_pf_inet_fd;
#ifdef IFLR_ACTIVE
	int ctx_pf_link_fd;
#endif
#ifdef HAVE_CASPER
	cap_channel_t *ctx_capnet;
#endif
};

int dhcpsd_dropperms(int);

#endif /* CTX_H */
