/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - auto plugin for automatic setup
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

#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "dhcp.h"
#include "dhcpsd.h"
#include "if.h"
#include "logerr.h"
#include "plugin.h"

static const char auto_name[] = "auto";
static const char auto_description[] = "Automatic DHCP configuration";

static int
inet_private_address(struct in_addr *addr)
{
	uint8_t *ip = (uint8_t *)&addr->s_addr;

	if (ip[0] == 10)
		return 0;
	if (ip[0] == 172 && ip[1] >= 16 && ip[1] < 32)
		return 0;
	if (ip[0] == 192 && ip[1] == 168)
		return 0;
	return -1;
}

static ssize_t
auto_configure_pools(__unused struct plugin *p, struct interface *ifp)
{
	struct ifaddrs *ifa;
	struct sockaddr_in *sin_addr, *sin_mask;
	uint8_t *ip, cidr;
	struct dhcp_pool *pool;
	char from[INET_ADDRSTRLEN], to[INET_ADDRSTRLEN];
	const char *fromp, *top;
	ssize_t npools = 0;

	for (ifa = ifp->if_ctx->ctx_ifa; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (strcmp(ifa->ifa_name, ifp->if_name) != 0)
			continue;
		sin_addr = (struct sockaddr_in *)ifa->ifa_addr;
		sin_mask = (struct sockaddr_in *)ifa->ifa_netmask;
		cidr = inet_ntocidr(&sin_mask->sin_addr);

		if (inet_private_address(&sin_addr->sin_addr) == -1) {
			logwarnx(
			    "%s: auto: not making pool for non private address"
			    " %s/%d",
			    ifp->if_name, inet_ntoa(sin_addr->sin_addr), cidr);
			continue;
		}

		ip = (uint8_t *)&sin_addr->sin_addr.s_addr;
		if (ip[3] != 1) {
			logwarnx("%s: auto: not making pool for %s/%d"
				 " (does not end with .1)",
			    ifp->if_name, inet_ntoa(sin_addr->sin_addr), cidr);
			continue;
		}

		if (cidr > 24) {
			logwarnx("%s: auto: not making pool for %s/%d"
				 " (cidr > 24)",
			    ifp->if_name, inet_ntoa(sin_addr->sin_addr), cidr);
			continue;
		}

		pool = realloc(ifp->if_pools,
		    sizeof(*pool) * (ifp->if_npools + 1));
		if (pool == NULL) {
			logerr("%s: realloc", __func__);
			return -1;
		}
		ifp->if_pools = pool;
		pool += ifp->if_npools++;

		pool->dp_addr = sin_addr->sin_addr;
		pool->dp_mask = sin_mask->sin_addr;
		pool->dp_from = pool->dp_addr;
		pool->dp_from.s_addr |= ~pool->dp_mask.s_addr;
		pool->dp_to = pool->dp_addr;

		// Start the magic pool from 11, allowing 10 static nodes
		ip = (uint8_t *)&pool->dp_from.s_addr;
		ip[3] = 11;

		// End the magic pool at 254
		// Some OS do not work with an IP address ending 255
		ip = (uint8_t *)&pool->dp_to.s_addr;
		ip[3] = 254;
		// Fill out the rest
		if (ip[2] == 0) {
			ip[2] = 255;
			if (ip[1] == 0)
				ip[1] = 255;
		}

		fromp = inet_ntop(AF_INET, &pool->dp_from, from, sizeof(from));
		top = inet_ntop(AF_INET, &pool->dp_to, to, sizeof(to));
		loginfox("%s: auto: pool for %s/%d: %s - %s", ifp->if_name,
		    inet_ntoa(pool->dp_addr), cidr, fromp, top);
		npools++;
	}

	return npools;
}

static bool
auto_has_oro(const uint8_t *oro, uint8_t o)
{
	const uint8_t *p, *e;

	if (oro == NULL)
		return false;

	e = oro + oro[0];
	p = oro + 1;
	for (; p < e; p++) {
		if (*p == o)
			return true;
	}
	return false;
}

static int
auto_add_dhcp_options(__unused struct plugin *plug,
    __unused struct bootp *bootp, uint8_t **p, const uint8_t *e,
    const struct dhcp_pool *pool, const struct bootp *req, size_t reqlen)
{
	const uint8_t *oro;

	oro = dhcp_findoption(req, reqlen, DHO_PARAMETERREQUESTLIST);

	if (auto_has_oro(oro, DHO_SUBNETMASK))
		DHCP_PUT_U32(p, e, DHO_SUBNETMASK, pool->dp_mask.s_addr);
	if (auto_has_oro(oro, DHO_ROUTER))
		DHCP_PUT_U32(p, e, DHO_ROUTER, pool->dp_addr.s_addr);
	if (auto_has_oro(oro, DHO_DNSSERVER))
		DHCP_PUT_U32(p, e, DHO_DNSSERVER, pool->dp_addr.s_addr);
	return 0;
}

int
plugin_init(struct plugin *p)
{
	p->p_name = auto_name;
	p->p_description = auto_description;
	p->p_configure_pools = auto_configure_pools;
	p->p_add_dhcp_options = auto_add_dhcp_options;
	return 0;
}
