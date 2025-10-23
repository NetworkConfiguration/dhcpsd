/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - ethers plugin for hardware address mapping
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>

#include <arpa/inet.h>
#ifdef __linux__
#include <netinet/ether.h>
#else
#include <netinet/if_ether.h>
#endif

#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "dhcp.h"
#include "dhcpsd.h"
#include "logerr.h"
#include "plugin.h"
#include "service.h"

static const char ethers_name[] = "ethers";
static const char ethers_description[] =
    "Looks up hostname from hardware address in ethers(5)";

#define E_LOOKUPHOSTNAME 1U

static ssize_t
ethers_run_lookup_hostname(struct plugin *p, struct svc_ctx *sctx,
    const void *data, size_t datalen)
{
	struct ether_addr *ether_addr = (struct ether_addr *)UNCONST(data);
	char hname[MAXHOSTNAMELEN + 1];
	size_t hnamelen = 0;
	ssize_t err = -1;

	if (datalen < sizeof(*ether_addr)) {
		errno = EINVAL;
		goto out;
	}

	if (ether_ntohost(hname, ether_addr) != 0) {
		errno = ESRCH;
		goto out;
	}

	err = 0;
	hnamelen = strlen(hname) + 1;

out:
	return svc_send(sctx, p, E_LOOKUPHOSTNAME, err, hname, hnamelen);
}

static ssize_t
ethers_dispatch(struct plugin *p, struct svc_ctx *sctx, unsigned int cmd,
    const void *data, size_t len)
{
	switch (cmd) {
	case E_LOOKUPHOSTNAME:
		return ethers_run_lookup_hostname(p, sctx, data, len);
	default:
		errno = ENOTSUP;
		return -1;
	}
}

static int
ethers_lookup_hostname(struct plugin *p, char *hostname,
    const struct bootp *bootp, __unused size_t len)
{
	struct ether_addr ea;
	ssize_t err, result;
	void *hname;
	size_t hnamelen;

	if (bootp->hlen != sizeof(ea)) {
		errno = EINVAL;
		return -1;
	}

	memcpy(&ea, bootp->chaddr, sizeof(ea));
	err = svc_run(p->p_ctx->ctx_unpriv, p, E_LOOKUPHOSTNAME, &ea,
	    sizeof(ea), &result, &hname, &hnamelen);
	if (err == -1 || result != 0)
		return -1;
	if (hnamelen > DHCP_HOSTNAME_LEN) {
		errno = ENOBUFS;
		return -1;
	}
	memcpy(hostname, hname, hnamelen);
	if (hostname[hnamelen] != '\0') {
		if (hnamelen < DHCP_HOSTNAME_LEN - 1)
			hnamelen++;
		hostname[hnamelen] = '\0';
	}
	return 1;
}

int
plugin_init(struct plugin *p)
{
	p->p_name = ethers_name;
	p->p_description = ethers_description;
	p->p_lookup_hostname = ethers_lookup_hostname;
	p->p_dispatch = ethers_dispatch;
	p->p_unpriv = 1;
	return 0;
}
