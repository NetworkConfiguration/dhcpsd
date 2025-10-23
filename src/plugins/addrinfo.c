/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - addrinfo plugin for hostname to address mapping
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

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "dhcp.h"
#include "dhcpsd.h"
#include "logerr.h"
#include "plugin.h"
#include "unpriv.h"

static const char addrinfo_name[] = "addrinfo";
static const char addrinfo_description[] =
    "Looks up hostname address mappings via getaddrinfo(3)";

static int
addrinfo_lookup_addr(struct plugin *p, struct sockaddr *sa,
    const char *hostname, const struct bootp *bootp, size_t bootplen)
{
	const uint8_t *opt;
	char hname[MAXHOSTNAMELEN + 1];
	struct addrinfo ai_hints = {
		.ai_family = sa->sa_family,
	};
	struct addrinfo *ai_result;
	int err;

	if (sa->sa_family != AF_INET) {
		errno = ENOTSUP;
		return -1;
	}

	if (hostname == NULL) {
		opt = dhcp_findoption(bootp, bootplen, DHO_HOSTNAME);
		if (opt == NULL) {
			errno = ESRCH;
			return -1;
		}
#if MAXHOSTNAMELEN < 255
		if (opt[0] == 0 || opt[0] > MAXHOSTNAMELEN) {
#else
		if (opt[0] == 0) {
#endif
			errno = EINVAL;
			return -1;
		}
		memcpy(hname, opt + 1, opt[0]);
		hname[opt[0]] = '\0';
		hostname = hname;
	}

	memset(&ai_hints, 0, sizeof(ai_hints));
	err = unpriv_getaddrinfo(p->p_ctx->ctx_unpriv, hostname, NULL,
	    &ai_hints, &ai_result);
	switch (err) {
	case 0: /* Success */
		break;
	case EAI_AGAIN:
		errno = EAGAIN;
		return -1;
	case EAI_NODATA:
	case EAI_NONAME:
	case EAI_ADDRFAMILY:
		errno = ESRCH;
		return -1;
	case EAI_FAMILY:
		errno = EAFNOSUPPORT;
		return -1;
	case EAI_MEMORY:
		errno = ENOBUFS;
		return -1;
	case EAI_SYSTEM:
		/* errno is set */
		return -1;
	default:
		logerr("%s: %s", addrinfo_name, gai_strerror(err));
		errno = ENOSYS;
		return -1;
	}

	memcpy(sa, ai_result->ai_addr, sizeof(struct sockaddr_in));
	freeaddrinfo(ai_result);
	return 0;
}

int
plugin_init(struct plugin *p)
{
	p->p_name = addrinfo_name;
	p->p_description = addrinfo_description;
	p->p_lookup_addr = addrinfo_lookup_addr;
	return 0;
}
