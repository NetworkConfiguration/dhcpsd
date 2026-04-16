/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - route(4) supprt
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

#include <net/if.h>
#include <net/route.h>

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "dhcpsd.h"
#include "eloop.h"
#include "if.h"
#include "logerr.h"
#include "queue.h"

struct link_ctx {
	struct ctx *link_ctx;
	int link_fd;
};

struct rtm {
	struct rt_msghdr hdr;
	char buffer[sizeof(struct sockaddr_storage) * RTAX_MAX];
};

static void
route_dispatch_ifinfo(struct link_ctx *lctx, struct rt_msghdr *rtm)
{
	struct ctx *ctx = lctx->link_ctx;
	struct if_msghdr *ifi = (struct if_msghdr *)rtm;
	struct interface *ifp;

	if (rtm->rtm_msglen < sizeof(*ifi))
		return;

	if (ifi->ifm_flags & IFF_UP)
		return;

	/* Interface is down, remove it from consideration. */
	TAILQ_FOREACH(ifp, ctx->ctx_ifaces, if_next) {
		if (ifp->if_index == ifi->ifm_index)
			break;
	}
	if (ifp == NULL)
		return;

	logwarnx("%s: interface is down", ifp->if_name);
	TAILQ_REMOVE(ctx->ctx_ifaces, ifp, if_next);
	if_free(ifp);
}

static void
route_dispatch(void *arg, unsigned short e)
{
	struct link_ctx *lctx = arg;
	struct rtm rtm;
	ssize_t len;

	if (e != ELE_READ) {
		logerrx("%s: unexpeced event %d", __func__, e);
	}
	len = read(lctx->link_fd, &rtm, sizeof(rtm));
	if (len == -1) {
		logerr("%s: read", __func__);
		return;
	}

	if ((size_t)len < offsetof(struct rt_msghdr, rtm_type) +
		    sizeof(rtm.hdr.rtm_type) ||
	    len < rtm.hdr.rtm_msglen) {
		logerrx("%s: truncated route message %zd %zu %d", __func__, len,
		    sizeof(rtm.hdr), rtm.hdr.rtm_msglen);
		return;
	}

	switch (rtm.hdr.rtm_type) {
	case RTM_IFINFO:
		route_dispatch_ifinfo(lctx, &rtm.hdr);
		break;
	default:
		/* Ignore other messages */
		break;
	}
}

int
link_open(struct ctx *ctx)
{
	struct link_ctx *lctx = malloc(sizeof(*lctx));
#ifdef SO_RERROR
	int n;
#endif
#if defined(RO_MSGFILTER) || defined(ROUTE_MSGFILTER)
	unsigned char msgfilter[] = {
		RTM_IFINFO,
#ifdef RTM_IFANNOUNCE
		RTM_IFANNOUNCE,
#endif
	};
#ifdef ROUTE_MSGFILTER
	unsigned int i, msgfilter_mask;
#endif
#endif

	if (lctx == NULL)
		return -1;

	lctx->link_ctx = ctx;

	lctx->link_fd = xsocket(PF_ROUTE, SOCK_RAW | SOCK_CXNB, AF_UNSPEC);
	if (lctx->link_fd == -1)
		return -1;

#ifdef SO_RERROR
	n = 1;
	if (setsockopt(ctx->link_fd, SOL_SOCKET, SO_RERROR, &n, sizeof(n)) ==
	    -1)
		logerr("%s: SO_RERROR", __func__);
#endif

#if defined(RO_MSGFILTER)
	if (setsockopt(ctx->link_fd, PF_ROUTE, RO_MSGFILTER, &msgfilter,
		sizeof(msgfilter)) == -1)
		logerr(__func__);
#elif defined(ROUTE_MSGFILTER)
	/* Convert the array into a bitmask. */
	msgfilter_mask = 0;
	for (i = 0; i < __arraycount(msgfilter); i++)
		msgfilter_mask |= ROUTE_FILTER(msgfilter[i]);
	if (setsockopt(ctx->link_fd, PF_ROUTE, ROUTE_MSGFILTER, &msgfilter_mask,
		sizeof(msgfilter_mask)) == -1)
		logerr(__func__);
#else
#warning kernel does not support route message filtering
#endif

	if (eloop_event_add(ctx->ctx_eloop, lctx->link_fd, ELE_READ,
		route_dispatch, lctx) == -1) {
		logerr("%s: eloop_event_add", __func__);
		return -1;
	}

	return 0;
}

void
link_free(struct ctx *ctx)
{
	struct link_ctx *lctx = ctx->ctx_link;

	if (lctx == NULL)
		return;
	if (lctx->link_fd != -1)
		close(lctx->link_fd);
	free(lctx);
	ctx->ctx_link = NULL;
}