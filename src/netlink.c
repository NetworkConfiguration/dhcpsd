/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - netlink(7) support
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

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdbool.h>
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

static int
netlink_get(struct link_ctx *lctx, struct iovec *iov, int fd, int flags,
    int (*cb)(struct link_ctx *, struct nlmsghdr *))
{
	struct sockaddr_nl nladdr = { .nl_pid = 0 };
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = 1,
	};
	ssize_t len;
	struct nlmsghdr *nlm;
	int r = 0;
	unsigned int again;
	bool terminated;

recv_again:
	len = recvmsg(fd, &msg, flags);
	if (len == 0 || len == -1)
		return (int)len;

	/* Check sender */
	if (msg.msg_namelen != sizeof(nladdr)) {
		errno = EINVAL;
		return -1;
	}

	/* Ignore message if it is not from kernel */
	if (nladdr.nl_pid != 0)
		return 0;

	again = 0;
	terminated = false;
	for (nlm = iov->iov_base; nlm && NLMSG_OK(nlm, len);
	    nlm = NLMSG_NEXT(nlm, len)) {
		again = (nlm->nlmsg_flags & NLM_F_MULTI);
		if (nlm->nlmsg_type == NLMSG_NOOP)
			continue;

		if (nlm->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err;

			if (nlm->nlmsg_len - sizeof(*nlm) < sizeof(*err)) {
				errno = EBADMSG;
				return -1;
			}
			err = (struct nlmsgerr *)NLMSG_DATA(nlm);
			if (err->error != 0) {
				errno = -err->error;
				return -1;
			}
			again = 0;
			terminated = true;
			break;
		}
		if (nlm->nlmsg_type == NLMSG_DONE) {
			again = 0;
			terminated = true;
			break;
		}
		if (cb == NULL)
			continue;
		r = cb(lctx, nlm);
	}

	if (again || !terminated)
		goto recv_again;

	return r;
}

static int
netlink_link(struct link_ctx *lctx, struct nlmsghdr *nlm)
{
	struct ctx *ctx = lctx->link_ctx;
	size_t len;
	struct ifinfomsg *ifi;
	struct interface *ifp;

	len = nlm->nlmsg_len - sizeof(*nlm);
	if ((size_t)len < sizeof(*ifi)) {
		errno = EBADMSG;
		return -1;
	}

	ifi = NLMSG_DATA(nlm);
	if (nlm->nlmsg_type != RTM_DELLINK && ifi->ifi_flags & IFF_UP)
		return 0;

	TAILQ_FOREACH(ifp, ctx->ctx_ifaces, if_next) {
		if (ifp->if_index == (unsigned int)ifi->ifi_index)
			break;
	}
	if (ifp == NULL)
		return 0;

	if (nlm->nlmsg_type == RTM_DELLINK)
		loginfox("%s: interface has departed", ifp->if_name);
	else if (!(ifi->ifi_flags & IFF_UP))
		loginfox("%s: interface is down", ifp->if_name);

	TAILQ_REMOVE(ctx->ctx_ifaces, ifp, if_next);
	if_free(ifp);
	return 0;
}

static int
netlink_dispatch(struct link_ctx *lctx, struct nlmsghdr *nlm)
{
	switch (nlm->nlmsg_type) {
	case RTM_DELLINK:
	case RTM_NEWLINK:
		return netlink_link(lctx, nlm);
	}
	return 0;
}

static void
netlink_handle(void *arg, unsigned short e)
{
	struct link_ctx *lctx = arg;
	unsigned char buf[16 * 1024];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf),
	};

#ifdef NDEBUG
	UNUSED(e);
#else
	assert(e == ELE_READ);
#endif

	if (netlink_get(lctx, &iov, lctx->link_fd, MSG_DONTWAIT,
		netlink_dispatch) == -1)
		logerr("%s: netlink_get", __func__);
}

int
link_open(struct ctx *ctx)
{
	struct link_ctx *lctx = malloc(sizeof(*lctx));
	struct sockaddr_nl nl = { .nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK };
#ifdef NETLINK_BROADCAST_ERROR
	int on = 1;
#endif

	if (lctx == NULL)
		return -1;

	/* lctx will be freed at exit regardless if any error below
	 * so there is no need to free it on an error path. */
	lctx->link_ctx = ctx;
	ctx->ctx_link = lctx;

	lctx->link_fd = xsocket(AF_NETLINK, SOCK_RAW | SOCK_CXNB,
	    NETLINK_ROUTE);
	if (lctx->link_fd == -1)
		return -1;

	if (bind(lctx->link_fd, (struct sockaddr *)&nl, sizeof(nl)) == -1) {
		logerr("%s: bind", __func__);
		return -1;
	}

	/* netlink socket can overflow if the kernel sends too many messages.
	 * We need to reliably track state and if we can't we need to know. */
#ifdef NETLINK_BROADCAST_ERROR
	if (setsockopt(lctx->link_fd, SOL_NETLINK, NETLINK_BROADCAST_ERROR, &on,
		sizeof(on)) == -1)
		logerr("%s: NETLINK_BROADCAST_ERROR", __func__);
#endif

	if (eloop_event_add(ctx->ctx_eloop, lctx->link_fd, ELE_READ,
		netlink_handle, lctx) == -1) {
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
