/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - ICMP plugin to test if we can offer an address
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
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "common.h"
#include "dhcp.h"
#include "dhcpsd.h"
#include "eloop.h"
#include "if.h"
#include "logerr.h"
#include "plugin.h"

#ifdef HAVE_CASPER
#include <sys/capsicum.h>

#include <capsicum_helpers.h>
#include <casper/cap_net.h>
#endif

static const char icmp_name[] = "icmp";
static const char icmp_description[] =
    "Tests if an address is available by sending an ICMP ping";

static unsigned int icmp_echo_requests = 1;
static unsigned int icmp_echo_timeout = 3000; // milliseconds

struct icmp_hold {
	struct icmp_ctx *ih_ctx;
	struct interface *ih_if;
	void *ih_data;
	size_t ih_datalen;
	struct sockaddr_in ih_sin;
	uint16_t ih_id;
	uint16_t ih_nrequests;
	void (*ih_release)(struct interface *, void *, size_t, uint32_t);
};

#define NAME	icmp_addr_map
#define KEY_TY	uint32_t
#define VAL_TY	struct icmp_hold *
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

struct icmp_ctx {
	struct ctx *i_ctx;
	int i_fd;
	uint8_t *i_buf;
	size_t i_buflen;
	icmp_addr_map i_hold;
#ifdef HAVE_CASPER
	int i_capfd;
#endif
};

static void
icmp_release(void *arg)
{
	struct icmp_hold *ih = arg;
	struct icmp_ctx *ctx = ih->ih_ctx;

	vt_erase(&ctx->i_hold, ih->ih_sin.sin_addr.s_addr);
	ih->ih_release(ih->ih_if, ih->ih_data, ih->ih_datalen, DL_OFFERED);
	free(ih->ih_data);
	free(ih);
}

static void
icmp_echo_request(void *arg)
{
	struct icmp_hold *ih = arg;
	struct icmp_ctx *ctx = ih->ih_ctx;
	struct icmp icmp = {
		.icmp_type = ICMP_ECHO,
		.icmp_id = ih->ih_id,
		.icmp_seq = htons(ih->ih_nrequests),
	};
	struct sockaddr *sa = (struct sockaddr *)&ih->ih_sin;

	icmp.icmp_cksum = in_cksum(&icmp, sizeof(icmp), NULL);
	if (icmp.icmp_cksum == 0)
		icmp.icmp_cksum = 0xffff;

	eloop_timeout_add_msec(ctx->i_ctx->ctx_eloop, icmp_echo_timeout,
	    ++ih->ih_nrequests >= icmp_echo_requests ? icmp_release :
						       icmp_echo_request,
	    ih);

	logdebugx("%s: echo request: %s %u", icmp_name,
	    inet_ntoa(ih->ih_sin.sin_addr), ih->ih_id);
#ifdef HAVE_CASPER
	if (cap_connect(ctx->i_ctx->ctx_capnet, ctx->i_capfd, sa, sa_len(sa)) ==
	    -1)
		logerr("%s: cap_connect", __func__);
	else if (send(ctx->i_capfd, &icmp, sizeof(icmp), 0) == -1)
		logerr("%s: send", __func__);
#else
	if (sendto(ctx->i_fd, &icmp, sizeof(icmp), 0, sa, sa_len(sa)) == -1)
		logerr("%s: sendto", __func__);
#endif
}

static int
icmp_test_addr(struct plugin *p, struct interface *ifp,
    const struct sockaddr *dst, void *data, size_t datalen,
    void (*release)(struct interface *, void *, size_t, uint32_t))
{
	struct icmp_ctx *ctx = p->p_pctx;
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
	};
	struct icmp_hold *ih;
	icmp_addr_map_itr itr;

	if (dst->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	memcpy(&sin, dst, sa_len(dst));

	itr = vt_get(&ctx->i_hold, sin.sin_addr.s_addr);
	if (!vt_is_end(itr)) {
		/* Should not happen */
		errno = EBUSY;
		return -1;
	} else {
		ih = malloc(sizeof(*ih));
		if (ih == NULL)
			return -1;
	}

	ih->ih_if = ifp;
	ih->ih_data = malloc(datalen);
	if (ih->ih_data == NULL) {
		free(ih);
		return -1;
	}

	memcpy(ih->ih_data, data, datalen);
	memcpy(&ih->ih_sin, dst, sa_len(dst));
	ih->ih_ctx = ctx;
	ih->ih_datalen = datalen;
	ih->ih_release = release;
	ih->ih_id = arc4random() & 0xffff;
	ih->ih_nrequests = 0;

	itr = vt_insert(&ctx->i_hold, ih->ih_sin.sin_addr.s_addr, ih);
	if (vt_is_end(itr)) {
		free(ih->ih_data);
		free(ih);
		return -1;
	}

	icmp_echo_request(ih);

	/* Notify we are testing this address */
	return 1;
}

static void
icmp_read0(struct icmp_ctx *ctx, int fd, unsigned short e)
{
	struct sockaddr_in from;
	struct sockaddr *sa = (struct sockaddr *)&from;
	socklen_t salen = sizeof(from);
	struct ip *ip = (struct ip *)ctx->i_buf;
	struct icmp *icmp;
	ssize_t nread;
	int hlen;
	icmp_addr_map_itr itr;
	struct icmp_hold *ih;

	if (!(e & ELE_READ))
		return;

	nread = recvfrom(fd, ctx->i_buf, ctx->i_buflen, 0, sa, &salen);
	if (nread == -1)
		logerr("%s: recvfrom", __func__);
	if ((size_t)nread < sizeof(*ip)) {
		logerrx("%s: trunacted read", __func__);
		return;
	}

	hlen = ip->ip_hl << 2;
	if ((size_t)hlen < sizeof(*ip)) {
		logerrx("%s: trunacted ip", __func__);
		return;
	}

	icmp = (struct icmp *)(ctx->i_buf + hlen);
	if (icmp->icmp_type != ICMP_ECHOREPLY)
		return;

	from.sin_port = 0;
	itr = vt_get(&ctx->i_hold, from.sin_addr.s_addr);
	if (vt_is_end(itr)) {
		return;
	}

	ih = itr.data->val;
	if (ih->ih_id != icmp->icmp_id) {
		logdebugx("%s: echo reply: %s - wrong id (%u != %u)", icmp_name,
		    inet_ntoa(from.sin_addr), ih->ih_id, icmp->icmp_id);
		return;
	}

	logdebugx("%s: echo reply: %s %u", icmp_name, inet_ntoa(from.sin_addr),
	    icmp->icmp_id);
	vt_erase(&ctx->i_hold, ih->ih_sin.sin_addr.s_addr);
	eloop_timeout_delete(ctx->i_ctx->ctx_eloop, icmp_release, ih);
	eloop_timeout_delete(ctx->i_ctx->ctx_eloop, icmp_echo_request, ih);
	ih->ih_release(ih->ih_if, ih->ih_data, ih->ih_datalen,
	    DL_PLUGIN_DECLINED);
	free(ih->ih_data);
	free(ih);
}

static void
icmp_read(void *arg, unsigned short e)
{
	struct icmp_ctx *ctx = arg;

	icmp_read0(ctx, ctx->i_fd, e);
}

#ifdef HAVE_CASPER
static void
icmp_capread(void *arg, unsigned short e)
{
	struct icmp_ctx *ctx = arg;

	icmp_read0(ctx, ctx->i_capfd, e);
}
#endif

static int
icmp_init(struct plugin *p)
{
	struct icmp_ctx *ctx = p->p_pctx;
#ifdef HAVE_CASPER
	cap_rights_t rights, wrights;
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_LOOPBACK,
		.sin_port = htons(BOOTPC),
#ifdef BSD
		.sin_len = sizeof(sin),
#endif
	};
#endif

	/* We cannot send over BPF as we don't know the target hardware address
	 * and modern nodes disallow broadcast ICMP.
	 * If this proves not to be performant, we can always listen via BPF
	 * and just send via this socket. */
	ctx->i_fd = xsocket(AF_INET, SOCK_RAW | SOCK_CXNB, IPPROTO_ICMP);
	if (ctx->i_fd == -1)
		return -1;

	if (eloop_event_add(p->p_ctx->ctx_eloop, ctx->i_fd, ELE_READ, icmp_read,
		ctx) == -1) {
		return -1;
	}

#ifdef HAVE_CASPER
	cap_rights_init(&rights, CAP_READ, CAP_EVENT);
	if (caph_rights_limit(ctx->i_fd, &rights) == -1)
		return -1;

	ctx->i_capfd = xsocket(AF_INET, SOCK_RAW | SOCK_CXNB, IPPROTO_ICMP);
	if (ctx->i_capfd == -1)
		return -1;

	if (connect(ctx->i_capfd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		return -1;

	cap_rights_init(&wrights, CAP_READ, CAP_EVENT, CAP_WRITE, CAP_CONNECT);
	if (caph_rights_limit(ctx->i_capfd, &wrights) == -1)
		return -1;

	if (eloop_event_add(p->p_ctx->ctx_eloop, ctx->i_capfd, ELE_READ,
		icmp_capread, ctx) == -1) {
		return -1;
	}
#endif

	return 0;
}

static int
icmp_unload(struct plugin *p)
{
	struct icmp_ctx *ctx = p->p_pctx;
	icmp_addr_map_itr itr;

	for (itr = vt_first(&ctx->i_hold); !vt_is_end(itr);
	     itr = vt_next(itr)) {
		free(itr.data->val->ih_data);
		free(itr.data->val);
	}
	vt_cleanup(&ctx->i_hold);

	free(ctx->i_buf);

	if (ctx->i_fd != -1)
		close(ctx->i_fd);
#ifdef HAVE_CASPER
	if (ctx->i_capfd != -1)
		close(ctx->i_capfd);
#endif
	free(ctx);
	return 0;
}

int
plugin_init(struct plugin *p)
{
	struct icmp_ctx *ctx = malloc(sizeof(*ctx));

	if (ctx == NULL)
		return -1;

	ctx->i_ctx = p->p_ctx;
	ctx->i_buflen = 60 + 76; /* MAXIP + MAXICMP */
	ctx->i_buf = malloc(ctx->i_buflen);
	if (ctx->i_buf == NULL) {
		free(ctx);
		return -1;
	}

	vt_init(&ctx->i_hold);
	ctx->i_fd = -1;
#ifdef HAVE_CASPER
	ctx->i_capfd = -1;
#endif

	p->p_name = icmp_name;
	p->p_description = icmp_description;
	p->p_pctx = ctx;
	p->p_init = icmp_init;
	p->p_unload = icmp_unload;
	p->p_test_addr = icmp_test_addr;
	return 0;
}
