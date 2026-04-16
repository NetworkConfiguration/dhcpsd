/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - privileged service helper
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "common.h"
#include "dhcpsd.h"
#include "if.h"
#include "logerr.h"
#include "plugin.h"
#include "priv.h"
#include "queue.h"
#include "service.h"
#include "src/eloop.h"

#define P_OPENBPF 1
#define P_SENDBPF 2
#define P_FREEIF  3

int
priv_openbpf(struct interface *ifp)
{
	struct srv_ctx *sctx = ifp->if_ctx->ctx_priv;
	ssize_t result;
	int err;

	err = srv_run(sctx, NULL, P_OPENBPF, ifp, sizeof(*ifp), &result, NULL,
	    0);
	return err == -1 ? -1 : (int)result;
}

ssize_t
priv_sendbpf(struct interface *ifp, const struct iovec *iov, size_t iov_len)
{
	assert(iov_len == 3);
	struct srv_ctx *sctx = ifp->if_ctx->ctx_priv;
	struct iovec iov0[] = {
		{ .iov_base = UNCONST(&ifp->if_index), sizeof(ifp->if_index) },
		{ .iov_base = iov[0].iov_base, .iov_len = iov[0].iov_len },
		{ .iov_base = iov[1].iov_base, .iov_len = iov[1].iov_len },
		{ .iov_base = iov[2].iov_base, .iov_len = iov[2].iov_len },
	};
	ssize_t result;
	int err;

	err = srv_runv(sctx, NULL, P_SENDBPF, iov0, ARRAYCOUNT(iov0), &result,
	    NULL, 0);
	return err == -1 ? -1 : (int)result;
}

int
priv_freeif(struct interface *ifp)
{
	struct srv_ctx *sctx = ifp->if_ctx->ctx_priv;
	ssize_t result;
	int err;

	err = srv_run(sctx, NULL, P_FREEIF, &ifp->if_index,
	    sizeof(ifp->if_index), &result, NULL, 0);
	return err == -1 ? -1 : (int)result;
}

static ssize_t
priv_dispatch_openbpf(struct srv_ctx *sctx, const void *data, size_t len)
{
	struct ctx *ctx = sctx->srv_ctx;
	const struct interface *iff = data;
	struct interface *ifp;
	ssize_t err = -1;

	if (len != sizeof(*iff)) {
		errno = EINVAL;
		goto err;
	}

	TAILQ_FOREACH(ifp, ctx->ctx_ifaces, if_next) {
		if (ifp->if_index == iff->if_index)
			break;
	}
	if (ifp == NULL) {
		ifp = calloc(1, sizeof(*ifp));
		ifp->if_ctx = ctx;
		ifp->if_index = iff->if_index;
		if (strlcpy(ifp->if_name, iff->if_name, sizeof(ifp->if_name)) >
		    sizeof(iff->if_name)) {
			free(ifp);
			errno = EINVAL;
			goto err;
		}
		ifp->if_flags = iff->if_flags;
		ifp->if_hwtype = iff->if_hwtype;
		if (iff->if_hwlen > sizeof(ifp->if_hwaddr)) {
			free(ifp);
			errno = EINVAL;
			goto err;
		}
		ifp->if_hwlen = iff->if_hwlen;
		memcpy(ifp->if_hwaddr, iff->if_hwaddr, sizeof(iff->if_hwaddr));
		if_update_output(ifp);
		TAILQ_INSERT_TAIL(ctx->ctx_ifaces, ifp, if_next);
	}

	if (ifp->if_bpf == NULL) {
		/*
		 * We only write to BPF, we don't read as we get the
		 * same data from the UDP socket even for unconfigured clients.
		 */
		ifp->if_bpf = bpf_open(ifp, bpf_bootp, O_WRONLY);
		if (ifp->if_bpf != NULL)
			err = 0;
	}

err:
	return srv_send(sctx, NULL, P_OPENBPF, err, NULL, 0);
}

static ssize_t
priv_dispatch_sendbpf(struct srv_ctx *sctx, const void *data, size_t len)
{
	struct ctx *ctx = sctx->srv_ctx;
	unsigned int if_index;
	struct interface *ifp;
	struct iovec iov[] = { { .iov_base = (uint8_t *)UNCONST(data) +
		sizeof(if_index),
	    .iov_len = len - sizeof(if_index) } };
	ssize_t err = -1;

	if (len <= sizeof(if_index)) {
		errno = EINVAL;
		goto err;
	}
	memcpy(&if_index, data, sizeof(if_index));
	len -= sizeof(if_index);

	TAILQ_FOREACH(ifp, ctx->ctx_ifaces, if_next) {
		if (ifp->if_index == if_index)
			break;
	}
	if (ifp == NULL) {
		errno = ESRCH;
		goto err;
	}

	err = ifp->if_output(ifp, ifp->if_bpf->bpf_fd, iov, ARRAYCOUNT(iov));

err:
	return srv_send(sctx, NULL, P_SENDBPF, err, NULL, 0);
}

static ssize_t
priv_dispatch_freeif(struct srv_ctx *sctx, const void *data, size_t len)
{
	struct ctx *ctx = sctx->srv_ctx;
	unsigned int if_index;
	struct interface *ifp;
	ssize_t err = -1;

	if (len != sizeof(if_index)) {
		errno = EINVAL;
		goto err;
	}
	memcpy(&if_index, data, sizeof(if_index));

	TAILQ_FOREACH(ifp, ctx->ctx_ifaces, if_next) {
		if (ifp->if_index == if_index)
			break;
	}
	if (ifp == NULL) {
		errno = ESRCH;
		goto err;
	}

	TAILQ_REMOVE(ctx->ctx_ifaces, ifp, if_next);
	if_free(ifp);
	err = 0;

err:
	return srv_send(sctx, NULL, P_FREEIF, err, NULL, 0);
}

static ssize_t
priv_dispatch(struct srv_ctx *sctx, struct plugin *p, unsigned int cmd,
    const void *data, size_t len)
{
	if (p != NULL) {
		if (p->p_dispatch != NULL)
			return p->p_dispatch(p, sctx, cmd, data, len);
		errno = ENOSYS;
		logerr(__func__);
		return srv_send(sctx, NULL, cmd, -1, NULL, 0);
	}

	switch (cmd) {
	case P_OPENBPF:
		return priv_dispatch_openbpf(sctx, data, len);
	case P_SENDBPF:
		return priv_dispatch_sendbpf(sctx, data, len);
	case P_FREEIF:
		return priv_dispatch_freeif(sctx, data, len);
	default:
		errno = EINVAL;
		logerr(__func__);
		return srv_send(sctx, NULL, cmd, -1, NULL, 0);
	}
}

struct srv_ctx *
priv_init(struct ctx *ctx)
{
	if (ctx->ctx_priv != NULL)
		goto out;
	ctx->ctx_priv = srv_init(ctx, "privileged helper", priv_dispatch);

	if (ctx->ctx_priv == NULL)
		return NULL;

	if (ctx->ctx_options & DHCPSD_RUN) {
		ctx->ctx_options |= DHCPSD_PRIV;
#ifdef HAVE_SETPROCTITLE
		setproctitle("privileged helper");
#endif
	}

out:
	return ctx->ctx_priv;
}
