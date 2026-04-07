/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - service helper for privilege separation
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
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "config.h"
#include "dhcpsd.h"
#include "eloop.h"
#include "logerr.h"
#include "service.h"

struct srv_cmd {
	uintptr_t sc_plugin;
	unsigned int sc_cmd;
	int sc_errno;
	ssize_t sc_result;
	size_t sc_datalen;
};

static ssize_t
srv_recv(struct srv_ctx *sctx, unsigned short e)
{
	struct srv_result *sr = &sctx->srv_result;
	struct srv_cmd cmd;
	struct iovec iov[] = {
		{
		    .iov_base = &cmd,
		    .iov_len = sizeof(cmd),
		},
	};
	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 1 };
	ssize_t nread;

	if (e & ELE_HANGUP) {
	hangup:
		eloop_exit(sctx->srv_ctx->ctx_eloop, EXIT_SUCCESS);
		return -1;
	}
	if (e != ELE_READ) {
		logerrx("%s: unexpected operation %u", __func__, e);
		return -1;
	}

	nread = recvmsg(sctx->srv_fd, &msg, MSG_WAITALL);
	if (nread == 0)
		goto hangup;
	if (nread == -1) {
		logerr("%s: recvmsg cmd", __func__);
		return -1;
	}
	if (nread != sizeof(cmd)) {
		logerrx("%s: invalid read len: %zd", __func__, nread);
		return -1;
	}

	if (cmd.sc_datalen != 0) {
		if (sctx->srv_buflen < cmd.sc_datalen) {
			void *nbuf = realloc(sctx->srv_buf, cmd.sc_datalen);
			if (nbuf == NULL) {
				logerr("%s: realloc", __func__);
				return -1;
			}
			sctx->srv_buf = nbuf;
			sctx->srv_buflen = cmd.sc_datalen;
		}
		iov[0].iov_base = sctx->srv_buf;
		iov[0].iov_len = cmd.sc_datalen;

		nread = recvmsg(sctx->srv_fd, &msg, MSG_WAITALL);
		if (nread == -1) {
			logerr("%s: recvmsg cmd", __func__);
			return -1;
		}
		if ((size_t)nread != cmd.sc_datalen) {
			logerrx("%s: read datalen mismatch: %zd != %zd",
			    __func__, nread, cmd.sc_datalen);
			return -1;
		}
	}

	sr->sr_result = cmd.sc_result;
	sr->sr_errno = cmd.sc_errno;
	sr->sr_data = cmd.sc_datalen != 0 ? sctx->srv_buf : NULL;
	sr->sr_datalen = cmd.sc_datalen;

	/* We are either a dispatcher for the helper, or a blocking loop for a
	 * response */
	if (sctx->srv_dispatch != NULL)
		sctx->srv_dispatch(sctx, (struct plugin *)cmd.sc_plugin,
		    cmd.sc_cmd, cmd.sc_datalen ? sctx->srv_buf : NULL,
		    cmd.sc_datalen);

	return (ssize_t)cmd.sc_datalen;
}

static void
srv_recvl(void *arg, unsigned short e)
{
	struct srv_ctx *sctx = arg;

	if (srv_recv(sctx, e) == -1 && !(e & ELE_HANGUP))
		eloop_exit(sctx->srv_ctx->ctx_eloop, EXIT_FAILURE);
}

ssize_t
srv_sendv(struct srv_ctx *sctx, struct plugin *p, unsigned int cmd,
    ssize_t result, struct iovec *iov, int iovlen)
{
	struct srv_cmd sc = {
		.sc_plugin = (uintptr_t)p,
		.sc_cmd = cmd,
		.sc_result = result,
		.sc_errno = errno,
		.sc_datalen = 0,
	};
	struct iovec _iov[5] = {
		{
		    .iov_base = &sc,
		    .iov_len = sizeof(sc),
		},
	};
	struct msghdr msg = {
		.msg_iov = _iov,
		.msg_iovlen = 1,
	};
	int i;

	if ((size_t)iovlen + (size_t)msg.msg_iovlen > ARRAYCOUNT(_iov)) {
		errno = ENOBUFS;
		return -1;
	}
	for (i = 0; i < iovlen; i++) {
		if (iov[i].iov_len == 0)
			continue;
		_iov[msg.msg_iovlen++] = iov[i];
		sc.sc_datalen += iov[i].iov_len;
	}

	ssize_t err = sendmsg(sctx->srv_fd, &msg, 0);
	return err;
}

ssize_t
srv_send(struct srv_ctx *sctx, struct plugin *p, unsigned int cmd,
    ssize_t result, const void *data, size_t len)
{
	struct iovec iov[] = {
		{ .iov_base = UNCONST(data), .iov_len = len },
	};

	return srv_sendv(sctx, p, cmd, result, iov, len == 0 ? 0 : 1);
}

int
srv_runv(struct srv_ctx *sctx, struct plugin *p, unsigned int cmd,
    struct iovec *iov, int iovlen, ssize_t *res, void **rdata, size_t *rlen)
{
	struct srv_result *result = &sctx->srv_result;
	int events;

	if (srv_sendv(sctx, p, cmd, 0, iov, iovlen) == -1) {
		logerr("%s: srv_write", __func__);
		return -1;
	}

	events = eloop_waitfd(sctx->srv_fd);
	if (events == -1)
		return -1;
	if (srv_recv(sctx, (unsigned short)events) == -1)
		return -1;

	if (result->sr_result == -1)
		errno = result->sr_errno;
	if (res != NULL)
		*res = result->sr_result;
	if (rdata != NULL)
		*rdata = result->sr_data;
	if (rlen != NULL)
		*rlen = result->sr_datalen;
	return 0;
}

int
srv_run(struct srv_ctx *sctx, struct plugin *p, unsigned int cmd,
    const void *data, size_t len, ssize_t *res, void **rdata, size_t *rlen)
{
	struct iovec iov[] = {
		{ .iov_base = UNCONST(data), .iov_len = len },
	};

	return srv_runv(sctx, p, cmd, iov, len == 0 ? 0 : 1, res, rdata, rlen);
}

struct srv_ctx *
srv_init(struct ctx *ctx, const char *name,
    ssize_t (*dispatch)(struct srv_ctx *, struct plugin *, unsigned int,
	const void *, size_t))
{
	struct srv_ctx *sctx;
	int fdset[2], fd;
	pid_t pid;
	unsigned int logopts;

	sctx = malloc(sizeof(*sctx));
	if (sctx == NULL) {
		logerr("%s: malloc", __func__);
		return NULL;
	}

	sctx->srv_ctx = ctx;
	sctx->srv_fd = -1;
	sctx->srv_dispatch = NULL;

	sctx->srv_buflen = 1024;
	sctx->srv_buf = malloc(sctx->srv_buflen);
	if (sctx->srv_buf == NULL) {
		logerr("%s: malloc", __func__);
		goto error;
	}

	if (xsocketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, fdset) == -1) {
		logerr("%s: socketpair", __func__);
		goto error;
	}

	pid = fork();
	switch (pid) {
	case -1:
		logerr("%s: fork", __func__);
		goto error;
	case 0:
		sctx->srv_fd = fdset[1];
		close(fdset[0]);
		break;
	default:
		sctx->srv_fd = fdset[0];
		close(fdset[1]);
		logdebugx("service: spawned %s on pid %ld", name, (long)pid);
		return sctx;
	}

	ctx->ctx_options &= ~DHCPSD_MAIN;
	ctx->ctx_options |= DHCPSD_UNPRIV | DHCPSD_RUN;
	sctx->srv_dispatch = dispatch;

	if (eloop_forked(ctx->ctx_eloop, ELF_KEEP_SIGNALS) == -1) {
		logerr("%s: eloop_forked", __func__);
		goto error;
	}

	if (eloop_event_add(ctx->ctx_eloop, sctx->srv_fd, ELE_READ, srv_recvl,
		sctx) == -1) {
		logerr("%s: eloop_event_add", __func__);
		goto error;
	}

	fd = open(_PATH_DEVNULL, O_RDWR);
	if (fd == -1) {
		logerr("%s: %s:", __func__, _PATH_DEVNULL);
		goto error;
	}

	if (dup2(fd, STDIN_FILENO) == -1) {
		logerr("%s: dup STDIN", __func__);
		goto error;
	}
	logopts = loggetopts();
	if (!(logopts & LOGERR_DEBUG)) {
		if (dup2(fd, STDOUT_FILENO) == -1) {
			logerr("%s: dup STDOUT", __func__);
			goto error;
		}
		if (dup2(fd, STDERR_FILENO) == -1) {
			logerr("%s: dup STDERR", __func__);
			goto error;
		}
	}
	close(fd);

	return sctx;

error:
	srv_free(sctx);
	return NULL;
}

void
srv_free(struct srv_ctx *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->srv_fd != -1)
		close(ctx->srv_fd);
	free(ctx->srv_buf);
	free(ctx);
}
