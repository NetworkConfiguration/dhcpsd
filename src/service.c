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

struct svc_cmd {
	uintptr_t sc_plugin;
	unsigned int sc_cmd;
	int sc_errno;
	ssize_t sc_result;
	size_t sc_datalen;
};

struct svc_result {
	struct svc_ctx *sr_ctx;
	ssize_t sr_result;
	int sr_errno;
	void *sr_data;
	size_t sr_datalen;
};

static void
svc_recv(void *arg, unsigned short e)
{
	struct svc_result *sr = arg;
	struct svc_ctx *sctx = sr->sr_ctx;
	struct svc_cmd cmd;
	struct iovec iov[] = {
		{
		    .iov_base = &cmd,
		    .iov_len = sizeof(cmd),
		},
		{ .iov_base = NULL, .iov_len = 0 },
	};
	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 1 };
	ssize_t nread;

	if (e & ELE_HANGUP) {
		eloop_exit(sctx->svc_ctx->ctx_eloop, EXIT_SUCCESS);
		return;
	}
	if (e != ELE_READ) {
		logerrx("%s: unexpected operation %u", __func__, e);
		return;
	}

	nread = recvmsg(sctx->svc_fd, &msg, MSG_WAITALL | MSG_PEEK);
	if (nread == -1) {
		logerr("%s: recvmsg cmd", __func__);
		return;
	}
	if (nread != sizeof(cmd)) {
		if (nread != 0)
			logerrx("%s: invalid read len: %zd", __func__, nread);
		return;
	}

	if (sctx->svc_buflen < cmd.sc_datalen) {
		void *nbuf = realloc(sctx->svc_buf, cmd.sc_datalen);
		if (nbuf == NULL) {
			logerr("%s: realloc", __func__);
			return;
		}
		sctx->svc_buf = nbuf;
		sctx->svc_buflen = cmd.sc_datalen;
	}
	iov[1].iov_base = sctx->svc_buf;
	iov[1].iov_len = sctx->svc_buflen;
	msg.msg_iovlen = 2;

	sr->sr_result = cmd.sc_result;
	sr->sr_errno = cmd.sc_errno;

	nread = recvmsg(sctx->svc_fd, &msg, 0);
	if (nread == -1) {
		logerr("%s: recvmsg cmd", __func__);
		return;
	}
	if ((size_t)nread != sizeof(cmd) + cmd.sc_datalen) {
		logerrx("%s: read datalen mismatch: %zd != %zd", __func__,
		    nread, sizeof(cmd) + cmd.sc_datalen);
		return;
	}
	if (cmd.sc_datalen != 0) {
		sr->sr_datalen = cmd.sc_datalen;
		sr->sr_data = sctx->svc_buf;
	}

	/* We are either a dispatcher for the helper, or a blocking loop for a
	 * response */
	if (sctx->svc_dispatch != NULL)
		sctx->svc_dispatch(sctx, (struct plugin *)cmd.sc_plugin,
		    cmd.sc_cmd, sctx->svc_buf, cmd.sc_datalen);
	else
		eloop_endwait(sctx->svc_ctx->ctx_eloop, EXIT_SUCCESS);
}

static void
svc_readctx(void *arg, unsigned short e)
{
	struct svc_result sr = {
		.sr_ctx = arg,
	};

	return svc_recv(&sr, e);
}

ssize_t
svc_sendv(struct svc_ctx *sctx, struct plugin *p, unsigned int cmd,
    ssize_t result, struct iovec *iov, int iovlen)
{
	struct svc_cmd sc = {
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

	if ((size_t)(iovlen + msg.msg_iovlen) > ARRAYCOUNT(_iov)) {
		errno = ENOBUFS;
		return -1;
	}
	for (i = 0; i < iovlen; i++) {
		if (iov[i].iov_len == 0)
			continue;
		_iov[msg.msg_iovlen++] = iov[i];
		sc.sc_datalen += iov[i].iov_len;
	}

	ssize_t err = sendmsg(sctx->svc_fd, &msg, MSG_EOR);
	return err;
}

ssize_t
svc_send(struct svc_ctx *sctx, struct plugin *p, unsigned int cmd,
    ssize_t result, const void *data, size_t len)
{
	struct iovec iov[] = {
		{ .iov_base = UNCONST(data), .iov_len = len },
	};

	return svc_sendv(sctx, p, cmd, result, iov, len == 0 ? 0 : 1);
}

int
svc_runv(struct svc_ctx *sctx, struct plugin *p, unsigned int cmd,
    struct iovec *iov, int iovlen, ssize_t *res, void **rdata, size_t *rlen)
{
	struct svc_result result = {
		.sr_ctx = sctx,
	};
	int err;

	if (svc_sendv(sctx, p, cmd, 0, iov, iovlen) == -1) {
		logerr("%s: svc_write", __func__);
		return -1;
	}

	err = eloop_wait(sctx->svc_ctx->ctx_eloop, sctx->svc_fd, ELE_READ,
	    svc_recv, &result);
	if (err == -1)
		return -1;

	if (result.sr_result == -1)
		errno = result.sr_errno;
	if (res != NULL)
		*res = result.sr_result;
	if (rdata != NULL)
		*rdata = result.sr_data;
	if (rlen != NULL)
		*rlen = result.sr_datalen;
	return 0;
}

int
svc_run(struct svc_ctx *sctx, struct plugin *p, unsigned int cmd,
    const void *data, size_t len, ssize_t *res, void **rdata, size_t *rlen)
{
	struct iovec iov[] = {
		{ .iov_base = UNCONST(data), .iov_len = len },
	};

	return svc_runv(sctx, p, cmd, iov, len == 0 ? 0 : 1, res, rdata, rlen);
}

struct svc_ctx *
svc_init(struct ctx *ctx, const char *name,
    ssize_t (*dispatch)(struct svc_ctx *, struct plugin *, unsigned int,
	const void *, size_t))
{
	struct svc_ctx *sctx;
	int fdset[2], fd;
	pid_t pid;
	unsigned int logopts;

	sctx = malloc(sizeof(*sctx));
	if (sctx == NULL) {
		logerr("%s: malloc", __func__);
		return NULL;
	}

	sctx->svc_ctx = ctx;
	sctx->svc_fd = -1;
	sctx->svc_dispatch = NULL;

	sctx->svc_buflen = 1024;
	sctx->svc_buf = malloc(sctx->svc_buflen);
	if (sctx->svc_buf == NULL) {
		logerr("%s: malloc", __func__);
		goto error;
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
		0, fdset) == -1) {
		logerr("%s: socketpair", __func__);
		goto error;
	}

	pid = fork();
	switch (pid) {
	case -1:
		logerr("%s: fork", __func__);
		close(fdset[0]);
		close(fdset[1]);
		goto error;
	case 0:
		sctx->svc_fd = fdset[1];
		close(fdset[0]);
		break;
	default:
		sctx->svc_fd = fdset[0];
		close(fdset[1]);
		logdebugx("service: spawned %s on pid %ld", name, (long)pid);
		return sctx;
	}

	ctx->ctx_options &= ~DHCPSD_MAIN;
	ctx->ctx_options |= DHCPSD_UNPRIV | DHCPSD_RUN;
	sctx->svc_dispatch = dispatch;

	if (eloop_event_add(ctx->ctx_eloop, sctx->svc_fd, ELE_READ, svc_readctx,
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
	svc_free(sctx);
	return NULL;
}

void
svc_free(struct svc_ctx *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->svc_fd != -1)
		close(ctx->svc_fd);
	free(ctx->svc_buf);
	free(ctx);
}
