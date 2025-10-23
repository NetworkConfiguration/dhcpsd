/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - unprivileged service helper
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
#include "dhcpsd.h"
#include "logerr.h"
#include "plugin.h"
#include "service.h"
#include "unpriv.h"

#define U_GETADDRINFO 1
#define U_GETADDRINFO 1

struct unpriv_addrinfo {
	int u_ai_flags;
	int u_ai_family;
	int u_ai_socktype;
	int u_ai_protocol;
	socklen_t u_ai_addrlen;
	struct sockaddr_storage u_ai_addr;
	char u_ai_canonname[MAXHOSTNAMELEN + 1];
};

struct unpriv_getaddrinfo {
	char u_gai_hostname[MAXHOSTNAMELEN + 1];
	char u_gai_servname[MAXHOSTNAMELEN + 1];
	struct unpriv_addrinfo u_gai_hints;
};

int
unpriv_getaddrinfo(struct svc_ctx *ctx, const char *hostname,
    const char *servname, struct addrinfo *hints,
    struct addrinfo **restrict res)
{
	struct unpriv_getaddrinfo u_gai = { .u_gai_hostname[0] = '\0' };
	struct unpriv_addrinfo *u_ai;
	ssize_t result;
	void *rdata;
	size_t rdata_len;
	int err;
	struct addrinfo *ai, *aif = NULL, *ail = NULL;

	struct addrinfo h = {
		.ai_family = AF_INET,
	};
	hints = &h;

	if (hostname != NULL)
		strlcpy(u_gai.u_gai_hostname, hostname,
		    sizeof(u_gai.u_gai_hostname));
	if (servname != NULL)
		strlcpy(u_gai.u_gai_servname, servname,
		    sizeof(u_gai.u_gai_servname));
	if (hints != NULL) {
		u_gai.u_gai_hints.u_ai_flags = hints->ai_flags;
		u_gai.u_gai_hints.u_ai_family = hints->ai_family;
		u_gai.u_gai_hints.u_ai_socktype = hints->ai_socktype;
		u_gai.u_gai_hints.u_ai_protocol = hints->ai_protocol;
	}

	err = svc_run(ctx, 0, U_GETADDRINFO, &u_gai, sizeof(u_gai), &result,
	    &rdata, &rdata_len);
	if (err == -1)
		return -1;

	for (u_ai = rdata; rdata_len != 0; rdata_len -= sizeof(*u_ai), u_ai++) {
		if (rdata_len < sizeof(*u_ai)) {
			logerrx("%s: ai_addrinfo truncated", __func__);
			goto err;
		}

		ai = malloc(sizeof(*ai) + u_ai->u_ai_addrlen);
		if (ai == NULL) {
			logerr("%s: malloc(addrinfo)", __func__);
			goto err;
		}
		if (aif == NULL)
			aif = ai;
		if (ail != NULL)
			ail->ai_next = ai;
		ail = ai;

		ai->ai_flags = u_ai->u_ai_flags;
		ai->ai_family = u_ai->u_ai_family;
		ai->ai_socktype = u_ai->u_ai_socktype;
		ai->ai_protocol = u_ai->u_ai_protocol;
		ai->ai_addrlen = u_ai->u_ai_addrlen;
		ai->ai_next = NULL;

		if (u_ai->u_ai_addrlen != 0) {
			ai->ai_addr = (struct sockaddr *)(ai + 1);
			memcpy(ai->ai_addr, &u_ai->u_ai_addr, ai->ai_addrlen);
		} else
			ai->ai_addr = NULL;

		if (u_ai->u_ai_canonname[0] != '\0') {
			ai->ai_canonname = strdup(u_ai->u_ai_canonname);
			if (ai->ai_canonname == NULL) {
				logerr("%s: malloc(ai_addr)", __func__);
				goto err;
			}
		} else
			ai->ai_canonname = NULL;
	}

	*res = aif;
	return (int)result;

err:
	if (aif != NULL)
		freeaddrinfo(aif);
	/*
	 * clang-tidy reports that memory pointed to by ail is not freed,
	 * but is happy with aif being freed.
	 * ail is just a pointer to the last element in the list of aif
	 * so this is a false positive.
	 */
	return -1; // NOLINT
}

static ssize_t
unpriv_dispatch(struct svc_ctx *sctx, struct plugin *p, unsigned int cmd,
    const void *data, size_t len)
{
	const struct unpriv_getaddrinfo *u_gai = data;
	const char *hostname, *servname;
	struct addrinfo ai_hints = { .ai_family = AF_UNSPEC },
			*ai_result = NULL, *ain;
	int err = -1;
	struct unpriv_addrinfo *reply = NULL, *rn;
	size_t n;
	ssize_t res;

	if (p != NULL) {
		if (p->p_dispatch != NULL)
			return p->p_dispatch(p, sctx, cmd, data, len);
		errno = ENOSYS;
		logerr(__func__);
		goto err;
	}

	if (cmd != U_GETADDRINFO || len != sizeof(*u_gai)) {
		errno = EINVAL;
		logerr(__func__);
		goto err;
	}

	if (u_gai->u_gai_hostname[0] != '\0')
		hostname = u_gai->u_gai_hostname;
	else
		hostname = NULL;
	if (u_gai->u_gai_servname[0] != '\0')
		servname = u_gai->u_gai_hostname;
	else
		servname = NULL;
	ai_hints.ai_flags = u_gai->u_gai_hints.u_ai_flags;
	ai_hints.ai_family = u_gai->u_gai_hints.u_ai_family;
	ai_hints.ai_socktype = u_gai->u_gai_hints.u_ai_socktype;
	ai_hints.ai_protocol = u_gai->u_gai_hints.u_ai_protocol;
	err = getaddrinfo(hostname, servname, &ai_hints, &ai_result);
	if (err != 0)
		goto err;

	n = 0;
	for (ain = ai_result; ain != NULL; ain = ain->ai_next)
		n++;

	reply = reallocarray(NULL, n, sizeof(*reply));
	if (reply == NULL) {
		logerr("%s: reallocarray", __func__);
		err = -1;
		goto err;
	}

	memset(reply, 0, sizeof(*reply) * n);
	for (ain = ai_result, rn = reply; ain != NULL;
	     ain = ain->ai_next, rn++) {
		rn->u_ai_flags = ain->ai_flags;
		rn->u_ai_family = ain->ai_family;
		rn->u_ai_socktype = ain->ai_socktype;
		rn->u_ai_protocol = ain->ai_protocol;
		rn->u_ai_addrlen = ain->ai_addrlen;
		memset(&rn->u_ai_addr, 0, sizeof(rn->u_ai_addr));
		if (ain->ai_addrlen > 0)
			memcpy(&rn->u_ai_addr, ain->ai_addr, ain->ai_addrlen);
		memset(rn->u_ai_canonname, 0, sizeof(rn->u_ai_canonname));
		if (ain->ai_canonname != NULL)
			strlcpy(rn->u_ai_canonname, ain->ai_canonname,
			    sizeof(rn->u_ai_canonname));
	}

	freeaddrinfo(ai_result);

	res = svc_send(sctx, NULL, U_GETADDRINFO, err, reply,
	    sizeof(*reply) * n);
	free(reply);
	return res;

err:
	freeaddrinfo(ai_result);
	free(reply);
	return svc_send(sctx, NULL, cmd, err, NULL, 0);
}

struct svc_ctx *
unpriv_init(struct ctx *ctx)
{
	if (ctx->ctx_unpriv != NULL)
		goto out;
	ctx->ctx_unpriv = svc_init(ctx, "unprivileged helper", unpriv_dispatch);

	if (ctx->ctx_unpriv == NULL)
		return NULL;

	if (ctx->ctx_options & DHCPSD_RUN) {
		ctx->ctx_options |= DHCPSD_UNPRIV;
		dhcpsd_dropperms(0);
#ifdef BSD
		setproctitle("unprivileged helper");
#endif
	}

out:
	return ctx->ctx_unpriv;
}
