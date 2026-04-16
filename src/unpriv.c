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

#include <net/if.h>

#include "queue.h"

#ifdef AF_LINK
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#undef AF_PACKET /* Newer Illumos defines this */
#endif
#ifdef AF_PACKET
#include <netpacket/packet.h>
#endif

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "dhcpsd.h"
#include "if.h"
#include "logerr.h"
#include "plugin.h"
#include "service.h"
#include "unpriv.h"

#define U_GETIFADDRS  1
#define U_LEARNIF     2
#define U_FREEIF      3
#define U_GETADDRINFO 4

#define IFA_NADDRS    4

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
unpriv_getifaddrs(struct srv_ctx *ctx, struct ifaddrs **ifahead,
    const unsigned int *match_if_index)
{
	struct ifaddrs *ifa;
	char *bp, *sap;
	socklen_t salen;
	ssize_t result;
	void *rdata, *buf;
	size_t rdata_len, len;
	int err;

	err = srv_run(ctx, 0, U_GETIFADDRS, match_if_index,
	    match_if_index != NULL ? sizeof(*match_if_index) : 0, &result,
	    &rdata, &rdata_len);
	if (err == -1)
		return -1;

	/* Should be impossible - lo0 will always exist. */
	if (rdata_len == 0) {
		*ifahead = NULL;
		return 0;
	}

	/* Take our own copy of the data. */
	buf = malloc(rdata_len);
	if (buf == NULL)
		return -1;
	memcpy(buf, rdata, rdata_len);
	len = rdata_len;

	bp = buf;
	*ifahead = (struct ifaddrs *)(void *)bp;
	for (ifa = *ifahead; ifa != NULL; ifa = ifa->ifa_next) {
		if (len < ALIGN(sizeof(*ifa)) + ALIGN(IFNAMSIZ) +
			ALIGN(sizeof(salen) * IFA_NADDRS))
			goto err;
		bp += ALIGN(sizeof(*ifa));
		ifa->ifa_name = bp;
		bp += ALIGN(IFNAMSIZ);
		sap = bp;
		bp += ALIGN(sizeof(salen) * IFA_NADDRS);
		len -= ALIGN(sizeof(*ifa)) + ALIGN(IFNAMSIZ) +
		    ALIGN(sizeof(salen) * IFA_NADDRS);

#define COPYOUTSA(addr)                                         \
	do {                                                    \
		memcpy(&salen, sap, sizeof(salen));             \
		if (len < salen)                                \
			goto err;                               \
		if (salen != 0) {                               \
			(addr) = (struct sockaddr *)(void *)bp; \
			bp += ALIGN(salen);                     \
			len -= ALIGN(salen);                    \
		}                                               \
		sap += sizeof(salen);                           \
	} while (0 /* CONSTCOND */)

		COPYOUTSA(ifa->ifa_addr);
		COPYOUTSA(ifa->ifa_netmask);
		COPYOUTSA(ifa->ifa_broadaddr);

		memcpy(&salen, sap, sizeof(salen));
		if (len < salen)
			goto err;
		if (salen != 0) {
			ifa->ifa_data = bp;
			bp += ALIGN(salen);
			len -= ALIGN(salen);
		} else
			ifa->ifa_data = NULL;

		if (len != 0)
			ifa->ifa_next = (struct ifaddrs *)(void *)bp;
		else
			ifa->ifa_next = NULL;
	}
	return 0;

err:
	free(buf);
	*ifahead = NULL;
	errno = EINVAL;
	return -1;
}

int
unpriv_learnif(struct interface *ifp)
{
	struct srv_ctx *sctx = ifp->if_ctx->ctx_unpriv;
	ssize_t result;
	void *rdata;
	size_t rdata_len, len;
	int err;
	struct interface *ifp0;

	err = srv_run(sctx, NULL, U_LEARNIF, &ifp->if_index,
	    sizeof(ifp->if_index), &result, &rdata, &rdata_len);
	if (err == -1 || result == -1)
		return -1;

	if (rdata_len != sizeof(*ifp)) {
		errno = EINVAL;
		return -1;
	}

	ifp0 = (struct interface *)rdata;
	len = strlcpy(ifp->if_name, ifp0->if_name, sizeof((ifp->if_name)));
	if (len >= sizeof(ifp->if_name)) {
		errno = EINVAL;
		return -1;
	}

	ifp->if_hwtype = ifp0->if_hwtype;
	ifp->if_hwlen = ifp0->if_hwlen;

	if (ifp0->if_hwlen > sizeof(ifp->if_hwaddr)) {
		errno = EINVAL;
		return -1;
	}
	memcpy(ifp->if_hwaddr, ifp0->if_hwaddr, ifp0->if_hwlen);

	ifp->if_mtu = ifp0->if_mtu;

	return 0;
}

int
unpriv_freeif(struct interface *ifp)
{
	struct srv_ctx *sctx = ifp->if_ctx->ctx_unpriv;
	ssize_t result;
	int err;

	err = srv_run(sctx, NULL, U_FREEIF, &ifp->if_index,
	    sizeof(ifp->if_index), &result, NULL, 0);
	if (err == -1)
		return -1;
	return (int)result;
}

int
unpriv_getaddrinfo(struct srv_ctx *ctx, const char *hostname,
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

	err = srv_run(ctx, 0, U_GETADDRINFO, &u_gai, sizeof(u_gai), &result,
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
unpriv_dispatch_getifaddrs(struct srv_ctx *sctx, const void *data, size_t len)
{
	struct ifaddrs *ifaddrs = NULL, *ifa;
	ssize_t err = -1;
	void *buf = NULL;
	uint8_t *bp, *sap;
	socklen_t salen;
	bool match_index, matching = false;
	unsigned int if_index;

	if (len == sizeof(if_index)) {
		memcpy(&if_index, data, sizeof(if_index));
		match_index = true;
	} else
		match_index = false;

	len = 0;
	if (getifaddrs(&ifaddrs) == -1)
		goto err;
	if (ifaddrs == NULL) {
		err = 0;
		goto err;
	}

	/* Work out the buffer length required.
	 * Ensure everything is aligned correctly, which does
	 * create a larger buffer than what is needed to send,
	 * but makes creating the same structure in the client
	 * much easier. */
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (match_index) {
			switch (if_link_match_index(ifa->ifa_addr, if_index)) {
			case -1:
				if (!matching)
					continue;
				break;
			case 0:
				matching = false;
				continue;
			case 1:
				matching = true;
				break;
			}
		}
		len += ALIGN(sizeof(*ifa));
		len += ALIGN(IFNAMSIZ);
		len += ALIGN(sizeof(salen) * IFA_NADDRS);
		if (ifa->ifa_addr != NULL)
			len += ALIGN(sa_len(ifa->ifa_addr));
		if (ifa->ifa_netmask != NULL)
			len += ALIGN(sa_len(ifa->ifa_netmask));
		if (ifa->ifa_broadaddr != NULL)
			len += ALIGN(sa_len(ifa->ifa_broadaddr));
#ifdef BSD
		/*
		 * On BSD we need to carry ifa_data so we can access
		 * if_data->ifi_link_state
		 */
		if (ifa->ifa_addr != NULL &&
		    ifa->ifa_addr->sa_family == AF_LINK)
			len += ALIGN(sizeof(struct if_data));
#endif
	}

	/* Use calloc to set everything to zero.
	 * This satisfies memory sanitizers because we don't write
	 * where we don't need to. */
	buf = calloc(1, len);
	if (buf == NULL) {
		freeifaddrs(ifaddrs);
		return -1;
	}

	bp = buf;
	matching = false;
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (match_index) {
			switch (if_link_match_index(ifa->ifa_addr, if_index)) {
			case -1:
				if (!matching)
					continue;
				break;
			case 0:
				matching = false;
				continue;
			case 1:
				matching = true;
				break;
			}
		}
		if (if_sockaddr_active(sctx->srv_ctx, ifa->ifa_name,
			ifa->ifa_addr) != 1)
			continue;

		memcpy(bp, ifa, sizeof(*ifa));
		bp += ALIGN(sizeof(*ifa));

		strlcpy((char *)bp, ifa->ifa_name, IFNAMSIZ);
		bp += ALIGN(IFNAMSIZ);
		sap = bp;
		bp += ALIGN(sizeof(salen) * IFA_NADDRS);

#define COPYINSA(addr)                                      \
	do {                                                \
		if ((addr) != NULL)                         \
			salen = sa_len((addr));             \
		else                                        \
			salen = 0;                          \
		if (salen != 0) {                           \
			memcpy(sap, &salen, sizeof(salen)); \
			memcpy(bp, (addr), salen);          \
			bp += ALIGN(salen);                 \
		}                                           \
		sap += sizeof(salen);                       \
	} while (0 /*CONSTCOND */)

		COPYINSA(ifa->ifa_addr);
		COPYINSA(ifa->ifa_netmask);
		COPYINSA(ifa->ifa_broadaddr);

#ifdef BSD
		if (ifa->ifa_addr != NULL &&
		    ifa->ifa_addr->sa_family == AF_LINK) {
			salen = (socklen_t)sizeof(struct if_data);
			memcpy(bp, ifa->ifa_data, salen);
			bp += ALIGN(salen);
		} else
#endif
			salen = 0;
		memcpy(sap, &salen, sizeof(salen));
	}
	len = (size_t)(bp - (uint8_t *)buf);

	err = 0;
err:
	freeifaddrs(ifaddrs);
	err = srv_send(sctx, NULL, U_GETIFADDRS, err, buf, len);
	free(buf);
	return err;
}

static ssize_t
unpriv_dispatch_learnif(struct srv_ctx *sctx, const void *data, size_t len)
{
	struct ctx *ctx = sctx->srv_ctx;
	struct interface *ifp = NULL;
	unsigned int if_index;
	ssize_t err = -1;
	size_t nlen;
	void *buf = NULL;
	struct ifaddrs *ifaddrs = NULL, *ifa;
	bool found_if_index = false;

	if (len != sizeof(if_index)) {
		errno = EINVAL;
		len = 0;
		goto err;
	}
	memcpy(&if_index, data, len);
	len = 0;

	TAILQ_FOREACH(ifp, ctx->ctx_ifaces, if_next) {
		if (ifp->if_index == if_index) {
			found_if_index = true;
			break;
		}
	}
	if (ifp == NULL) {
		ifp = calloc(1, sizeof(*ifp));
		if (ifp == NULL)
			goto err;
		ifp->if_ctx = ctx;
		ifp->if_index = if_index;
	}

	if (getifaddrs(&ifaddrs) != 0)
		goto err;
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (sa_is_link(ifa->ifa_addr) == 1 &&
		    if_link_match_index(ifa->ifa_addr, if_index) == 1 &&
		    if_sockaddr_active(sctx->srv_ctx, ifa->ifa_name,
			ifa->ifa_addr) == 1)
			break;
	}

	if (ifa == NULL) {
		errno = ESRCH;
		goto err;
	}
	nlen = strlcpy(ifp->if_name, ifa->ifa_name, sizeof(ifp->if_name));
	if (nlen > sizeof(ifp->if_name)) {
		errno = EINVAL;
		goto err;
	}
	if_update(ifp, ifa->ifa_addr);
	if_update_mtu(ifp);

	err = 0;
	buf = ifp;
	len = sizeof(*ifp);
	if (!found_if_index) {
		TAILQ_INSERT_TAIL(ctx->ctx_ifaces, ifp, if_next);
		/* stop ifp being freed below */
		found_if_index = true;
	}

err:
	freeifaddrs(ifaddrs);
	if (!found_if_index)
		if_free(ifp);
	return srv_send(sctx, NULL, U_LEARNIF, err, buf, len);
}

static ssize_t
unpriv_dispatch_freeif(struct srv_ctx *sctx, const void *data, size_t len)
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
	return srv_send(sctx, NULL, U_FREEIF, err, NULL, 0);
}

static ssize_t
unpriv_dispatch_getaddrinfo(struct srv_ctx *sctx, const void *data, size_t len)
{
	const struct unpriv_getaddrinfo *u_gai = data;
	const char *hostname, *servname;
	struct addrinfo ai_hints = { .ai_family = AF_UNSPEC },
			*ai_result = NULL, *ain;
	int err = -1;
	struct unpriv_addrinfo *reply = NULL, *rn;
	size_t n;
	ssize_t res;

	if (len != sizeof(*u_gai)) {
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

	res = srv_send(sctx, NULL, U_GETADDRINFO, err, reply,
	    sizeof(*reply) * n);
	free(reply);
	return res;

err:
	freeaddrinfo(ai_result);
	free(reply);
	return srv_send(sctx, NULL, U_GETADDRINFO, err, NULL, 0);
}

static ssize_t
unpriv_dispatch(struct srv_ctx *sctx, struct plugin *p, unsigned int cmd,
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
	case U_GETIFADDRS:
		return unpriv_dispatch_getifaddrs(sctx, data, len);
	case U_LEARNIF:
		return unpriv_dispatch_learnif(sctx, data, len);
	case U_FREEIF:
		return unpriv_dispatch_freeif(sctx, data, len);
	case U_GETADDRINFO:
		return unpriv_dispatch_getaddrinfo(sctx, data, len);
	default:
		errno = EINVAL;
		logerr(__func__);
		return srv_send(sctx, NULL, cmd, -1, NULL, 0);
	}
}

struct srv_ctx *
unpriv_init(struct ctx *ctx)
{
	if (ctx->ctx_unpriv != NULL)
		goto out;
	ctx->ctx_unpriv = srv_init(ctx, "unprivileged helper", unpriv_dispatch);

	if (ctx->ctx_unpriv == NULL)
		return NULL;

	if (ctx->ctx_options & DHCPSD_RUN) {
		ctx->ctx_options |= DHCPSD_UNPRIV;
		dhcpsd_dropperms(0);
#ifdef HAVE_SETPROCTITLE
		setproctitle("unprivileged helper");
#endif
	}

out:
	return ctx->ctx_unpriv;
}
