/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - interface definition
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
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include <stdbool.h>

#include "queue.h"
#include "src/common.h"
#include "src/priv.h"
#include "src/unpriv.h"

#ifdef AF_LINK
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in_var.h>
#undef AF_PACKET /* Newer Illumos defines this */
#endif
#ifdef AF_PACKET
#include <netpacket/packet.h>
#endif

#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "config.h"
#include "dhcpsd.h"
#include "if.h"
#include "if_ether.h"
#include "if_none.h"
#include "logerr.h"

void
if_update_output(struct interface *ifp)
{
	switch (ifp->if_hwtype) {
	case ARPHRD_ETHER:
		ifp->if_output = if_ether_output;
		break;
	default:
		ifp->if_output = if_none_output;
		break;
	}
}

void
if_update(struct interface *ifp, struct sockaddr *sa)
{
#ifdef AF_LINK
	struct sockaddr_dl *sdl = (void *)sa;

	ifp->if_index = sdl->sdl_index;

	switch (sdl->sdl_type) {
#ifdef IFT_BRIDGE
	case IFT_BRIDGE: /* FALLTHROUGH */
#endif
#ifdef IFT_PROPVIRTUAL
	case IFT_PROPVIRTUAL: /* FALLTHROUGH */
#endif
#ifdef IFT_TUNNEL
	case IFT_TUNNEL: /* FALLTHROUGH */
#endif
	case IFT_LOOP: /* FALLTHROUGH */
	case IFT_PPP:  /* FALLTHROUGH */
#ifdef IFT_L2VLAN
	case IFT_L2VLAN: /* FALLTHROUGH */
#endif
#ifdef IFT_L3IPVLAN
	case IFT_L3IPVLAN: /* FALLTHROUGH */
#endif
	case IFT_ETHER:
		ifp->if_hwtype = ARPHRD_ETHER;
		break;
#ifdef notyet
#ifdef IFT_IEEE1394
	case IFT_IEEE1394:
		ifp->if_hwtype = ARPHRD_IEEE1394;
		break;
#endif
#ifdef IFT_INFINIBAND
	case IFT_INFINIBAND:
		ifp->if_hwtype = ARPHRD_INFINIBAND;
		break;
#endif
#endif
	default:
		logdebugx("%s: unsupported interface type 0x%.2x", ifp->if_name,
		    sdl->sdl_type);
		break;
	}

	if (sdl->sdl_alen <= sizeof(ifp->if_hwaddr)) {
		ifp->if_hwlen = sdl->sdl_alen;
		memcpy(ifp->if_hwaddr, LLADDR(sdl), sdl->sdl_alen);
	}
#elif defined(AF_PACKET)
	struct sockaddr_ll *sll = (void *)sa;
	ifp->if_index = (unsigned int)sll->sll_ifindex;
	ifp->if_hwtype = sll->sll_hatype;
	if (sll->sll_halen <= sizeof(ifp->if_hwaddr)) {
		ifp->if_hwlen = sll->sll_halen;
		memcpy(ifp->if_hwaddr, sll->sll_addr, sll->sll_halen);
	}
#endif
}

int
if_update_mtu(struct interface *ifp)
{
	struct ctx *ctx = ifp->if_ctx;
	struct ifreq ifr = { .ifr_mtu = 0 };

	strlcpy(ifr.ifr_name, ifp->if_name, sizeof(ifr.ifr_name));
	if (ioctl(ctx->ctx_pf_inet_fd, SIOCGIFMTU, &ifr, sizeof(ifr)) == -1) {
		logerr("%s SIOCGIFMTU", __func__);
		return -1;
	}

	ifp->if_mtu = ifr.ifr_mtu;
	return 0;
}

int
if_sockaddr_active(struct ctx *ctx, const char *if_name,
    const struct sockaddr *sa)
{
#ifdef IFLR_ACTIVE
	const struct sockaddr_dl *sdl = (const void *)sa;
	struct if_laddrreq iflr = {
		.flags = IFLR_PREFIX,
		.prefixlen = (unsigned int)sdl->sdl_alen * NBBY,
	};

	strlcpy(iflr.iflr_name, if_name, sizeof(iflr.iflr_name));
	memcpy(&iflr.addr, sa, MIN(sa->sa_len, sizeof(iflr.addr)));

	if (ioctl(ctx->ctx_pf_link_fd, SIOCGLIFADDR, &iflr) == -1)
		return 0;
	if (!(iflr.flags & IFLR_ACTIVE))
		return 0;
#else
	UNUSED(ctx);
	UNUSED(if_name);
	UNUSED(sa);
#endif

	return 1;
}

int
if_link_match_index(const struct sockaddr *sa, unsigned int if_index)
{
	if (sa_is_link(sa) != 1) {
		errno = EINVAL;
		return -1;
	}

#ifdef AF_LINK
	const struct sockaddr_dl *sdl = (const void *)sa;
	return sdl->sdl_index == if_index ? 1 : 0;
#elif defined(AF_PACKET)
	const struct sockaddr_ll *sll = (const void *)sa;
	return (unsigned int)sll->sll_ifindex == if_index ? 1 : 0;
#else
#error undefined platform
#endif
}

int
if_learnifaces(struct ctx *ctx)
{
	struct ifaddrs *ifaddrs, *ifa;
	struct interface *ifp;
	int err = -1;

	if (unpriv_getifaddrs(ctx->ctx_unpriv, &ifaddrs, NULL) == -1) {
		logerr("%s: unpriv_getifaddrs", __func__);
		return -1;
	}
	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		if (!sa_is_link(ifa->ifa_addr))
			continue;

		if (if_sockaddr_active(ctx, ifa->ifa_name, ifa->ifa_addr) != 1)
			continue;

		ifp = calloc(1, sizeof(*ifp));
		if (ifp == NULL) {
			logerr("%s: malloc", __func__);
			goto err;
		}
		ifp->if_ctx = ctx;
		strlcpy(ifp->if_name, ifa->ifa_name, sizeof(ifp->if_name));

		if_update(ifp, ifa->ifa_addr);
		if_update_output(ifp);
		if (if_update_mtu(ifp) == -1) {
			logerr("%s: if_update_mtu: %s", __func__,
			    ifa->ifa_name);
			free(ifp);
			continue;
		}

		TAILQ_INSERT_TAIL(ctx->ctx_ifaces, ifp, if_next);
	}

	err = 0;

err:
	free(ifaddrs);
	return err;
}

struct interface *
if_findifpfromcmsg(struct ctx *ctx, struct msghdr *msg, void *to)
{
	struct cmsghdr *cm;
	unsigned int if_index = 0;
	struct interface *ifp;
#ifdef IP_RECVIF
	struct sockaddr_dl sdl = { .sdl_len = 0 };
#else
	struct in_pktinfo ipi;
#endif
#ifdef INET6
	struct in6_pktinfo ipi6;
#endif

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(msg); cm;
	    cm = (struct cmsghdr *)CMSG_NXTHDR(msg, cm)) {
		if (cm->cmsg_level == IPPROTO_IP) {
			switch (cm->cmsg_type) {
#ifdef IP_RECVIF
			case IP_RECVIF:
				if (cm->cmsg_len <
				    offsetof(struct sockaddr_dl, sdl_index) +
					sizeof(sdl.sdl_index))
					continue;
				memcpy(&sdl, CMSG_DATA(cm),
				    MIN(sizeof(sdl), cm->cmsg_len));
				if_index = sdl.sdl_index;
				break;
#else
			case IP_PKTINFO:
				if (cm->cmsg_len != CMSG_LEN(sizeof(ipi)))
					continue;
				memcpy(&ipi, CMSG_DATA(cm), sizeof(ipi));
				if_index = (unsigned int)ipi.ipi_ifindex;
				if (to != NULL)
					memcpy(to, &ipi.ipi_addr,
					    sizeof(ipi.ipi_addr));
				break;
#endif
#ifdef IP_RECVDSTADDR
			case IP_RECVDSTADDR:
#else
			case IP_RECVORIGDSTADDR:
#endif
				if (to == NULL ||
				    cm->cmsg_len !=
					CMSG_LEN(sizeof(struct in_addr)))
					continue;
				memcpy(to, CMSG_DATA(cm),
				    sizeof(struct in_addr));
				break;
			}
		}
#ifdef INET6
		if (cm->cmsg_level == IPPROTO_IPV6) {
			switch (cm->cmsg_type) {
			case IPV6_PKTINFO:
				if (cm->cmsg_len != CMSG_LEN(sizeof(ipi6)))
					continue;
				memcpy(&ipi6, CMSG_DATA(cm), sizeof(ipi6));
				if_index = (unsigned int)ipi6.ipi6_ifindex;
				break;
			}
		}
#endif
	}

	/* Find the receiving interface */
	TAILQ_FOREACH(ifp, ctx->ctx_ifaces, if_next) {
		if (ifp->if_index == if_index)
			break;
	}

	if (ifp == NULL) {
		int i;

		if (!(ctx->ctx_options & DHCPSD_WAITIF)) {
			errno = ESRCH;
			return NULL;
		}

		ifp = calloc(1, sizeof(*ifp));
		if (ifp == NULL)
			return NULL;
		ifp->if_ctx = ctx;
		ifp->if_index = if_index;

		if (unpriv_learnif(ifp) == -1) {
			logerr("%s: unpriv_learnif", __func__);
			/* Avoid neededless checks */
			free(ifp);
			return NULL;
		}

		if (ctx->ctx_argc == 0)
			ifp->if_flags |= IF_ACTIVE;
		else {
			for (i = 0; i < ctx->ctx_argc; i++) {
				if (strcmp(ifp->if_name, ctx->ctx_argv[i]) ==
				    0) {
					ifp->if_flags |= IF_ACTIVE;
				}
			}
		}
		if (ifp->if_flags & IF_ACTIVE) {
			logdebugx("%s: activated interface (%d)", ifp->if_name,
			    ifp->if_index);
			if (dhcpsd_configure_pools(ifp) == -1) {
				logerr("%s: dhcpsd_configure_pools",
				    ifp->if_name);
				if_free(ifp);
				return NULL;
			}
		}
		TAILQ_INSERT_TAIL(ctx->ctx_ifaces, ifp, if_next);
	}

	return ifp;
}

void
if_free(struct interface *ifp)
{
	bool srv_if_free;
	unsigned int options;

	if (ifp == NULL)
		return;

	/* If we are exiting there is no need to notify our services
	 * that we are freeing an interface. */
	options = ifp->if_ctx->ctx_options;
	srv_if_free = options & DHCPSD_MAIN && !(options & DHCPSD_EXITING);

	if (srv_if_free) {
		if (options & DHCPSD_WAITIF) {
			loginfox("%s: deactiving interface", ifp->if_name);
			if (priv_freeif(ifp) == -1 && errno != ESRCH)
				logerr("%s: priv_freeif: %s", __func__,
				    ifp->if_name);
		}
		if (unpriv_freeif(ifp) == -1 && errno != ESRCH)
			logerr("%s: unpriv_freeif: %s", __func__, ifp->if_name);
	}
	if (ifp->if_bpf != NULL)
		bpf_close(ifp->if_bpf);
	free(ifp->if_pools);
	if (srv_if_free && options & DHCPSD_WAITIF)
		logdebugx("%s: deactivated interface", ifp->if_name);
	free(ifp);
}
