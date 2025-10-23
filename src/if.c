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
#ifdef AF_LINK
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in_var.h>
#undef AF_PACKET /* Newer Illumos defines this */
#endif
#ifdef AF_PACKET
#include <netpacket/packet.h>
#endif

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

int
if_learnifaces(struct ctx *ctx)
{
	struct ifaddrs *ifa;
	struct interface *ifp;
#ifdef AF_LINK
	const struct sockaddr_dl *sdl;
#ifdef IFLR_ACTIVE
	struct if_laddrreq iflr = { .flags = IFLR_PREFIX };
#endif
#elif defined(AF_PACKET)
	const struct sockaddr_ll *sll;
#endif

	for (ifa = ctx->ctx_ifa; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
#ifdef AF_LINK
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
#elif defined(AF_PACKET)
		if (ifa->ifa_addr->sa_family != AF_PACKET)
			continue;
#endif

#ifdef IFLR_ACTIVE
		sdl = (const void *)ifa->ifa_addr;

		/* We need to check for active address */
		strlcpy(iflr.iflr_name, ifa->ifa_name, sizeof(iflr.iflr_name));
		memcpy(&iflr.addr, ifa->ifa_addr,
		    MIN(ifa->ifa_addr->sa_len, sizeof(iflr.addr)));
		iflr.flags = IFLR_PREFIX;
		iflr.prefixlen = (unsigned int)sdl->sdl_alen * NBBY;
		if (ioctl(ctx->ctx_pf_link_fd, SIOCGLIFADDR, &iflr) == -1 ||
		    !(iflr.flags & IFLR_ACTIVE))
			continue;
#endif

		ifp = calloc(1, sizeof(*ifp));
		if (ifp == NULL) {
			logerr("%s: malloc", __func__);
			return -1;
		}
		ifp->if_ctx = ctx;
		strlcpy(ifp->if_name, ifa->ifa_name, sizeof(ifp->if_name));

#ifdef AF_LINK
#ifndef IFLR_ACTIVE
		sdl = (const void *)ifa->ifa_addr;
#endif

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
			logdebugx("%s: unsupported interface type 0x%.2x",
			    ifp->if_name, sdl->sdl_type);
			break;
		}
		ifp->if_index = sdl->sdl_index;
		ifp->if_hwlen = sdl->sdl_alen;
		if (ifp->if_hwlen != 0) {
#ifdef CLLADDR
			memcpy(ifp->if_hwaddr, CLLADDR(sdl), ifp->if_hwlen);
#else
			memcpy(ifp->if_hwaddr, LLADDR(sdl), ifp->if_hwlen);
#endif
		}
#elif defined(AF_PACKET)
		sll = (const void *)ifa->ifa_addr;
		ifp->if_index = (unsigned int)sll->sll_ifindex;
		ifp->if_hwtype = sll->sll_hatype;
		ifp->if_hwlen = sll->sll_halen;
		if (ifp->if_hwlen != 0)
			memcpy(ifp->if_hwaddr, sll->sll_addr, ifp->if_hwlen);
#endif

		switch (ifp->if_hwtype) {
		case ARPHRD_ETHER:
			ifp->if_output = if_ether_output;
			break;
		default:
			ifp->if_output = if_none_output;
			break;
		}

		TAILQ_INSERT_TAIL(ctx->ctx_ifaces, ifp, if_next);
	}

	return 0;
}

struct interface *
if_findifpfromcmsg(struct ctx *ctx, struct msghdr *msg, void *to)
{
	struct cmsghdr *cm;
	unsigned int if_index = 0;
	struct interface *ifp;
#ifdef IP_RECVIF
	struct sockaddr_dl sdl;
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
			return ifp;
	}

	/* No support for learning new interfaces after we have loaded. */
	errno = ESRCH;
	return ifp;
}

void
if_free(struct interface *ifp)
{
	if (ifp == NULL)
		return;
	if (ifp->if_bpf != NULL)
		bpf_close(ifp->if_bpf);
	free(ifp->if_pools);
	free(ifp);
}
