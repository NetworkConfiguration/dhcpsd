/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd: DHCP
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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <fcntl.h>

#ifdef AF_LINK
#include <net/if_dl.h>
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Get access to private members not passed to plugins */
#define DHCP_PRIVATE

#include "config.h"

#ifdef HAVE_SYS_RBTREE_H
#include <sys/rbtree.h>
#else
#include "rbtree.h"
#endif

#include "bpf.h"
#include "common.h"
#include "dhcp.h"
#include "dhcp_lease.h"
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

/* Default cache timers, in seconds */
static unsigned int dhcp_cache_oldaddr = 30;
static unsigned int dhcp_cache_declined = 3600;
static unsigned int dhcp_plugin_cache_declined = 30;

struct dhcp_message_type {
	uint8_t mt_type;
	const char *mt_name;
};

static const struct dhcp_message_type dhcp_message_types[] = {
	{ DHCP_BOOTREQUEST, "BOOTREQUEST" }, { DHCP_DISCOVER, "DISCOVER" },
	{ DHCP_OFFER, "OFFER" }, { DHCP_REQUEST, "REQUEST" },
	{ DHCP_DECLINE, "DECLINE" }, { DHCP_ACK, "ACK" }, { DHCP_NAK, "NAK" },
	{ DHCP_RELEASE, "RELEASE" }, { DHCP_INFORM, "INFORM" },
	{ DHCP_FORCERENEW, "FORCERENEW" }, { 0, NULL }
};

/* IPv4 pseudo header used for computing TCP and UDP checksums. */
struct ip_pseudo {
	struct in_addr ipp_src;
	struct in_addr ipp_dst;
	uint8_t ipp_pad; /* must be zero */
	uint8_t ipp_p;
	uint16_t ipp_len;
};

static void dhcp_set_expire_timeout(struct dhcp_ctx *ctx);
static void dhcp_handlebootp(struct interface *ifp, struct bootp *bootp,
    size_t len, uint32_t flags);

static inline int
dhcp_cookiecmp(struct bootp *bootp)
{
	uint32_t cookie = htonl(MAGIC_COOKIE);

	return memcmp(bootp->vend, &cookie, sizeof(cookie));
}

static char dhcp_flags[12];
const char *
dhcp_ftoa(uint32_t flags)
{
	char *bp = dhcp_flags;

	if (flags & DL_ADDRESS)
		*bp++ = 'A';
	if (flags & DL_DECLINED)
		*bp++ = 'D';
	if (flags & DL_INFORMED)
		*bp++ = 'I';
	if (flags & DL_OFFERED)
		*bp++ = 'O';
	if (flags & DL_LEASED)
		*bp++ = 'L';
	if (flags & DL_HOSTNAME)
		*bp++ = 'H';
	if (flags & DL_UPDATE_DNSA)
		*bp++ = 'N';
	if (flags & DL_UPDATE_DNSPTR)
		*bp++ = 'P';
	if (flags & DL_PLUGIN_HOSTNAME)
		*bp++ = 'h';
	if (flags & DL_PLUGIN_DNSA)
		*bp++ = 'n';
	if (flags & DL_PLUGIN_DNSPTR)
		*bp++ = 'p';
	if (flags & DL_PLUGIN_ADDRESS)
		*bp++ = 'a';
	if (flags & DL_PLUGIN_DECLINED)
		*bp++ = 'd';
	if (flags & DL_PLUGIN_RESERVED)
		*bp++ = 'r';
	*bp = '\0';

	return dhcp_flags;
}

uint32_t
dhcp_atof(const char *flagstr)
{
	uint32_t flags = 0;
	const char *f;

	for (f = flagstr; *f != '\0'; f++) {
		switch (*f) {
		case 'D':
			flags |= DL_DECLINED;
			break;
		case 'I':
			flags |= DL_INFORMED;
			break;
		case 'O':
			flags |= DL_OFFERED;
			break;
		case 'L':
			flags |= DL_LEASED;
			break;
		case 'H':
			flags |= DL_HOSTNAME;
			break;
		case 'N':
			flags |= DL_UPDATE_DNSA;
			break;
		case 'P':
			flags |= DL_UPDATE_DNSPTR;
			break;
		case 'h':
			flags |= DL_PLUGIN_HOSTNAME;
			break;
		case 'n':
			flags |= DL_PLUGIN_DNSA;
			break;
		case 'p':
			flags |= DL_PLUGIN_DNSPTR;
			break;
		case 'a':
			flags |= DL_PLUGIN_ADDRESS;
			break;
		case 'd':
			flags |= DL_PLUGIN_DECLINED;
			break;
		case 'r':
			flags |= DL_PLUGIN_RESERVED;
			break;
		default:
			errno = EINVAL;
		}
	}

	return flags;
}

static int
dhcp_cmp_lease(__unused void *context, const void *node1, const void *node2)
{
	const struct dhcp_lease *dl1 = node1, *dl2 = node2;

	if (timespeccmp(&dl1->dl_expires, &dl2->dl_expires, <))
		return -1;
	if (timespeccmp(&dl1->dl_expires, &dl2->dl_expires, >))
		return 1;
	if (dl1->dl_clientid[0] != dl2->dl_clientid[0])
		return dl1->dl_clientid[0] - dl2->dl_clientid[0];
	return memcmp(dl1->dl_clientid + 1, dl2->dl_clientid + 1,
	    dl1->dl_clientid[0]);
}

static rb_tree_ops_t dhcp_expire_lease_ops = {
	.rbto_compare_nodes = dhcp_cmp_lease,
	.rbto_compare_key = dhcp_cmp_lease,
	.rbto_node_offset = offsetof(struct dhcp_lease, dl_expire_tree),
	.rbto_context = NULL,
};

const uint8_t *
dhcp_findoption(const struct bootp *bootp, size_t len, uint8_t opt)
{
	uint32_t cookie;
	const uint8_t *p = bootp->vend;
	uint8_t optlen;

	/* We have already validated the cookie */
	len -= offsetof(struct bootp, vend);
	p += sizeof(cookie);
	len -= sizeof(cookie);

	while (len > 1) {
		if (*p++ == opt)
			return p;
		optlen = *p++;
		len -= 2;
		if (optlen > len)
			return NULL;
		p += optlen;
		len -= optlen;
	}
	return NULL;
}

static void
dhcp_outputudp(const struct interface *ifp, const size_t len)
{
	const struct dhcp_ctx *ctx = ifp->if_ctx->ctx_dhcp;
	const struct bootp *bootp = ctx->dhcp_bootp;
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = bootp->ciaddr,
		.sin_port = htons(BOOTPC),
#ifdef BSD
		.sin_len = sizeof(sin),
#endif
	};

#ifdef HAVE_CASPER
	if (cap_connect(ctx->dhcp_ctx->ctx_capnet, ctx->dhcp_capfd,
		(struct sockaddr *)&sin, sizeof(sin)) == -1)
		logerr("%s: cap_connect", __func__);
	else if (send(ctx->dhcp_capfd, bootp, len, 0) == -1)
		logerr("%s: send", __func__);
#else
	if (sendto(ctx->dhcp_fd, bootp, len, 0, (struct sockaddr *)&sin,
		sizeof(sin)) == -1)
		logerr("%s: sendto", __func__);
#endif
}

static void
dhcp_outputipudp(const struct interface *ifp, const struct in_addr *src,
    const size_t len)
{
	const struct dhcp_ctx *ctx = ifp->if_ctx->ctx_dhcp;
	struct bootp *bootp = ctx->dhcp_bootp;
	struct ip ip = {
		.ip_v = IPVERSION,
		.ip_hl = sizeof(struct ip) / 4,
		.ip_len = htons(
		    sizeof(struct ip) + sizeof(struct udphdr) + (uint16_t)len),
		.ip_off = htons(IP_DF),
		.ip_ttl = DHCP_TTL,
		.ip_p = IPPROTO_UDP,
		.ip_src = *src,
	};
	struct udphdr udp = {
		.uh_sport = htons(BOOTPS),
		.uh_ulen = htons(sizeof(struct udphdr) + (uint16_t)len),
	};
	struct ip_pseudo ipp = {
		.ipp_src = ip.ip_src,
		.ipp_p = ip.ip_p,
		.ipp_len = udp.uh_ulen,
	};
	const uint8_t *opt;
	uint8_t type;
	uint32_t sum = 0;
	struct iovec iov[] = {
		{
		    .iov_base = &ip,
		    .iov_len = sizeof(ip),
		},
		{
		    .iov_base = &udp,
		    .iov_len = sizeof(udp),
		},
		{
		    .iov_base = bootp,
		    .iov_len = len,
		},
	};

	if (dhcp_cookiecmp(bootp) == 0 &&
	    ((opt = dhcp_findoption(bootp, len, DHO_MESSAGETYPE)) != NULL) &&
	    opt[0] == 1)
		type = opt[1];
	else
		type = 0;

	/* Fairly complex reading of RFC2131 4.1 */
	if (bootp->giaddr != INADDR_ANY) {
		/* Shouldn't be needed as we send to the generic UDP port. */
		ip.ip_dst.s_addr = bootp->giaddr;
		udp.uh_dport = htons(BOOTPS);
	} else {
		if ((bootp->ciaddr == INADDR_ANY &&
			bootp->flags & BROADCAST_FLAG) ||
		    type == DHCP_NAK)
			ip.ip_dst.s_addr = INADDR_BROADCAST;
		else
			ip.ip_dst.s_addr = bootp->yiaddr;
		udp.uh_dport = htons(BOOTPC);
	}
	ipp.ipp_dst = ip.ip_dst;

	ip.ip_sum = in_cksum(&ip, sizeof(ip), NULL);
	if (ip.ip_sum == 0)
		ip.ip_sum = 0xffff; /* RFC 768 */

	in_cksum(&ipp, sizeof(ipp), &sum);
	in_cksum(&udp, sizeof(udp), &sum);
	udp.uh_sum = in_cksum(bootp, len, &sum);

	if (ifp->if_output(ifp, ifp->if_bpf->bpf_fd, iov, ARRAYCOUNT(iov)) ==
	    -1)
		logerr("%s: if_output: %s", __func__, ifp->if_name);
}

static const char *
dhcp_message_type(uint8_t type)
{
	const struct dhcp_message_type *mt;

	for (mt = dhcp_message_types; mt->mt_name; mt++)
		if (mt->mt_type == type)
			return mt->mt_name;
	return "UNKNOWN";
}

struct dhcp_lease *
dhcp_alloclease(void)
{
	return calloc(1, sizeof(struct dhcp_lease));
}

struct dhcp_lease *
dhcp_newlease(struct dhcp_ctx *ctx, const uint8_t *clientid)
{
	struct dhcp_lease *lease;

	lease = dhcp_lease_find(ctx, clientid);
	if (lease != NULL)
		return lease;

	lease = dhcp_alloclease();
	if (lease == NULL) {
		logerr("%s: dhcp_alloclease", __func__);
		return NULL;
	}
	memcpy(lease->dl_clientid, clientid, clientid[0] + 1);

	if (dhcp_lease_insert(ctx, lease) == -1) {
		logerr("%s: dhcp_lease_insert", __func__);
		free(lease);
		return NULL;
	}
	return lease;
}

struct dhcp_lease *
dhcp_newleaseaddr(struct dhcp_ctx *ctx, const struct dhcp_lease *from)
{
	struct dhcp_lease *old_lease, *new_lease;

	new_lease = dhcp_alloclease();
	if (new_lease == NULL) {
		logerr("%s: dhcp_alloclease", __func__);
		return NULL;
	}

	memcpy(new_lease, from, sizeof(*new_lease));

	old_lease = dhcp_lease_findaddr(ctx, &from->dl_addr);
	if (old_lease != NULL && old_lease != from) {
		/* Should be impossible */
		free(old_lease);
	}

	if (dhcp_lease_insertaddr(ctx, new_lease) == -1) {
		logerr("%s: dhcp_lease_insertaddr", __func__);
		free(new_lease);
		return NULL;
	}
	return new_lease;
}

static bool
dhcp_lease_matchclientid(const struct dhcp_lease *client,
    const struct dhcp_lease *lease)
{
	if (lease == NULL)
		return true;

	if (!(lease->dl_flags & DL_ANY_DECLINED) &&
	    client->dl_clientid[0] == lease->dl_clientid[0] &&
	    memcmp(client->dl_clientid + 1, lease->dl_clientid + 1,
		client->dl_clientid[0]) == 0)
		return true;

	return false;
}

/**
 * Assumes client lease is from clientid and lease is from address
 */
static bool
dhcp_lease_avail(const struct dhcp_lease *client,
    const struct dhcp_lease *lease, const struct timespec *now)
{
	if (lease == NULL)
		return true;

	if (dhcp_lease_matchclientid(client, lease) &&
	    !(lease->dl_flags & DL_ANY_DECLINED))
		return true;

	if (!(lease->dl_flags & DL_PLUGIN_RESERVED) &&
	    timespecisset(&lease->dl_expires) &&
	    timespeccmp(&lease->dl_expires, now, <))
		return true;
	return false;
}

static int
dhcp_plugin_validateaddr(struct ctx *ctx, const struct in_addr *addr)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
#ifdef BSD
		.sin_len = sizeof(sin),
#endif
		.sin_addr.s_addr = INADDR_ANY,
	};
	struct plugin *p;

	if (addr->s_addr == INADDR_ANY)
		return 0;

	PLUGIN_FOREACH(ctx, p)
	{
		if (p->p_validate_addr == NULL)
			continue;
		loginfo("FOO");
		if (p->p_validate_addr(p, (const struct sockaddr *)&sin) ==
		    -1) {
			if (errno != EINVAL)
				logerr("plugin %s", p->p_name);
			return -1;
		}
	}

	return 0;
}

static struct in_addr
dhcp_plugin_findaddr(struct ctx *ctx, char *hostname, const struct bootp *bootp,
    size_t len)
{
	struct plugin *p;
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
#ifdef BSD
		.sin_len = sizeof(sin),
#endif
		.sin_addr.s_addr = INADDR_ANY,
	};
	int err;
	const char *hname = NULL;
	size_t l;

	PLUGIN_FOREACH(ctx, p)
	{
		if (p->p_lookup_hostname == NULL)
			continue;
		err = p->p_lookup_hostname(p, hostname, bootp, len);
		if (err == -1) {
			if (errno != ESRCH && errno != ENOSYS)
				logerr("plugin %s", p->p_name);
			continue;
		}
		if (err != 0)
			hname = hostname;
		break;
	}

	/* Handle the hostname being an IP address */
	if (hname != NULL && inet_pton(AF_INET, hname, &sin.sin_addr) == 1) {
		hostname[0] = '\0';
		goto check_valid;
	}

	/* Trim any trailing dot from the hostname */
	l = strlen(hostname);
	while (l != 0 && hostname[l - 1] == '.')
		hostname[--l] = '\0';

	PLUGIN_FOREACH(ctx, p)
	{
		if (p->p_lookup_addr == NULL)
			continue;
		err = p->p_lookup_addr(p, (struct sockaddr *)&sin, hname, bootp,
		    len);
		if (err == -1) {
			if (errno != ESRCH && errno != ENOSYS)
				logerr("plugin %s", p->p_name);
			continue;
		}
		break;
	}

check_valid:
	if (dhcp_plugin_validateaddr(ctx, &sin.sin_addr) == -1)
		sin.sin_addr.s_addr = INADDR_ANY;

	return sin.sin_addr;
}

static const struct dhcp_pool *
dhcp_findpool(const struct interface *ifp, in_addr_t addr, bool strict)
{
	const struct dhcp_pool *pool, *subnet = NULL;
	in_addr_t m1, m2;
	size_t npools;

	for (pool = ifp->if_pools, npools = ifp->if_npools; npools != 0;
	     pool++, npools--) {
		if (ntohl(addr) >= ntohl(pool->dp_from.s_addr) &&
		    ntohl(addr) <= ntohl(pool->dp_to.s_addr))
			return pool;

		if (strict)
			continue;

		/* While we prefer to match an address within
		 * a pool, we will as a last resort match the subnet
		 * as a configured address maybe set outside the pool. */
		m1 = addr | ~pool->dp_mask.s_addr;
		m2 = pool->dp_addr.s_addr | ~pool->dp_mask.s_addr;
		if (m1 == m2)
			subnet = pool;
	}

	return subnet;
}

static void
dhcp_continue(struct interface *ifp, void *data, size_t datalen, uint32_t flags)
{
	dhcp_handlebootp(ifp, data, datalen, flags);
}

static int
dhcp_test_addr(struct interface *ifp, struct in_addr *dst, void *data,
    size_t datalen)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
#ifdef BSD
		.sin_len = sizeof(sin),
#endif
		.sin_addr = *dst,
	};
	const struct sockaddr *sa = (const struct sockaddr *)&sin;
	const struct dhcp_pool *pool;
	struct plugin *p;
	int r;

	pool = dhcp_findpool(ifp, dst->s_addr, true);
	if (pool == NULL)
		return 0;

	PLUGIN_FOREACH(ifp->if_ctx, p)
	{
		if (p->p_test_addr == NULL)
			continue;
		r = p->p_test_addr(p, ifp, sa, data, datalen, dhcp_continue);
		if (r == -1)
			logerr("%s: %s", __func__, p->p_name);
		else if (r != 0)
			return r;
	}
	return 0;
}

static struct in_addr
dhcp_pool_findaddr(struct interface *ifp, struct dhcp_pool *pool,
    struct timespec *now, struct dhcp_lease *current)
{
	struct dhcp_ctx *ctx = ifp->if_ctx->ctx_dhcp;
	struct in_addr addr = pool->dp_from;
	struct dhcp_lease *lease, *oldest = NULL;
	uint8_t skipping = 0;

	if (ntohl(current->dl_addr.s_addr) >= ntohl(pool->dp_from.s_addr) &&
	    ntohl(current->dl_addr.s_addr) < ntohl(pool->dp_to.s_addr)) {
		lease = dhcp_lease_findaddr(ctx, &current->dl_addr);
		if (lease == current && !(current->dl_flags & DL_ANY_DECLINED))
			return current->dl_addr;
		addr.s_addr = htonl(ntohl(current->dl_addr.s_addr) + 1);
		skipping = 1;
	}

	while ((lease = dhcp_lease_findaddr(ctx, &addr)) != NULL) {
		/*
		 * We will use the oldest expired or offered lease,
		 * but will always prefer an expired to an offered.
		 * A declined lease has a reduced expiry to now so is
		 * checked by expiration time.
		 */
		if (dhcp_lease_matchclientid(current, lease)) {
			return lease->dl_addr;
		} else if (dhcp_lease_avail(current, lease, now)) {
			if (oldest == NULL || oldest->dl_flags & DL_OFFERED ||
			    timespeccmp(&lease->dl_expires, &oldest->dl_expires,
				<)) {
				oldest = lease;
			}
		} else if (lease->dl_flags & DL_OFFERED &&
		    (oldest == NULL ||
			(oldest->dl_flags & DL_OFFERED &&
			    timespeccmp(&lease->dl_expires, &oldest->dl_expires,
				<)))) {
			oldest = lease;
		}

		if (addr.s_addr == pool->dp_to.s_addr) {
			if (skipping) {
				addr.s_addr = pool->dp_from.s_addr;
				continue;
			}
			addr.s_addr = INADDR_ANY;
			break;
		}

		addr.s_addr = htonl(ntohl(addr.s_addr) + 1);
		if (skipping && current->dl_addr.s_addr == addr.s_addr) {
			addr.s_addr = INADDR_ANY;
			break;
		}
	}

	if (addr.s_addr != INADDR_ANY)
		return addr;

	if (oldest != NULL) {
		addr = oldest->dl_addr;
		dhcp_lease_erase(ctx, oldest);
		/* We should not have to erase the address as the insertion
		 * will overwrite the entry */
		free(oldest);
	}
	return addr;
}

static struct in_addr
dhcp_findaddr(struct interface *ifp, struct timespec *now,
    struct dhcp_lease *current)
{
	size_t npools = ifp->if_npools;
	struct dhcp_pool *pool = ifp->if_pools;
	struct in_addr addr = { .s_addr = INADDR_ANY };

	while (npools--) {
		addr = dhcp_pool_findaddr(ifp, pool, now, current);
		if (addr.s_addr != INADDR_ANY)
			break;
		pool++;
	}
	return addr;
}

static int
dhcp_addhostname(uint8_t **p, const uint8_t *e, const struct dhcp_lease *lease,
    const struct bootp *req, size_t reqlen)
{
	const uint8_t *opt, *opte;
	size_t l;

	if (lease->dl_hostname[0] == '\0')
		return 0;

	opt = dhcp_findoption(req, reqlen, DHO_FQDN);
	if (opt != NULL && opt[0] >= 3) {
		/* Copy back the FQDN option */
		uint8_t flags = opt[1];
		uint8_t fqdn[255] = { '\0' };

		/* Clients generally don't perform DNS updates. */
		if ((lease->dl_flags & DL_PLUGIN_DNSPTR)) {
			if (lease->dl_flags & DL_PLUGIN_DNSA) {
				fqdn[0] |= FQDN_S;
			} else if (flags & FQDN_S)
				fqdn[0] |= FQDN_O;
		} else {
			if (flags & FQDN_S)
				fqdn[0] |= FQDN_O;
			fqdn[0] |= FQDN_N;
		}

		fqdn[1] = 0xff;
		fqdn[2] = 0xff;

		if (flags & FQDN_E) {
			fqdn[0] |= FQDN_E;
			l = encode_rfc1035(lease->dl_hostname, fqdn + 3);
		} else {
			l = MIN(strlen(lease->dl_hostname), sizeof(fqdn) - 3);
			memcpy(fqdn + 3, lease->dl_hostname, l);
		}
		DHCP_PUT_BIN(p, e, DHO_FQDN, fqdn, l + 3);

		return 0;
	}

	opt = dhcp_findoption(req, reqlen, DHO_PARAMETERREQUESTLIST);
	if (opt == NULL)
		return 0;
	opte = opt + *opt;
	for (opt++; opt < opte; opt++) {
		if (*opt == DHO_HOSTNAME)
			break;
	}
	if (*opt != DHO_HOSTNAME)
		return 0;

	DHCP_PUT_STR(p, e, DHO_HOSTNAME, lease->dl_hostname);
	return 0;
}

static int
dhcp_addoptions(struct bootp *bootp, uint8_t **p, const uint8_t *e,
    struct dhcp_ctx *ctx, const struct dhcp_lease *lease, uint8_t type,
    const struct dhcp_pool *pool, const char *msg, const struct bootp *req,
    size_t reqlen)
{
	const uint8_t *opt;

	DHCP_PUT_B(p, e, DHO_MESSAGETYPE, type);
	DHCP_PUT_U32(p, e, DHO_SERVERID, pool->dp_addr.s_addr);
	if (type == DHCP_OFFER || type == DHCP_ACK) {
		uint32_t u32, lease_time = ctx->dhcp_lease_time;
		struct plugin *plug;
		int n;

		opt = dhcp_findoption(req, reqlen, DHO_LEASETIME);
		if (opt != NULL && opt[0] == sizeof(u32)) {
			memcpy(&u32, opt + 1, sizeof(u32));
			u32 = ntohl(u32);
			if (u32 < lease_time)
				lease_time = u32;
		}
		u32 = htonl(lease_time);
		DHCP_PUT_U32(p, e, DHO_LEASETIME, u32);
		u32 = htonl((uint32_t)(lease_time * T1));
		DHCP_PUT_U32(p, e, DHO_RENEWALTIME, u32);
		u32 = htonl((uint32_t)(lease_time * T2));
		DHCP_PUT_U32(p, e, DHO_REBINDTIME, u32);

		n = dhcp_addhostname(p, e, lease, req, reqlen);
		if (n == -1)
			return n;

		PLUGIN_FOREACH(ctx->dhcp_ctx, plug)
		{
			if (plug->p_add_dhcp_options == NULL)
				continue;
			n = plug->p_add_dhcp_options(plug, bootp, p, e, pool,
			    req, reqlen);
			if (n == -1) {
				if (errno == ENOSYS)
					continue;
				return -1;
			}
			if (n != 0)
				break;
		}

		if (dhcp_findoption(req, reqlen, DHO_RAPIDCOMMIT))
			DHCP_PUT_O(p, e, DHO_RAPIDCOMMIT);
	}

	if (msg != NULL)
		DHCP_PUT_STR(p, e, DHO_MESSAGE, msg);
	return 0;
}

static void
dhcp_output(const struct interface *ifp, const struct dhcp_lease *lease,
    const uint8_t type, const char *msg, const struct bootp *req, size_t reqlen)
{
	struct dhcp_ctx *ctx = ifp->if_ctx->ctx_dhcp;
	struct bootp *bootp = ctx->dhcp_bootp;
	const struct dhcp_pool *pool;
	struct in_addr addr;
	uint8_t *p, *e;
	size_t len;
	uint16_t u16;
	uint32_t u32;
	const uint8_t *opt;
	int err;

	memset(bootp, 0, sizeof(*bootp));
	bootp->op = BOOTREPLY;
	bootp->htype = req->htype;
	bootp->hlen = req->hlen;
	if (req->hlen > 0)
		memcpy(bootp->chaddr, req->chaddr, req->hlen);
	bootp->xid = req->xid;
	if (lease != NULL)
		bootp->yiaddr = lease->dl_addr.s_addr;
	bootp->ciaddr = req->ciaddr;
	bootp->giaddr = req->giaddr;

	addr.s_addr = bootp->yiaddr != INADDR_ANY ? bootp->yiaddr :
						    bootp->ciaddr;
	if (addr.s_addr == INADDR_ANY) {
		opt = dhcp_findoption(req, reqlen, DHO_IPADDRESS);
		if (opt != NULL && opt[0] == sizeof(addr.s_addr))
			memcpy(&addr.s_addr, opt + 1, sizeof(addr.s_addr));
	}

	pool = dhcp_findpool(ifp, addr.s_addr, false);
	if (pool == NULL) {
		pool = ifp->if_pools;
		logwarnx(
		    "%s: failed to find a pool for the address to reply to: %s",
		    ifp->if_name, inet_ntoa(addr));
	}

	if (type == DHCP_BOOTREQUEST) {
		len = sizeof(*bootp);
		goto out;
	}

	if (bootp->giaddr != INADDR_ANY && type == DHCP_NAK)
		bootp->flags = htons(ntohs(bootp->flags) | BROADCAST_FLAG);

	p = bootp->vend;
	u32 = htonl(MAGIC_COOKIE);
	memcpy(p, &u32, sizeof(u32));
	p += 4;

	opt = dhcp_findoption(req, reqlen, DHO_MAXMESSAGESIZE);
	if (opt != NULL && opt[0] == sizeof(u16)) {
		memcpy(&u16, opt + 1, sizeof(u16));
		e = (uint8_t *)bootp + ntohs(u16);
	} else
		e = (uint8_t *)bootp + ctx->dhcp_bootplen;

	err = dhcp_addoptions(bootp, &p, e, ctx, lease, type, pool, msg, req,
	    reqlen);
	if (err == -1) {
		if (errno == E2BIG)
			logwarnx("%s: DHCP reply is too big for client",
			    ifp->if_name);
		else {
			logerr("%s: dhcp_addoptions", ifp->if_name);
			return;
		}
	}

	*p++ = DHO_END;

	len = (size_t)(p - (uint8_t *)bootp);
	while (len < sizeof(*bootp)) {
		*p++ = DHO_PAD;
		len++;
	}

out:
	addr.s_addr = bootp->yiaddr != INADDR_ANY ? bootp->yiaddr :
						    bootp->ciaddr;
	loginfox("%s: send %s 0x%x %s", ifp->if_name, dhcp_message_type(type),
	    bootp->xid, inet_ntoa(addr));
	if (bootp->giaddr != INADDR_ANY ||
	    (bootp->ciaddr != INADDR_ANY && type != DHCP_NAK))
		dhcp_outputudp(ifp, len);
	else
		dhcp_outputipudp(ifp, &pool->dp_addr, len);
	return;
}

static void
dhcp_expire_lease(struct dhcp_ctx *ctx, struct dhcp_lease *lease)
{
	struct plugin *p;

	if (!(lease->dl_flags & DL_LEASED))
		return;
	if (lease->dl_in_expire_tree) {
		rb_tree_remove_node(&ctx->dhcp_expire_tree, lease);
		lease->dl_in_expire_tree = false;
		dhcp_set_expire_timeout(ctx);
	}
	lease->dl_flags &= ~DL_LEASED;

	PLUGIN_FOREACH(ctx->dhcp_ctx, p)
	{
		if (p->p_expire_lease == NULL)
			continue;
		p->p_expire_lease(p, lease);
	}
}

static void
dhcp_expire_timeout(void *arg)
{
	struct dhcp_ctx *ctx = arg;

	struct dhcp_lease *lease = RB_TREE_MIN(&ctx->dhcp_expire_tree);

	dhcp_expire_lease(ctx, lease);
}

static void
dhcp_set_expire_timeout(struct dhcp_ctx *ctx)
{
	struct dhcp_lease *lease = RB_TREE_MIN(&ctx->dhcp_expire_tree);
	struct timespec now, tv;

	if (lease == NULL) {
		logdebugx("dhcp: no lease has an active expiry");
		eloop_timeout_delete(ctx->dhcp_ctx->ctx_eloop,
		    dhcp_expire_timeout, ctx);
		return;
	}

	if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
		logerr("%s: clock_gettime", __func__);
		return;
	}
	timespecsub(&lease->dl_expires, &now, &tv);
	logdebugx("dhcp: earliest lease expires in %jd seconds",
	    (intmax_t)tv.tv_sec);
	if (eloop_timeout_add_tv(ctx->dhcp_ctx->ctx_eloop, &tv,
		dhcp_expire_timeout, ctx) == -1)
		logerr("%s: eloop_timeout_add_tv", __func__);
}

static void
dhcp_lease_settime(struct dhcp_ctx *ctx, struct dhcp_lease *lease,
    struct timespec *now, const struct bootp *bootp, size_t len)
{
	const uint8_t *opt;
	uint32_t u32, lease_time = ctx->dhcp_lease_time;

	opt = dhcp_findoption(bootp, len, DHO_LEASETIME);
	if (opt != NULL && opt[0] == sizeof(u32)) {
		memcpy(&u32, opt + 1, sizeof(u32));
		u32 = ntohl(u32);
		if (u32 < lease_time)
			lease_time = u32;
	}

	if (lease->dl_in_expire_tree) {
		rb_tree_remove_node(&ctx->dhcp_expire_tree, lease);
		lease->dl_in_expire_tree = false;
	}

	lease->dl_leased = *now;
	if (lease_time == INFINITE_LIFETIME)
		timespecclear(&lease->dl_expires);
	else {
		struct timespec add = { .tv_sec = lease_time };
		void *node;

		timespecadd(&lease->dl_leased, &add, &lease->dl_expires);
		node = rb_tree_insert_node(&ctx->dhcp_expire_tree, lease);
		if (node == lease)
			lease->dl_in_expire_tree = true;
		else
			logerrx(
			    "%s: rb_tree_insert_node: didn't insert our lease",
			    __func__);
	}

	dhcp_set_expire_timeout(ctx);
}

static void
dhcp_commit_lease(struct dhcp_ctx *ctx, struct dhcp_lease *lease,
    struct bootp *req, size_t reqlen)
{
	struct plugin *p;
	unsigned int flags;
	int err;

	PLUGIN_FOREACH(ctx->dhcp_ctx, p)
	{
		if (p->p_commit_lease == NULL)
			continue;
		err = p->p_commit_lease(p, lease, req, reqlen, &flags);
		if (err == -1)
			continue;
		lease->dl_flags &= ~(DL_PLUGIN_DNSA | DL_PLUGIN_DNSPTR);
		lease->dl_flags |= (flags &
		    (DL_PLUGIN_DNSA | DL_PLUGIN_DNSPTR));
		if (err != 0)
			break;
	}
}

static int
dhcp_declined(struct dhcp_ctx *ctx, struct dhcp_lease *lease, uint32_t flags,
    struct bootp *req, size_t reqlen)
{
	struct dhcp_lease *declined;
	struct timespec add = {
		.tv_sec = dhcp_cache_oldaddr,
	};

	if (lease->dl_addr.s_addr == INADDR_ANY)
		return 0;

	lease->dl_flags |= flags;
	lease->dl_flags &= ~DL_OFFERED;
	if (lease->dl_flags & DL_LEASED)
		dhcp_expire_lease(ctx, lease);
	lease->dl_flags &= ~DL_ADDRESS;

	declined = dhcp_newleaseaddr(ctx, lease);
	if (declined == NULL) {
		logerr("%s: malloc", __func__);
		return -1;
	}
	declined->dl_flags = lease->dl_flags;

	if (flags & DL_DECLINED)
		add.tv_sec = dhcp_cache_declined;
	else if (flags & DL_PLUGIN_DECLINED)
		add.tv_sec = dhcp_plugin_cache_declined;
	if (clock_gettime(CLOCK_REALTIME, &declined->dl_leased) == -1)
		logerr("%s: clock_gettime", __func__);
	timespecadd(&declined->dl_leased, &add, &declined->dl_expires);

	dhcp_commit_lease(ctx, declined, req, reqlen);
	return 0;
}

static void
dhcp_handlebootp(struct interface *ifp, struct bootp *bootp, size_t len,
    uint32_t flags)
{
	struct dhcp_ctx *ctx = ifp->if_ctx->ctx_dhcp;
	const uint8_t *opt;
	uint8_t type, clientid[DHCP_CLIENTID_LEN + 1], fqdn_flags;
	struct in_addr addr = { .s_addr = INADDR_ANY };
	char phostname[DHCP_HOSTNAME_LEN] = { '\0' };
	struct in_addr paddr = { .s_addr = INADDR_ANY };
	struct dhcp_lease *lease = NULL, *wanted = NULL;
	char clid_buf[sizeof(clientid) * 3];
	const char *clid, *msg = NULL;
	struct timespec now, expires;

	/* Sanity checks */
	if (bootp->op != BOOTREQUEST) {
		logdebugx("%s: recv %u 0x%x: invalid bootp op", ifp->if_name,
		    bootp->op, bootp->xid);
		return;
	}
	if (bootp->hlen > sizeof(bootp->chaddr)) {
		logdebugx("%s: xid 0x%x hlen %u overflow", ifp->if_name,
		    bootp->xid, bootp->hlen);
		return;
	}
	if (bootp->hlen != 0 && bootp->htype == 0) {
		logdebugx("%s: xid 0x%x hlen %u but no htype", ifp->if_name,
		    bootp->xid, bootp->hlen);
		return;
	}

	if (dhcp_cookiecmp(bootp) != 0) {
		type = DHCP_BOOTREQUEST;
	} else {
		opt = dhcp_findoption(bootp, len, DHO_MESSAGETYPE);
		if (opt[0] != 1) {
			logdebugx("%s: xid 0x%x invalid message type length",
			    ifp->if_name, bootp->xid);
			return;
		}
		type = opt[1];
	}

	/* If we don't have a clientid, make one from the bootp message */
	if (type == DHCP_BOOTREQUEST) {
		if (bootp->hlen == 0) {
			logdebugx("%s: 0x%x hlen zero", ifp->if_name,
			    bootp->xid);
			return;
		}
		if (bootp->htype == 0) {
			logdebugx("%s: 0x%x htype zero", ifp->if_name,
			    bootp->xid);
			return;
		}
		opt = NULL;
	} else
		opt = dhcp_findoption(bootp, len, DHO_CLIENTID);

	/* Store it like a DHCP option, first byte is length */
	if (opt != NULL)
		memcpy(clientid, opt, opt[0] + 1);
	else if (bootp->hlen != 0 && bootp->htype != 0) {
		clientid[0] = bootp->hlen + 1;
		clientid[1] = bootp->htype;
		memcpy(clientid + 2, bootp->chaddr, bootp->hlen);
	} else
		clientid[0] = '\0';

	clid = hwaddr_ntoa(clientid + 1, clientid[0], clid_buf,
	    sizeof(clid_buf));

	if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
		logerr("%s: clock_gettime", __func__);
		return;
	}

	if (type == DHCP_BOOTREQUEST) {
		lease = dhcp_newlease(ctx, clientid);
		if (lease == NULL)
			return;
		if (lease->dl_addr.s_addr == INADDR_ANY) {
			lease->dl_addr = dhcp_plugin_findaddr(ifp->if_ctx,
			    phostname, bootp, len);
			if (lease->dl_addr.s_addr != INADDR_ANY)
				lease->dl_flags |= DL_PLUGIN_ADDRESS;
		}
		if (lease->dl_addr.s_addr == INADDR_ANY)
			lease->dl_addr = dhcp_findaddr(ifp, &now, lease);
		if (lease->dl_addr.s_addr == INADDR_ANY) {
			logwarnx("%s: no free addresses", ifp->if_name);
			return;
		}
		lease->dl_leased = now;
		/* BOOTP leases don't expire :( */
		if (lease->dl_in_expire_tree) {
			rb_tree_remove_node(&ctx->dhcp_expire_tree, lease);
			lease->dl_in_expire_tree = false;
		}
		timespecclear(&lease->dl_expires);
		if (dhcp_lease_insertaddr(ctx, lease) == -1) {
			logerr("%s: dhcp_lease_insertaddr", __func__);
			return;
		}
		goto out;
	}

	/* From here we are DHCP */
	opt = dhcp_findoption(bootp, len, DHO_MESSAGETYPE);
	if (opt == NULL) {
		logdebugx("%s: 0x%x no message type", ifp->if_name, bootp->xid);
		return;
	}
	if (opt[0] != 1) {
		logdebugx("%s: 0x%x invalid message type length", ifp->if_name,
		    bootp->xid);
		return;
	}
	type = opt[1];

	switch (type) {
	case DHCP_DISCOVER:
	case DHCP_REQUEST:
	case DHCP_DECLINE:
	case DHCP_RELEASE:
	case DHCP_INFORM:
		break;
	default:
		logdebugx("%s: 0x%x invalid message type: %s (%u)",
		    ifp->if_name, bootp->xid, dhcp_message_type(type), type);
		return;
	}

	logdebugx("%s: %s 0x%x %s: %s", ifp->if_name, flags ? "cont" : "recv",
	    bootp->xid, dhcp_message_type(type), clid);

	lease = dhcp_newlease(ctx, clientid);
	if (lease == NULL)
		return;

	/*
	 * If a plugin configured address outside the pool is declined,
	 * then they will be given a different address at the next discover.
	 * However, when it is renewed and the plugin assigned address
	 * declined timeout period has expired then the current
	 * address will be NAKed and the plugin assigned address will
	 * be offered again.
	 */
	switch (type) {
	case DHCP_DISCOVER:
		if (lease->dl_flags & DL_PLUGIN_TESTING) {
			if (flags != 0) {
				lease->dl_flags &= ~DL_PLUGIN_TESTING;
				if (flags & DL_OFFERED) {
					type = DHCP_OFFER;
					goto out;
				}
				dhcp_declined(ctx, lease, DL_PLUGIN_DECLINED,
				    bootp, len);
				break;
			}
			/*
			 * I don't care what the client says, we're already
			 * testing an address for them. Clients shouldn't
			 * DISCOVER faster than we can test. RFC2131 4.1 says 4
			 * seconds for 10Mbs Ethernet +-1 second randomistation.
			 * So the worst case should be 3 seconds which is enough
			 * time for an ICMP ping.
			 */
			return;
		}
		/* FALLTHROUGH */
	case DHCP_REQUEST:
		paddr = dhcp_plugin_findaddr(ifp->if_ctx, phostname, bootp,
		    len);
		if (paddr.s_addr == INADDR_ANY)
			break;
		wanted = dhcp_lease_findaddr(ctx, &paddr);
		if (wanted != NULL && !dhcp_lease_avail(lease, wanted, &now)) {
			logwarnx(
			    "%s: plugin assigned address unavailable: 0x%x %s",
			    ifp->if_name, bootp->xid, inet_ntoa(paddr));
			paddr.s_addr = INADDR_ANY;
			wanted = NULL;
		}
		break;
	}

	/* Don't test plugin assigned addresses are outside the pool */
	switch (type) {
	case DHCP_REQUEST:
		if (bootp->ciaddr != INADDR_ANY) {
			if (paddr.s_addr == bootp->ciaddr)
				break;
			if (dhcp_findpool(ifp, bootp->ciaddr, true) == NULL)
				goto outsidepool;
			break;
		}
		/* FALLTHROUGH */
	case DHCP_DISCOVER:
	case DHCP_DECLINE:
		opt = dhcp_findoption(bootp, len, DHO_IPADDRESS);
		if (opt != NULL && opt[0] != sizeof(addr.s_addr))
			opt = NULL;
		if (opt == NULL && type != DHCP_DISCOVER) {
			logdebugx("%s: 0x%x no ip requested address",
			    ifp->if_name, bootp->xid);
			return;
		}
		if (opt != NULL) {
			memcpy(&addr.s_addr, opt + 1, sizeof(addr.s_addr));
			if (paddr.s_addr != addr.s_addr &&
			    dhcp_findpool(ifp, addr.s_addr, true) == NULL) {
				if (type == DHCP_DISCOVER)
					addr.s_addr = INADDR_ANY;
				else
					goto outsidepool;
			}
		}
		break;
	case DHCP_INFORM:
		if (dhcp_findpool(ifp, bootp->ciaddr, false) == NULL) {
		outsidepool:
			type = DHCP_NAK;
			msg = "address outside pool";
			goto out;
		}
		break;
	}

	switch (type) {
	case DHCP_DISCOVER:
		if (paddr.s_addr != INADDR_ANY) {
			/* We have already validated */
			addr = paddr;
			goto offer_plugin_addr;
		}
		if (addr.s_addr != INADDR_ANY &&
		    (wanted = dhcp_lease_findaddr(ctx, &addr)) != NULL &&
		    wanted != lease && !dhcp_lease_avail(lease, wanted, &now))
			addr.s_addr = INADDR_ANY;
		if (addr.s_addr == INADDR_ANY &&
		    lease->dl_addr.s_addr != INADDR_ANY &&
		    !(lease->dl_flags & DL_ANY_DECLINED) &&
		    ((wanted = dhcp_lease_findaddr(ctx, &lease->dl_addr)) ==
			    NULL ||
			(wanted != lease &&
			    dhcp_lease_avail(lease, wanted, &now))))
			addr.s_addr = lease->dl_addr.s_addr;
		if (addr.s_addr == INADDR_ANY) {
			addr = dhcp_findaddr(ifp, &now, lease);
			if (addr.s_addr == INADDR_ANY) {
				logwarnx("%s: 0x%x no address available",
				    ifp->if_name, bootp->xid);
				return;
			}
		}
	offer_plugin_addr:
		/* If we had an address, split it off */
		if (lease->dl_addr.s_addr != addr.s_addr &&
		    lease->dl_flags & DL_ADDRESS) {
			lease->dl_flags &= ~(
			    DL_LEASED | DL_OFFERED | DL_INFORMED);
			dhcp_declined(ctx, lease, 0, bootp, len);
		}
		lease->dl_addr = addr;
		lease->dl_flags |= DL_OFFERED;
		lease->dl_flags &= ~(DL_LEASED | DL_ANY_DECLINED | DL_INFORMED);
		if (lease->dl_addr.s_addr == paddr.s_addr)
			lease->dl_flags |= DL_PLUGIN_ADDRESS;
		else
			lease->dl_flags &= ~DL_PLUGIN_ADDRESS;
		if (wanted != NULL)
			expires = wanted->dl_expires;
		else if (lease->dl_flags & DL_ADDRESS)
			expires = lease->dl_expires;
		else
			timespecclear(&expires);
		dhcp_lease_settime(ctx, lease, &now, bootp, len);
		if (wanted != lease) {
			if (dhcp_lease_insertaddr(ctx, lease) == -1) {
				logerr("%s: dhcp_lease_insertaddr", __func__);
				return;
			}
			/* If the address isn't linked it can be freed */
			if (wanted && !(wanted->dl_flags & DL_ADDRESS))
				free(wanted);
			wanted = NULL;
		}
		lease->dl_flags |= DL_ADDRESS;
		/* Don't test plugin assigned address. */
		if (!(lease->dl_flags & DL_PLUGIN_ADDRESS) &&
		    timespeccmp(&expires, &now, <) &&
		    dhcp_test_addr(ifp, &addr, bootp, len) == 1) {
			lease->dl_flags |= DL_PLUGIN_TESTING;
			return;
		}
		if (dhcp_findoption(bootp, len, DHO_RAPIDCOMMIT) != NULL) {
			lease->dl_flags |= DL_LEASED;
			lease->dl_flags &= ~DL_OFFERED;
			type = DHCP_ACK;
			break;
		}
		type = DHCP_OFFER;
		break;
	case DHCP_REQUEST:
		if (bootp->ciaddr != INADDR_ANY)
			addr.s_addr = bootp->ciaddr;
		if ((paddr.s_addr != INADDR_ANY &&
			addr.s_addr != paddr.s_addr) ||
		    ((wanted = dhcp_lease_findaddr(ctx, &addr)) != NULL &&
			wanted != lease &&
			!dhcp_lease_avail(lease, wanted, &now))) {
			type = DHCP_NAK;
			msg = "requested address unavailable";
			goto out;
		}
		/* If we had an address, split it off */
		if (lease->dl_addr.s_addr != addr.s_addr) {
			lease->dl_flags &= ~(DL_LEASED | DL_OFFERED);
			dhcp_declined(ctx, lease, 0, bootp, len);
		}
		lease->dl_addr = addr;
		lease->dl_flags |= DL_LEASED;
		lease->dl_flags &= ~(
		    DL_OFFERED | DL_ANY_DECLINED | DL_INFORMED);
		if (lease->dl_addr.s_addr == paddr.s_addr)
			lease->dl_flags |= DL_PLUGIN_ADDRESS;
		else
			lease->dl_flags &= ~DL_PLUGIN_ADDRESS;
		dhcp_lease_settime(ctx, lease, &now, bootp, len);
		if (wanted != lease) {
			if (dhcp_lease_insertaddr(ctx, lease) == -1) {
				logerr("%s: dhcp_lease_insertaddr", __func__);
				return;
			}
			/* If the address isn't linked it can be freed */
			if (wanted && !(wanted->dl_flags & DL_ADDRESS))
				free(wanted);
		}
		lease->dl_flags |= DL_ADDRESS;
		type = DHCP_ACK;
		break;
	case DHCP_DECLINE:
		if (lease->dl_addr.s_addr != addr.s_addr) {
			logdebugx("%s: 0x%x decline address mismatch",
			    ifp->if_name, bootp->xid);
			return;
		}
		logwarnx("%s: 0x%x declined %s: %s", ifp->if_name, bootp->xid,
		    inet_ntoa(addr), clid);
		lease->dl_flags |= DL_DECLINED;
		lease->dl_flags &= ~(DL_OFFERED | DL_LEASED | DL_INFORMED);
		goto released;
	case DHCP_RELEASE:
		if (lease->dl_addr.s_addr != bootp->ciaddr) {
			logdebugx("%s: 0x%x release address mismatch",
			    ifp->if_name, bootp->xid);
			return;
		}
		addr.s_addr = bootp->ciaddr;
		logwarnx("%s: 0x%x released %s: %s", ifp->if_name, bootp->xid,
		    inet_ntoa(addr), clid);
		lease->dl_flags &= ~(DL_OFFERED | DL_LEASED | DL_DECLINED);
	released:
		dhcp_declined(ctx, lease,
		    type == DHCP_DECLINE ? DL_DECLINED : 0, bootp, len);
		return;
	case DHCP_INFORM:
		/*
		 * RFC2131 3.4 says that we MUST NOT check for an existing
		 * lease. We don't mark the address as OFFERED or LEASED, but we
		 * do mark it as INFORMED so that if it falls inside a pool we
		 * don't OFFER it to anyone else. Ideally clients should INFORM
		 * with an address outside the pool.
		 */
		addr.s_addr = bootp->ciaddr;
		if ((wanted = dhcp_lease_findaddr(ctx, &addr)) != NULL &&
		    wanted != lease) {
			/* Address takeover? */
			if (dhcp_lease_eraseaddr(ctx, &wanted->dl_addr) == -1) {
				logerr("%s: dhcp_lease_eraseaddr", __func__);
				return;
			}
			if (wanted->dl_flags & DL_ADDRESS)
				wanted->dl_flags &= ~DL_ADDRESS;
			else {
				free(wanted);
				wanted = NULL;
			}
		}
		lease->dl_flags |= DL_INFORMED;
		lease->dl_flags &= ~(DL_OFFERED | DL_LEASED);
		if (lease->dl_addr.s_addr != bootp->ciaddr) {
			/* Informant changed address */
			if (lease->dl_flags & DL_ADDRESS) {
				if (dhcp_lease_eraseaddr(ctx,
					&lease->dl_addr) == -1) {
					logerr("%s: dhcp_lease_eraseaddr",
					    __func__);
					return;
				}
				lease->dl_flags &= ~DL_ADDRESS;
			}
			lease->dl_addr.s_addr = bootp->ciaddr;
			if (dhcp_lease_insertaddr(ctx, lease) == -1) {
				logerr("%s: dhcp_lease_insertaddr", __func__);
				return;
			}
			lease->dl_flags |= DL_ADDRESS;
		}
		type = DHCP_ACK;
		break;
	}

out:
	switch (type) {
	case DHCP_BOOTREQUEST:
	case DHCP_OFFER:
	case DHCP_ACK:
		/*
		 * Look at the FQDN option to work out the clients
		 * preference for updating DNS.
		 * It's upto each plugin to respect the clients wishes or not.
		 */
		lease->dl_flags &= ~(DL_UPDATE_DNSA | DL_UPDATE_DNSPTR);
		opt = dhcp_findoption(bootp, len, DHO_FQDN);
		if (opt != NULL && opt[0] >= 3) {
			fqdn_flags = opt[1];
			if (!(fqdn_flags & FQDN_N)) {
				lease->dl_flags |= DL_UPDATE_DNSPTR;
				if (fqdn_flags & FQDN_S)
					lease->dl_flags |= DL_UPDATE_DNSA;
			}
		} else
			fqdn_flags = 0;

		/*
		 * If a plugin defines a hostname, use that.
		 * Otherwise use what the client tells us.
		 */
		lease->dl_flags &= ~(DL_HOSTNAME | DL_PLUGIN_HOSTNAME);
		if (phostname[0] != '\0') {
			memcpy(lease->dl_hostname, phostname,
			    sizeof(lease->dl_hostname));
			lease->dl_flags |= DL_PLUGIN_HOSTNAME;
		} else {
			memset(lease->dl_hostname, '\0',
			    sizeof(lease->dl_hostname));
			if (opt != NULL && opt[0] >= 3) {
				if (fqdn_flags & FQDN_E) {
					if (decode_rfc1035(lease->dl_hostname,
						sizeof(lease->dl_hostname),
						opt + 3, opt[0] - 3) == -1)
						memset(lease->dl_hostname, '\0',
						    sizeof(lease->dl_hostname));
				} else {
					// hostname field is bigger than 255
					memcpy(lease->dl_hostname, opt + 3,
					    opt[0] - 3);
				}
			} else {
				opt = dhcp_findoption(bootp, len, DHO_HOSTNAME);
				if (opt != NULL)
					memcpy(lease->dl_hostname, opt + 1,
					    opt[0]);
			}
			if (lease->dl_hostname[0] != '\0')
				lease->dl_flags |= DL_HOSTNAME;
		}
		dhcp_commit_lease(ctx, lease, bootp, len);
		break;
	}

	switch (type) {
	case DHCP_BOOTREQUEST:
	case DHCP_OFFER:
	case DHCP_ACK:
	case DHCP_NAK:
		dhcp_output(ifp, lease, type, msg, bootp, len);
		break;
	}
}

static void
dhcp_readudp0(struct dhcp_ctx *ctx, int fd, unsigned short events)
{
	struct sockaddr_in from;
	struct iovec iov = {
		.iov_base = ctx->dhcp_udp_buf,
		.iov_len = ctx->dhcp_udp_buflen,
	};
#define BUFSPC_BASE CMSG_SPACE(sizeof(struct in_addr))
#ifdef IP_RECVIF
#define BUFSPC BUFSPC_BASE + CMSG_SPACE(sizeof(struct sockaddr_dl))
#else
#define BUFSPC BUFSPC_BASE + CMSG_SPACE(sizeof(struct in_pktinfo))
#endif
	union {
		struct cmsghdr hdr;
		uint8_t buf[BUFSPC];
	} cmsgbuf = { .buf = { 0 } };
	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = sizeof(from),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsgbuf.buf,
		.msg_controllen = sizeof(cmsgbuf.buf),
	};
	ssize_t nread;
	struct bootp *bootp;
	struct interface *ifp;

	if (events != ELE_READ)
		logerrx("%s: unexpected event 0x%04x", __func__, events);

	nread = recvmsg(fd, &msg, 0);
	if (nread == -1) {
		logerr("%s: recvmsg", __func__);
		return;
	}

	if ((size_t)nread < offsetof(struct bootp, vend)) {
		logerrx("dhcp: truncated packet (%zu) from %s", nread,
		    inet_ntoa(from.sin_addr));
		return;
	}

	bootp = ctx->dhcp_udp_buf;
	ifp = if_findifpfromcmsg(ctx->dhcp_ctx, &msg, NULL);
	if (ifp == NULL) {
		/* This is a common situation for me when my tap
		 * interfaces come and go. */
#if 0
		logwarnx("dhcp: interface not found 0x%x %s", bootp->xid,
		    inet_ntoa(from.sin_addr));
#endif
		return;
	}

	if (!(ifp->if_flags & IF_ACTIVE) || ifp->if_pools == NULL)
		return;

	dhcp_handlebootp(ifp, bootp, (size_t)nread, 0);
}

static void
dhcp_readudp(void *arg, unsigned short events)
{
	struct dhcp_ctx *ctx = arg;

	dhcp_readudp0(ctx, ctx->dhcp_fd, events);
}

#ifdef HAVE_CASPER
static void
dhcp_capreadudp(void *arg, unsigned short events)
{
	struct dhcp_ctx *ctx = arg;

	dhcp_readudp0(ctx, ctx->dhcp_capfd, events);
}
#endif

static int
dhcp_try_expire_lease(void *c, struct dhcp_lease *lease)
{
	struct dhcp_ctx *ctx = c;

	if (!(lease->dl_flags & DL_LEASED))
		return 0;

	if (timespecisset(&lease->dl_expires) &&
	    timespeccmp(&lease->dl_expires, &ctx->dhcp_now, <)) {
		dhcp_expire_lease(ctx, lease);
		return 0;
	}

	if (rb_tree_insert_node(&ctx->dhcp_expire_tree, lease) == lease)
		lease->dl_in_expire_tree = true;
	else
		logerrx("%s: failed to insert lease into expiry tree",
		    __func__);
	return 0;
}

void
dhcp_expire_leases(struct dhcp_ctx *ctx)
{
	if (clock_gettime(CLOCK_REALTIME, &ctx->dhcp_now) == -1) {
		logerr("%s: clock_gettime", __func__);
		timespecclear(&ctx->dhcp_now);
	}

	dhcp_lease_foreach(ctx, dhcp_try_expire_lease, ctx);
	dhcp_set_expire_timeout(ctx);
}

int
dhcp_openbpf(struct interface *ifp)
{
	struct ctx *ctx = ifp->if_ctx;
	struct dhcp_ctx *dhcp_ctx = ctx->ctx_dhcp;
	struct ifreq ifr = { .ifr_mtu = 0 };
	size_t buflen;
#ifdef HAVE_CASPER
	cap_rights_t rights;
#endif

	/* Ensure our bootp write buffer is as big as the MTU */
	strlcpy(ifr.ifr_name, ifp->if_name, sizeof(ifr.ifr_name));
	if (ioctl(ctx->ctx_pf_inet_fd, SIOCGIFMTU, &ifr, sizeof(ifr)) == -1) {
		logerr("%s SIOCGIFMTU", __func__);
		return -1;
	}
	buflen = (size_t)ifr.ifr_mtu - sizeof(struct udphdr) -
	    sizeof(struct ip);
	if (buflen > dhcp_ctx->dhcp_bootplen) {
		void *n = realloc(dhcp_ctx->dhcp_bootp, buflen);
		if (n == NULL) {
			logerr("%s: realloc", __func__);
			return -1;
		}
		dhcp_ctx->dhcp_bootp = n;
		dhcp_ctx->dhcp_bootplen = buflen;
	}

	/*
	 * We only write to BPF, we don't read as we get the
	 * same data from the UDP socket even for unconfigured clients.
	 */
	ifp->if_bpf = bpf_open(ifp, bpf_bootp, O_WRONLY);
	if (ifp->if_bpf == NULL)
		return -1;

#ifdef HAVE_CASPER
	cap_rights_init(&rights, CAP_WRITE);
	if (caph_rights_limit(ifp->if_bpf->bpf_fd, &rights) == -1) {
		logerr("%s: caph_rights_limit", __func__);
		return -1;
	}
#endif

	return 0;
}

static int
dhcp_open(void)
{
	int s, n;
	struct sockaddr_in sin;

	s = xsocket(PF_INET, SOCK_DGRAM | SOCK_CXNB, IPPROTO_UDP);
	if (s == -1) {
		logerr("%s: socket", __func__);
		return -1;
	}

	n = 1;
#ifdef IP_RECVDSTADDR
	if (setsockopt(s, IPPROTO_IP, IP_RECVDSTADDR, &n, sizeof(n)) == -1) {
		logerr("%s: IP_RECVDSTADDR", __func__);
		goto errexit;
	}
#endif

	n = 1;
#ifdef IP_RECVIF
	if (setsockopt(s, IPPROTO_IP, IP_RECVIF, &n, sizeof(n)) == -1) {
		logerr("%s: IP_RECVIF", __func__);
		goto errexit;
	}
#else
	if (setsockopt(s, IPPROTO_IP, IP_PKTINFO, &n, sizeof(n)) == -1) {
		logerr("%s: IP_PKTINFO", __func__);
		goto errexit;
	}
#endif

#ifdef SO_RERROR
	n = 1;
	if (setsockopt(s, SOL_SOCKET, SO_RERROR, &n, sizeof(n)) == -1) {
		logerr("%s: SO_RERROR", __func__);
		goto errexit;
	}
#endif

#ifdef HAVE_CASPER
	n = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &n, sizeof(n)) == -1) {
		logerr("%s: SO_REUSEPORT", __func__);
		goto errexit;
	}
#endif

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(BOOTPS);
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		logerr("%s: bind", __func__);
		goto errexit;
	}

	return s;

errexit:
	close(s);
	return -1;
}

struct dhcp_ctx *
dhcp_new(struct ctx *dhcpsd_ctx)
{
	struct dhcp_ctx *ctx;
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

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		logerr("%s: malloc", __func__);
		return NULL;
	}

	ctx->dhcp_ctx = dhcpsd_ctx;
#ifdef HAVE_CASPER
	ctx->dhcp_capfd = -1;
#endif
	ctx->dhcp_fd = dhcp_open();
	if (ctx->dhcp_fd == -1)
		goto err;

	if (eloop_event_add(ctx->dhcp_ctx->ctx_eloop, ctx->dhcp_fd, ELE_READ,
		dhcp_readudp, ctx) == -1) {
		logerr("%s: eloop_event_add", __func__);
		goto err;
	}

#ifdef HAVE_CASPER
	/*
	 * We are only allowed to connect(2) to a socket via cap_net(3)
	 * for send(2). sendto(2) does not work in capabilies mode at all.
	 * As such we open another socket just for sending as connect(2) will
	 * reject clients sending while connected and we don't want that.
	 */
	cap_rights_init(&rights, CAP_READ, CAP_EVENT);
	if (caph_rights_limit(ctx->dhcp_fd, &rights) == -1) {
		logerr("%s: caph_rights_limit", __func__);
		goto err;
	}

	ctx->dhcp_capfd = dhcp_open();
	if (ctx->dhcp_capfd == -1)
		goto err;

	if (connect(ctx->dhcp_capfd, (struct sockaddr *)&sin, sizeof(sin)) ==
	    -1) {
		logerr("%s: cap_connect", __func__);
		goto err;
	}

	cap_rights_init(&wrights, CAP_READ, CAP_EVENT, CAP_WRITE, CAP_CONNECT);
	if (caph_rights_limit(ctx->dhcp_capfd, &wrights) == -1) {
		logerr("%s: caph_rights_limit", __func__);
		goto err;
	}

	if (eloop_event_add(ctx->dhcp_ctx->ctx_eloop, ctx->dhcp_capfd, ELE_READ,
		dhcp_capreadudp, ctx) == -1) {
		logerr("%s: eloop_event_add", __func__);
		goto err;
	}
#endif

	ctx->dhcp_udp_buf = malloc(FRAMELEN_MAX);
	if (ctx->dhcp_udp_buf == NULL) {
		logerr("%s: malloc", __func__);
		goto err;
	}
	ctx->dhcp_udp_buflen = FRAMELEN_MAX;

	ctx->dhcp_lease_time = DHCP_LEASE_TIME;

	if (dhcp_lease_map_new(ctx) == NULL)
		goto err;

	rb_tree_init(&ctx->dhcp_expire_tree, &dhcp_expire_lease_ops);

	return ctx;

err:
	close(ctx->dhcp_fd);
#ifdef HAVE_CASPER
	if (ctx->dhcp_capfd != -1)
		close(ctx->dhcp_capfd);
#endif
	free(ctx->dhcp_udp_buf);
	free(ctx);
	return NULL;
}

void
dhcp_free(struct dhcp_ctx *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->dhcp_fd != -1)
		close(ctx->dhcp_fd);
#ifdef HAVE_CASPER
	if (ctx->dhcp_capfd != -1)
		close(ctx->dhcp_capfd);
#endif
	free(ctx->dhcp_udp_buf);
	free(ctx->dhcp_bootp);
	dhcp_lease_map_free(ctx);
	free(ctx);
}
