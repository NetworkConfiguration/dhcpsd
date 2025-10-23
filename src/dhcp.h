/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - DHCP server daemon
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

#ifndef DHCP_H
#define DHCP_H

#include <netinet/in.h>

/* UDP port numbers for BOOTP */
#define BOOTPS	       67
#define BOOTPC	       68

#define MAGIC_COOKIE   0x63825363
#define BROADCAST_FLAG 0x8000

/* BOOTP message OP code */
#define BOOTREQUEST 1
#define BOOTREPLY   2

/* DHCP message type */
#define DHCP_BOOTREQUEST 0
#define DHCP_DISCOVER	 1
#define DHCP_OFFER	 2
#define DHCP_REQUEST	 3
#define DHCP_DECLINE	 4
#define DHCP_ACK	 5
#define DHCP_NAK	 6
#define DHCP_RELEASE	 7
#define DHCP_INFORM	 8
#define DHCP_FORCERENEW	 9

/* Constants taken from RFC 2131. */
#define T1	      0.5
#define T2	      0.875
#define DHCP_BASE     4
#define DHCP_MAX      64
#define DHCP_RAND_MIN -1
#define DHCP_RAND_MAX 1

#ifdef RFC2131_STRICT
/* Be strictly conformant for section 4.1.1 */
#define DHCP_MIN_DELAY 1
#define DHCP_MAX_DELAY 10
#else
/* or mirror the more modern IPv6RS and DHCPv6 delays */
#define DHCP_MIN_DELAY 0
#define DHCP_MAX_DELAY 1
#endif

/* DHCP options */
enum DHO {
	DHO_PAD = 0,
	DHO_SUBNETMASK = 1,
	DHO_ROUTER = 3,
	DHO_DNSSERVER = 6,
	DHO_HOSTNAME = 12,
	DHO_DNSDOMAIN = 15,
	DHO_MTU = 26,
	DHO_BROADCAST = 28,
	DHO_STATICROUTE = 33,
	DHO_NISDOMAIN = 40,
	DHO_NISSERVER = 41,
	DHO_NTPSERVER = 42,
	DHO_VENDOR = 43,
	DHO_IPADDRESS = 50,
	DHO_LEASETIME = 51,
	DHO_OPTSOVERLOADED = 52,
	DHO_MESSAGETYPE = 53,
	DHO_SERVERID = 54,
	DHO_PARAMETERREQUESTLIST = 55,
	DHO_MESSAGE = 56,
	DHO_MAXMESSAGESIZE = 57,
	DHO_RENEWALTIME = 58,
	DHO_REBINDTIME = 59,
	DHO_VENDORCLASSID = 60,
	DHO_CLIENTID = 61,
	DHO_USERCLASS = 77,	       /* RFC 3004 */
	DHO_RAPIDCOMMIT = 80,	       /* RFC 4039 */
	DHO_FQDN = 81,		       /* RFC 4702 */
	DHO_AUTHENTICATION = 90,       /* RFC 3118 */
	DHO_IPV6_PREFERRED_ONLY = 108, /* RFC 8925 */
	DHO_AUTOCONFIGURE = 116,       /* RFC 2563 */
	DHO_DNSSEARCH = 119,	       /* RFC 3397 */
	DHO_CSR = 121,		       /* RFC 3442 */
	DHO_VIVCO = 124,	       /* RFC 3925 */
	DHO_VIVSO = 125,	       /* RFC 3925 */
	DHO_FORCERENEW_NONCE = 145,    /* RFC 6704 */
	DHO_MUDURL = 161,	       /* draft-ietf-opsawg-mud */
	DHO_SIXRD = 212,	       /* RFC 5969 */
	DHO_MSCSR = 249,	       /* MS code for RFC 3442 */
	DHO_END = 255
};

#define FQDN_N		0x08
#define FQDN_E		0x04
#define FQDN_O		0x02
#define FQDN_S		0x01

#define MIN_V6ONLY_WAIT 300 /* seconds, RFC 8925 */

/* Sizes for BOOTP options */
#define BOOTP_CHADDR_LEN 16
#define BOOTP_SNAME_LEN	 64
#define BOOTP_FILE_LEN	 128
#define BOOTP_VEND_LEN	 64

/* DHCP is basically an extension to BOOTP */
struct bootp {
	uint8_t op;	 /* message type */
	uint8_t htype;	 /* hardware address type */
	uint8_t hlen;	 /* hardware address length */
	uint8_t hops;	 /* should be zero in client message */
	uint32_t xid;	 /* transaction id */
	uint16_t secs;	 /* elapsed time in sec. from boot */
	uint16_t flags;	 /* such as broadcast flag */
	uint32_t ciaddr; /* (previously allocated) client IP */
	uint32_t yiaddr; /* 'your' client IP address */
	uint32_t siaddr; /* should be zero in client's messages */
	uint32_t giaddr; /* should be zero in client's messages */
	uint8_t chaddr[BOOTP_CHADDR_LEN]; /* client's hardware address */
	char sname[BOOTP_SNAME_LEN];	  /* server host name */
	char file[BOOTP_FILE_LEN];	  /* boot file name */
	uint8_t vend[BOOTP_VEND_LEN];	  /* vendor specific area */
	/* DHCP allows a variable length vendor area */
};

#define DHCP_TTL	128
#define DHCP_LEASE_TIME 3600

struct dhcp_pool {
	struct in_addr dp_addr;
	struct in_addr dp_mask;
	struct in_addr dp_from;
	struct in_addr dp_to;
};

#define DHCP_CLIENTID_LEN 1 + 255 /* first byte is length */
#define DHCP_HOSTNAME_LEN 255 + 1 /* Space for a trailing NUL */
struct dhcp_lease {
	uint8_t dl_clientid[DHCP_CLIENTID_LEN];
	struct in_addr dl_addr;
	uint32_t dl_flags;
#define DL_ADDRESS	   0x0001U // A
#define DL_OFFERED	   0x0002U // O
#define DL_LEASED	   0x0004U // L
#define DL_DECLINED	   0x0008U // D
#define DL_INFORMED	   0x0010U // I
#define DL_HOSTNAME	   0x0020U // H
#define DL_UPDATE_DNSA	   0x0040U // N
#define DL_UPDATE_DNSPTR   0x0080U // P
#define DL_PLUGIN_HOSTNAME 0x0200U // h
#define DL_PLUGIN_DNSA	   0x0400U // n
#define DL_PLUGIN_DNSPTR   0x0800U // p
#define DL_PLUGIN_ADDRESS  0x1000U // a
#define DL_PLUGIN_RESERVED 0x2000U // r
#define DL_PLUGIN_DECLINED 0x4000U // d
#define DL_PLUGIN_TESTING  0x8000U // t
#define DL_ANY_DECLINED	   (DL_DECLINED | DL_PLUGIN_DECLINED)
	struct timespec dl_leased;
	struct timespec dl_expires;
	char dl_hostname[DHCP_HOSTNAME_LEN];
#ifdef DHCP_PRIVATE
	/* Only dhcp.c needs access to this, plugins etc don't. */
	rb_node_t dl_expire_tree;
	bool dl_in_expire_tree;
#endif
};

struct ctx;
struct dhcp_ctx {
	struct ctx *dhcp_ctx;
	int dhcp_fd;
	void *dhcp_lease_map;
	void *dhcp_addr_map;
	uint32_t dhcp_lease_time;
	void *dhcp_udp_buf;
	size_t dhcp_udp_buflen;
	struct bootp *dhcp_bootp;
	size_t dhcp_bootplen;
#ifdef HAVE_CASPER
	int dhcp_capfd;
#endif
#ifdef DHCP_PRIVATE
	/* Only dhcp.c needs access to this, plugins etc don't. */
	rb_tree_t dhcp_expire_tree;
	struct timespec dhcp_now;
#endif
};

struct interface;

struct dhcp_ctx *dhcp_new(struct ctx *);
void dhcp_free(struct dhcp_ctx *);
int dhcp_openbpf(struct interface *);
void dhcp_expire_leases(struct dhcp_ctx *ctx);

struct dhcp_lease *dhcp_alloclease(void);
struct dhcp_lease *dhcp_newlease(struct dhcp_ctx *, const uint8_t *);
struct dhcp_lease *dhcp_newleaseaddr(struct dhcp_ctx *,
    const struct dhcp_lease *);

/* For plugins to interogate the DHCP message */
const uint8_t *dhcp_findoption(const struct bootp *, size_t, uint8_t);

const char *dhcp_ftoa(uint32_t);
uint32_t dhcp_atof(const char *);

/* Macros for plugins to insert DHCP options */
#define DHCP_PUT_CHECK(p, e, l)                           \
	do {                                              \
		if ((l) > 255 || *(p) + 2 + (l) >= (e)) { \
			errno = E2BIG;                    \
			return -1;                        \
		}                                         \
	} while (0 /* CONSTCOND */)
#define DHCP_PUT_O(p, e, o)                  \
	do {                                 \
		DHCP_PUT_CHECK((p), (e), 0); \
		**(p) = (o);                 \
		*(p) = *p + 1;               \
		**(p) = 0;                   \
		*(p) = *(p) + 1;             \
	} while (0 /* CONSTCOND */)
#define DHCP_PUT_B(p, e, o, v)               \
	do {                                 \
		DHCP_PUT_CHECK((p), (e), 1); \
		**(p) = (o);                 \
		*(p) = *(p) + 1;             \
		**(p) = 1;                   \
		*(p) = *(p) + 1;             \
		**(p) = (v);                 \
		*(p) = *(p) + 1;             \
	} while (0 /* CONSTCOND */)
#define DHCP_PUT_BIN(p, e, o, v, l)            \
	do {                                   \
		DHCP_PUT_CHECK((p), (e), (l)); \
		**(p) = (o);                   \
		*(p) = *(p) + 1;               \
		**(p) = (uint8_t)(l);          \
		*(p) = *(p) + 1;               \
		memcpy(*(p), (v), (l));        \
		*(p) = *(p) + (l);             \
	} while (0 /* CONSTCOND */)
#define DHCP_PUT_U32(p, e, o, v)                                     \
	do {                                                         \
		DHCP_PUT_CHECK((p), (e), sizeof(uint32_t));          \
		DHCP_PUT_BIN((p), (e), (o), &(v), sizeof(uint32_t)); \
	} while (0 /* CONSTCOND */)
#define DHCP_PUT_STR(p, e, o, v)                               \
	do {                                                   \
		DHCP_PUT_CHECK((p), (e), strlen((v)));         \
		DHCP_PUT_BIN((p), (e), (o), (v), strlen((v))); \
	} while (0 /* CONSTCOND */)
#define DHCP_EXTEND_CHECK(o, p, e, l)                          \
	do {                                                   \
		if ((o)[1] + (l) > 255 || *(p) + (l) >= (e)) { \
			errno = E2BIG;                         \
			return -1;                             \
		}                                              \
	} while (0 /* CONSTCOND */)
#define DHCP_EXTEND_U32(o, p, e, v)                                 \
	do {                                                        \
		DHCP_EXTEND_CHECK((o), (p), (e), sizeof(uint32_t)); \
		o[1] = o[1] + sizeof(uint32_t);                     \
		memcpy(*(p), &(v), sizeof(uint32_t));               \
		*(p) = *(p) + sizeof(uint32_t);                     \
	} while (0 /* CONSTCOND */)

#endif /* DHCP_H */
