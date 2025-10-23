/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpcd: BPF bootp filtering
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#ifdef __linux__
/* Special BPF snowflake. */
#include <linux/filter.h>
#define bpf_insn sock_filter
#include <linux/if_packet.h>
#else
#include <net/bpf.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "common.h"
#include "dhcp.h"
#include "if.h"
#include "logerr.h"

/* BPF helper macros */
#ifdef __linux__
#define BPF_WHOLEPACKET 0x7fffffff /* work around buggy LPF filters */
#else
#define BPF_WHOLEPACKET ~0U
#endif

/* Macros to update the BPF structure */
#define BPF_SET_STMT(insn, c, v)           \
	{                                  \
		(insn)->code = (c);        \
		(insn)->jt = 0;            \
		(insn)->jf = 0;            \
		(insn)->k = (uint32_t)(v); \
	}

#define BPF_SET_JUMP(insn, c, v, t, f)     \
	{                                  \
		(insn)->code = (c);        \
		(insn)->jt = (t);          \
		(insn)->jf = (f);          \
		(insn)->k = (uint32_t)(v); \
	}

static const struct bpf_insn bpf_reject[] = {
	/* Reject everything as we are not reading from BPF, just sending */
	BPF_STMT(BPF_RET + BPF_K, 0),
};
#define BPF_REJECT_LEN ARRAYCOUNT(bpf_reject)

#ifdef BIOCSETWF

#ifdef ARPHRD_NONE
static const struct bpf_insn bpf_none[] = {};
#define BPF_NONE_LEN ARRAYCOUNT(bpf_none)
#endif

static const struct bpf_insn bpf_ether[] = {
	/* Make sure this is an IP packet. */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	    offsetof(struct ether_header, ether_type)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Advance to the IP header. */
	BPF_STMT(BPF_LDX + BPF_K, sizeof(struct ether_header)),
};
#define BPF_ETHER_LEN ARRAYCOUNT(bpf_ether)

static const struct bpf_insn bpf_bootp_base[] = {
	/* Make sure it's an IPv4 packet. */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, 0),
	BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0xf0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x40, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Make sure it's a UDP packet. */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(struct ip, ip_p)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Make sure this isn't a fragment. */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct ip, ip_off)),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Advance to the UDP header. */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, 0),
	BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x0f),
	BPF_STMT(BPF_ALU + BPF_MUL + BPF_K, 4),
	BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),
	BPF_STMT(BPF_MISC + BPF_TAX, 0),
};
#define BPF_BOOTP_BASE_LEN ARRAYCOUNT(bpf_bootp_base)

static const struct bpf_insn bpf_bootp_write[] = {
	/* Make sure it's from and to the right port.
	 * RFC2131 makes no mention of encforcing a source port,
	 * but dhcpsd does enforce it for sending. */
	BPF_STMT(BPF_LD + BPF_W + BPF_IND, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (BOOTPS << 16) + BOOTPC, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
};
#define BPF_BOOTP_WRITE_LEN ARRAYCOUNT(bpf_bootp_write)

#define BPF_BOOTP_LEN	    BPF_ETHER_LEN + BPF_BOOTP_BASE_LEN + BPF_BOOTP_WRITE_LEN
#else
#define BPF_BOOTP_LEN BPF_REJECT_LEN
#endif

#if 0
static const struct bpf_insn bpf_icmp_base[] = {
	/* Make sure it's an IPv4 packet. */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, 0),
	BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0xf0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x40, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Make sure it's a ICMP packet. */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(struct ip, ip_p)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Make sure this isn't a fragment. */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct ip, ip_off)),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Advance to the ICMP header. */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, 0),
	BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x0f),
	BPF_STMT(BPF_ALU + BPF_MUL + BPF_K, 4),
	BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),
	BPF_STMT(BPF_MISC + BPF_TAX, 0),
};
#define BPF_ICMP_BASE_LEN      ARRAYCOUNT(bpf_icmp_base)

static const struct bpf_insn bpf_icmp_echo[] = {
	/* ICMP_ECHO */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ICMP_ECHO, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Ensure code is zero */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, 1),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
};
#define BPF_ICMP_ECHO_LEN      ARRAYCOUNT(bpf_icmp_echo)

static const struct bpf_insn bpf_icmp_echoreply[] = {
	/* ICMP_ECHOREPLY */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ICMP_ECHOREPLY, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Ensure code is zero */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, 1),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
};
#define BPF_ICMP_ECHOREPLY_LEN ARRAYCOUNT(bpf_icmp_echoreply)

#define BPF_ICMP_LEN                        \
	BPF_ETHER_LEN + BPF_ICMP_BASE_LEN + \
	    MAX(BPF_ICMP_ECHO_LEN, BPF_ICMP_ECHOREPLY_LEN)
#endif

#ifdef __linux__
static int
bpf_attach(int fd, bool read, void *filter, unsigned int filter_len)
{
	struct sock_fprog pf = {
		.filter = filter,
		.len = (unsigned short)filter_len,
	};
	UNUSED(read);

	/* Install the filter. */
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) == -1)
		return -1;

#ifdef SO_LOCK_FILTER
	int on = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &on, sizeof(on)) == -1)
		return -1;
#endif

	return 0;
}
#else
static int
bpf_attach(int fd, bool read, void *filter, unsigned int filter_len)
{
	struct bpf_program pf = { .bf_insns = filter, .bf_len = filter_len };

	/* Install the filter. */
	if (read)
		return ioctl(fd, BIOCSETF, &pf);
#ifdef BIOCSETWF
	return ioctl(fd, BIOCSETWF, &pf);
#else
	return 0;
#endif
}
#endif

static int
bpf_bootp_rw(const struct bpf *bpf, bool read)
{
	struct bpf_insn buf[BPF_BOOTP_LEN + 1];
	struct bpf_insn *bp;

	bp = buf;

	if (read) {
		memcpy(bp, bpf_reject, sizeof(bpf_reject));
		bp += BPF_REJECT_LEN;
		return bpf_attach(bpf->bpf_fd, read, buf,
		    (unsigned int)(bp - buf));
	}

#ifdef BIOCSETWF
	switch (bpf->bpf_if->if_hwtype) {
#ifdef ARPHRD_NONE
	case ARPHRD_NONE:
		memcpy(bp, bpf_bootp_none, sizeof(bpf_bootp_none));
		bp += BPF_BOOTP_NONE_LEN;
		break;
#endif
	case ARPHRD_ETHER:
		memcpy(bp, bpf_ether, sizeof(bpf_ether));
		bp += BPF_ETHER_LEN;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	/* Copy in the main filter. */
	memcpy(bp, bpf_bootp_base, sizeof(bpf_bootp_base));
	bp += BPF_BOOTP_BASE_LEN;

	memcpy(bp, bpf_bootp_write, sizeof(bpf_bootp_write));
	bp += BPF_BOOTP_WRITE_LEN;

	/* All passed, return the packet. */
	BPF_SET_STMT(bp, BPF_RET + BPF_K, BPF_WHOLEPACKET);
	bp++;

	return bpf_attach(bpf->bpf_fd, read, buf, (unsigned int)(bp - buf));
#else
	UNUSED(bpf);
	return 0;
#endif
}

int
bpf_bootp(const struct bpf *bpf)
{
#ifdef BIOCSETWF
	if (bpf_bootp_rw(bpf, true) == -1 || bpf_bootp_rw(bpf, false) == -1 ||
	    ioctl(bpf->bpf_fd, BIOCLOCK) == -1)
		return -1;
	return 0;
#else
#if defined(BIOCSETF)
#warning No BIOCSETWF support - a compromised BPF can be used as a raw socket
#else
#warning A compromised PF_PACKET socket can be used as a raw socket
#endif
	return bpf_bootp_rw(bpf, true);
#endif
}

/* Currently using a RAW socket to read ICMP_ECHOREPLY.
 * If it proves to busy, we could use this. */
#if 0
static int
bpf_icmp_rw(const struct bpf *bpf, bool read)
{
	struct bpf_insn buf[BPF_ICMP_LEN + 1];
	struct bpf_insn *bp;

	bp = buf;

	switch (bpf->bpf_if->if_hwtype) {
#ifdef ARPHRD_NONE
	case ARPHRD_NONE:
		memcpy(bp, bpf_bootp_none, sizeof(bpf_bootp_none));
		bp += BPF_BOOTP_NONE_LEN;
		break;
#endif
	case ARPHRD_ETHER:
		memcpy(bp, bpf_ether, sizeof(bpf_ether));
		bp += BPF_ETHER_LEN;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	/* Copy in the main filter. */
	memcpy(bp, bpf_icmp_base, sizeof(bpf_icmp_base));
	bp += BPF_ICMP_BASE_LEN;

	if (read) {
		memcpy(bp, bpf_icmp_echoreply, sizeof(bpf_icmp_echoreply));
		bp += BPF_ICMP_ECHOREPLY_LEN;
	} else {
		memcpy(bp, bpf_icmp_echo, sizeof(bpf_icmp_echo));
		bp += BPF_ICMP_ECHO_LEN;
	}

	/* All passed, return the packet. */
	BPF_SET_STMT(bp, BPF_RET + BPF_K, BPF_WHOLEPACKET);
	bp++;

	return bpf_attach(bpf->bpf_fd, read, buf, (unsigned int)(bp - buf));
}

int
bpf_icmp(const struct bpf *bpf)
{
#ifdef BIOCSETWF
	if (bpf_icmp_rw(bpf, true) == -1 || bpf_icmp_rw(bpf, false) == -1 ||
	    ioctl(bpf->bpf_fd, BIOCLOCK) == -1)
		return -1;
	return 0;
#else
	return bpf_icmp_rw(bpf, true);
#endif
}
#endif

struct bpf *
bpf_open(const struct interface *ifp, int (*filter)(const struct bpf *),
    unsigned int flags)
{
	struct bpf *bpf;
#ifdef __linux__
	struct sockaddr_ll sll = {
		.sll_family = PF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = (int)ifp->if_index,
	};
#ifdef PACKET_AUXDATA
	int n;
#endif
#else
	struct bpf_version pv = { .bv_major = 0, .bv_minor = 0 };
	struct ifreq ifr = { .ifr_flags = 0 };
#if 0
	int ibuf_len = 0;
#endif
	unsigned int imm;
#ifndef O_CLOEXEC
	int fd_opts;
#endif
#endif

	bpf = calloc(1, sizeof(*bpf));
	if (bpf == NULL) {
		logerr("%s: calloc", __func__);
		return NULL;
	}
	bpf->bpf_if = ifp;
	bpf->bpf_flags = BPF_EOF;

#ifdef __linux__
	bpf->bpf_fd = xsocket(PF_PACKET, SOCK_RAW | SOCK_CXNB,
	    htons(ETH_P_ALL));
	if (bpf->bpf_fd == -1)
		goto eexit;

	/* We cannot validate the correct interface,
	 * so we MUST set this first. */
	if (bind(bpf->bpf_fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
		logerr("%s: bind", __func__);
		goto eexit;
	}

	/* In the ideal world, this would be set before the bind and filter. */
#ifdef PACKET_AUXDATA
	n = 1;
	if (setsockopt(bpf->bpf_fd, SOL_PACKET, PACKET_AUXDATA, &n,
		sizeof(n)) != 0) {
		if (errno != ENOPROTOOPT) {
			logerr("%s: setsockopt PACKET_AUXDATA", __func__);
			goto eexit;
		}
	}
#endif

#else /* !__linux__ */

#ifdef O_CLOEXEC
#define BPF_OPEN_FLAGS O_RDWR | O_NONBLOCK | O_CLOEXEC
#else
#define BPF_OPEN_FLAGS O_RDWR | O_NONBLOCK
#endif

	/* /dev/bpf is a cloner on modern kernels */
	bpf->bpf_fd = open("/dev/bpf", BPF_OPEN_FLAGS);

	/* Support older kernels where /dev/bpf is not a cloner */
	if (bpf->bpf_fd == -1) {
		char device[32];
		int n = 0, r;

		do {
			r = snprintf(device, sizeof(device), "/dev/bpf%d", n++);
			if (r == -1)
				break;
			bpf->bpf_fd = open(device, BPF_OPEN_FLAGS);
		} while (bpf->bpf_fd == -1 && errno == EBUSY);
	}

	if (bpf->bpf_fd == -1) {
		logerr("%s: open bpf", __func__);
		goto eexit;
	}

#ifndef O_CLOEXEC
	if ((fd_opts = fcntl(bpf->bpf_fd, F_GETFD)) == -1 ||
	    fcntl(fd, F_SETFD, bpf->bpf_fd_opts | FD_CLOEXEC) == -1) {
		logerr("%s: fcntl", __func__);
		goto eexit;
	}
#endif

	if (ioctl(bpf->bpf_fd, BIOCVERSION, &pv) == -1) {
		logerr("%s: BIOCVERSION", __func__);
		goto eexit;
	}
	if (pv.bv_major != BPF_MAJOR_VERSION ||
	    pv.bv_minor < BPF_MINOR_VERSION) {
		logerrx("BPF version mismatch - recompile");
		goto eexit;
	}

	strlcpy(ifr.ifr_name, ifp->if_name, sizeof(ifr.ifr_name));
	if (ioctl(bpf->bpf_fd, BIOCSETIF, &ifr) == -1) {
		logerr("%s: BIOCSETIF %s", __func__, ifp->if_name);
		goto eexit;
	}

#ifdef BIOCIMMEDIATE
	imm = 1;
	if (ioctl(bpf->bpf_fd, BIOCIMMEDIATE, &imm) == -1)
		goto eexit;
#endif
#endif /* !__linux__ */

	if (filter(bpf) != 0)
		goto eexit;

/* As we are only writing to BPF, we don't need a buffer */
#if 0
#ifdef __linux__
	UNUSED(flags);
#else
	if (flags & (O_RDONLY | O_RDWR)) {
		/* Get the required BPF buffer length from the kernel. */
		if (ioctl(bpf->bpf_fd, BIOCGBLEN, &ibuf_len) == -1)
			goto eexit;

		bpf->bpf_size = (size_t)ibuf_len;
		bpf->bpf_buffer = malloc(bpf->bpf_size);
		if (bpf->bpf_buffer == NULL)
			goto eexit;
	}
#endif
#else
	UNUSED(flags);
#endif

	return bpf;

eexit:
	close(bpf->bpf_fd);
	free(bpf);
	return NULL;
}

/* Keep support for reading around, we might need it in the future. */
#if 0
/* BPF requires that we read the entire buffer.
 * So we pass the buffer in the API so we can loop on >1 packet. */
ssize_t
bpf_read(struct bpf *bpf, void *data, size_t len)
{
	ssize_t bytes;
	struct bpf_hdr packet;
	const char *payload;

	bpf->bpf_flags &= ~BPF_EOF;
	for (;;) {
		if (bpf->bpf_len == 0) {
			bytes = read(bpf->bpf_fd, bpf->bpf_buffer,
			    bpf->bpf_size);
#if defined(__sun)
			/* After 2^31 bytes, the kernel offset overflows.
			 * To work around this bug, lseek 0. */
			if (bytes == -1 && errno == EINVAL) {
				lseek(bpf->bpf_fd, 0, SEEK_SET);
				continue;
			}
#endif
			if (bytes == -1 || bytes == 0)
				return bytes;
			bpf->bpf_len = (size_t)bytes;
			bpf->bpf_pos = 0;
		}
		bytes = -1;
		payload = (const char *)bpf->bpf_buffer + bpf->bpf_pos;
		memcpy(&packet, payload, sizeof(packet));
		if (bpf->bpf_pos + packet.bh_caplen + packet.bh_hdrlen >
		    bpf->bpf_len)
			goto next; /* Packet beyond buffer, drop. */
		payload += packet.bh_hdrlen;
		if (packet.bh_caplen > len)
			bytes = (ssize_t)len;
		else
			bytes = (ssize_t)packet.bh_caplen;
		memcpy(data, payload, (size_t)bytes);
	next:
		bpf->bpf_pos += BPF_WORDALIGN(
		    packet.bh_hdrlen + packet.bh_caplen);
		if (bpf->bpf_pos >= bpf->bpf_len) {
			bpf->bpf_len = bpf->bpf_pos = 0;
			bpf->bpf_flags |= BPF_EOF;
		}
		if (bytes != -1)
			return bytes;
	}

	/* NOTREACHED */
}
#endif

void
bpf_close(struct bpf *bpf)
{
	close(bpf->bpf_fd);
	free(bpf->bpf_buffer);
	free(bpf);
}
