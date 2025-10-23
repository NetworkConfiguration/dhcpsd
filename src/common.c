/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - DHCP client daemon
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

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "config.h"

/* Support very old arpa/nameser.h as found in OpenBSD */
#ifndef NS_MAXDNAME
#define NS_MAXCDNAME MAXCDNAME
#define NS_MAXDNAME  MAXDNAME
#define NS_MAXLABEL  MAXLABEL
#endif

/* decode an rfc1035 dns search order option into a space
 * separated string. returns length of string (including
 * terminating zero) or zero on error. out may be null
 * to just determine output length. */
ssize_t
decode_rfc1035(char *out, size_t len, const uint8_t *p, size_t pl)
{
	const char *start;
	size_t start_len, l, d_len, o_len;
	const uint8_t *r, *q = p, *e;
	int hops;
	uint8_t ltype;

	o_len = 0;
	start = out;
	start_len = len;
	q = p;
	e = p + pl;
	while (q < e) {
		r = NULL;
		d_len = 0;
		hops = 0;
		/* check we are inside our length again in-case
		 * the name isn't fully qualified (ie, not terminated) */
		while (q < e && (l = (size_t)*q++)) {
			ltype = l & 0xc0;
			if (ltype == 0x80 || ltype == 0x40) {
				/* currently reserved for future use as noted
				 * in rfc1035 4.1.4 as the 10 and 01
				 * combinations. */
				errno = ENOTSUP;
				return -1;
			} else if (ltype == 0xc0) { /* pointer */
				if (q == e) {
					errno = ERANGE;
					return -1;
				}
				l = (l & 0x3f) << 8;
				l |= *q++;
				/* save source of first jump. */
				if (!r)
					r = q;
				hops++;
				if (hops > 255) {
					errno = ERANGE;
					return -1;
				}
				q = p + l;
				if (q >= e) {
					errno = ERANGE;
					return -1;
				}
			} else {
				/* straightforward name segment, add with '.' */
				if (q + l > e) {
					errno = ERANGE;
					return -1;
				}
				if (l > NS_MAXLABEL) {
					errno = EINVAL;
					return -1;
				}
				d_len += l + 1;
				if (out) {
					if (l + 1 > len) {
						errno = ENOBUFS;
						return -1;
					}
					memcpy(out, q, l);
					out += l;
					*out++ = '.';
					len -= l;
					len--;
				}
				q += l;
			}
		}

		/* don't count the trailing nul */
		if (d_len > NS_MAXDNAME + 1) {
			errno = E2BIG;
			return -1;
		}
		o_len += d_len;

		/* change last dot to space */
		if (out && out != start)
			*(out - 1) = ' ';
		if (r)
			q = r;
	}

	/* change last space to zero terminator */
	if (out) {
		if (out != start)
			*(out - 1) = '\0';
		else if (start_len > 0)
			*out = '\0';
	}

	/* remove the trailing nul */
	if (o_len != 0)
		o_len--;

	return (ssize_t)o_len;
}

size_t
encode_rfc1035(const char *src, uint8_t *dst)
{
	uint8_t *p;
	uint8_t *lp;
	size_t len;
	uint8_t has_dot;

	if (src == NULL || *src == '\0')
		return 0;

	if (dst) {
		p = dst;
		lp = p++;
	}
	/* Silence bogus GCC warnings */
	else
		p = lp = NULL;

	len = 1;
	has_dot = 0;
	for (; *src; src++) {
		if (*src == '\0')
			break;
		if (*src == '.') {
			/* Skip the trailing . */
			if (src[1] == '\0')
				break;
			has_dot = 1;
			if (dst) {
				*lp = (uint8_t)(p - lp - 1);
				if (*lp == '\0')
					return len;
				lp = p++;
			}
		} else if (dst)
			*p++ = (uint8_t)*src;
		len++;
	}

	if (dst) {
		*lp = (uint8_t)(p - lp - 1);
		if (has_dot)
			*p++ = '\0';
	}

	if (has_dot)
		len++;

	return len;
}

const char *
hwaddr_ntoa(const void *hwaddr, size_t hwlen, char *buf, size_t buflen)
{
	const unsigned char *hp, *ep;
	char *p;

	/* Allow a hwlen of 0 to be an empty string. */
	if (buf == NULL || buflen == 0) {
		errno = ENOBUFS;
		return NULL;
	}

	if (hwlen * 3 > buflen) {
		/* We should still terminate the string just in case. */
		buf[0] = '\0';
		errno = ENOBUFS;
		return NULL;
	}

	hp = hwaddr;
	ep = hp + hwlen;
	p = buf;
	while (hp < ep) {
		if (hp != hwaddr)
			*p++ = ':';
		p += snprintf(p, 3, "%.2x", *hp++);
	}
	*p++ = '\0';
	return buf;
}

size_t
hwaddr_aton(uint8_t *buffer, const char *addr)
{
	char c[3];
	const char *p = addr;
	uint8_t *bp = buffer;
	size_t len = 0;

	c[2] = '\0';
	while (*p != '\0') {
		/* Skip separators */
		c[0] = *p++;
		switch (c[0]) {
		case '\n': /* long duid split on lines */
		case ':':  /* typical mac address */
		case '-':  /* uuid */
			continue;
		}
		c[1] = *p++;
		/* Ensure that digits are hex */
		if (isxdigit((unsigned char)c[0]) == 0 ||
		    isxdigit((unsigned char)c[1]) == 0) {
			errno = EINVAL;
			return 0;
		}
		/* We should have at least two entries 00:01 */
		if (len == 0 && *p == '\0') {
			errno = EINVAL;
			return 0;
		}
		if (bp)
			*bp++ = (uint8_t)strtol(c, NULL, 16);
		len++;
	}
	return len;
}

uint16_t
in_cksum(const void *data, size_t len, uint32_t *isum)
{
	const uint16_t *word = data;
	uint32_t sum = isum != NULL ? *isum : 0;

	for (; len > 1; len -= sizeof(*word))
		sum += *word++;

	if (len == 1)
		sum += htons((uint16_t)(*(const uint8_t *)word << 8));

	if (isum != NULL)
		*isum = sum;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (uint16_t)~sum;
}

uint8_t
inet_ntocidr(struct in_addr *addr)
{
	uint8_t cidr = 0;
	uint32_t mask = htonl(addr->s_addr);

	while (mask) {
		cidr++;
		mask <<= 1;
	}
	return cidr;
}

size_t
sa_len(const struct sockaddr *sa)
{
#ifdef BSD
	return sa->sa_len;
#else
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		errno = EAFNOSUPPORT;
		return 0;
	}
#endif
}

int
sa_cmp(const struct sockaddr *a, const struct sockaddr *b)
{
	if (a->sa_family != b->sa_family)
		return a->sa_family - b->sa_family;
	if (sa_len(a) != sa_len(b))
		return (int)(sa_len(a) - sa_len(b));
	return memcmp(a, b, sa_len(a));
}

int
sa_pton(struct sockaddr *sa, const char *src)
{
	void *addr;
	switch (sa->sa_family) {
	case AF_INET:
		addr = &((struct sockaddr_in *)sa)->sin_addr.s_addr;
		break;
	case AF_INET6:
		addr = &((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
		break;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	return inet_pton(sa->sa_family, src, addr);
}

int
xsocket(int domain, int type, int protocol)
{
	int s;
#if !defined(HAVE_SOCK_CLOEXEC) || !defined(HAVE_SOCK_NONBLOCK)
	int xflags, xtype = type;
#endif

#ifndef HAVE_SOCK_CLOEXEC
	if (xtype & SOCK_CLOEXEC)
		type &= ~SOCK_CLOEXEC;
#endif
#ifndef HAVE_SOCK_NONBLOCK
	if (xtype & SOCK_NONBLOCK)
		type &= ~SOCK_NONBLOCK;
#endif

	if ((s = socket(domain, type, protocol)) == -1)
		return -1;

#ifndef HAVE_SOCK_CLOEXEC
	if ((xtype & SOCK_CLOEXEC) &&
	    ((xflags = fcntl(s, F_GETFD)) == -1 ||
		fcntl(s, F_SETFD, xflags | FD_CLOEXEC) == -1))
		goto out;
#endif
#ifndef HAVE_SOCK_NONBLOCK
	if ((xtype & SOCK_NONBLOCK) &&
	    ((xflags = fcntl(s, F_GETFL)) == -1 ||
		fcntl(s, F_SETFL, xflags | O_NONBLOCK) == -1))
		goto out;
#endif

	return s;

#if !defined(HAVE_SOCK_CLOEXEC) || !defined(HAVE_SOCK_NONBLOCK)
out:
	close(s);
	return -1;
#endif
}
