/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2025 Roy Marples <roy@marples.name>
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

#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <stdint.h>

#include "config.h"

#ifndef MIN
#define MIN(a, b) ((/*CONSTCOND*/ (a) < (b)) ? (a) : (b))
#define MAX(a, b) ((/*CONSTCOND*/ (a) > (b)) ? (a) : (b))
#endif

#define UNCONST(a)    ((void *)(unsigned long)(const void *)(a))
#define STRINGIFY(a)  #a
#define TOSTRING(a)   STRINGIFY(a)
#define UNUSED(a)     (void)(a)
#define ARRAYCOUNT(a) (sizeof((a)) / sizeof((a)[0]))

/* Some systems don't define timespec macros */
#ifndef timespecclear
#define timespecclear(tsp) (tsp)->tv_sec = (time_t)((tsp)->tv_nsec = 0L)
#define timespecisset(tsp) ((tsp)->tv_sec || (tsp)->tv_nsec)
#define timespeccmp(tsp, usp, cmp)                   \
	(((tsp)->tv_sec == (usp)->tv_sec) ?          \
		((tsp)->tv_nsec cmp(usp)->tv_nsec) : \
		((tsp)->tv_sec cmp(usp)->tv_sec))
#define timespecadd(tsp, usp, vsp)                                \
	do {                                                      \
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;    \
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec; \
		if ((vsp)->tv_nsec >= 1000000000L) {              \
			(vsp)->tv_sec++;                          \
			(vsp)->tv_nsec -= 1000000000L;            \
		}                                                 \
	} while (0)
#define timespecsub(tsp, usp, vsp)                                \
	do {                                                      \
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;    \
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec; \
		if ((vsp)->tv_nsec < 0) {                         \
			(vsp)->tv_sec--;                          \
			(vsp)->tv_nsec += 1000000000L;            \
		}                                                 \
	} while (0)
#endif

#if __GNUC__ > 2 || defined(__INTEL_COMPILER)
#ifndef __unused
#define __unused __attribute__((__unused__))
#endif
#else
#ifndef __unused
#define __unused
#endif
#endif

#define INFINITE_LIFETIME (~0U)

ssize_t decode_rfc1035(char *, size_t, const uint8_t *, size_t);
size_t encode_rfc1035(const char *, uint8_t *);
const char *hwaddr_ntoa(const void *, size_t, char *, size_t);
size_t hwaddr_aton(uint8_t *, const char *);
struct in_addr;
uint16_t in_cksum(const void *, size_t, uint32_t *);
uint8_t inet_ntocidr(struct in_addr *);

struct sockaddr;

size_t sa_len(const struct sockaddr *);
int sa_cmp(const struct sockaddr *, const struct sockaddr *);
#define ss_len(ss) sa_len((const struct sockaddr *)(ss))
int sa_pton(struct sockaddr *, const char *restrict);

/* FNV-1a 64-bit hash */
static inline uint64_t
hash_fnv1a(const void *key, size_t len)
{
	uint64_t hash = 0xcbf29ce484222325U;
	const uint8_t *p = key;

	while (len--)
		hash = (*p++ ^ hash) * 0x100000001b3;

	return hash;
}

/* Define SOCK_CLOEXEC and SOCK_NONBLOCK for systems that lack it.
 * xsocket() in if.c will map them to fctnl FD_CLOEXEC and O_NONBLOCK. */
#ifdef SOCK_CLOEXEC
#define HAVE_SOCK_CLOEXEC
#else
#define SOCK_CLOEXEC 0x10000000
#endif
#ifdef SOCK_NONBLOCK
#define HAVE_SOCK_NONBLOCK
#else
#define SOCK_NONBLOCK 0x20000000
#endif
#ifndef SOCK_CXNB
#define SOCK_CXNB SOCK_CLOEXEC | SOCK_NONBLOCK
#endif
int xsocket(int, int, int);
#endif
