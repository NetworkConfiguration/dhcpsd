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

#ifndef INTERFACE_H
#define INTERFACE_H

#include <net/if.h>

#include "queue.h"

/* The BSD's don't define this yet */
#ifndef ARPHRD_INFINIBAND
#define ARPHRD_INFINIBAND 32
#endif

/* Maximum frame length.
 * Support jumbo frames and some extra. */
#define FRAMEHDRLEN_MAX 14 /* only ethernet support */
#define FRAMELEN_MAX	(FRAMEHDRLEN_MAX + 9216)

#define IF_HWADDR_LEN	20

struct bpf;
struct ctx;
struct dhcp_pool;
struct iovec;

struct interface {
	TAILQ_ENTRY(interface) if_next;
	struct ctx *if_ctx;
	char if_name[IF_NAMESIZE];
	unsigned int if_index;
	uint16_t if_hwtype; /* ARPHRD_ETHER for example */
	uint8_t if_hwaddr[IF_HWADDR_LEN];
	uint8_t if_hwlen;
	int if_mtu;
	unsigned int if_flags;
#define IF_ACTIVE 0x01U

	struct dhcp_pool *if_pools;
	size_t if_npools;
	struct bpf *if_bpf;
	ssize_t (*if_output)(const struct interface *, int,
	    const struct iovec *, int);
};
TAILQ_HEAD(if_head, interface);

struct ifaddrs;

int if_learnifaces(struct ctx *);
void if_free(struct interface *);
struct interface *if_findifpfromcmsg(struct ctx *, struct msghdr *, void *);

#endif
