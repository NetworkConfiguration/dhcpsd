/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - DHCP lease hashmap
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

#ifndef DHCP_LEASE_H
#define DHCP_LEASE_H

#include "dhcp.h"

void *dhcp_lease_map_new(struct dhcp_ctx *);
void dhcp_lease_map_free(struct dhcp_ctx *);

struct dhcp_lease *dhcp_lease_find(struct dhcp_ctx *, const uint8_t *);
int dhcp_lease_insert(struct dhcp_ctx *, struct dhcp_lease *);
int dhcp_lease_erase(struct dhcp_ctx *, struct dhcp_lease *);

struct dhcp_lease *dhcp_lease_findaddr(struct dhcp_ctx *,
    const struct in_addr *);
int dhcp_lease_insertaddr(struct dhcp_ctx *, struct dhcp_lease *);
int dhcp_lease_eraseaddr(struct dhcp_ctx *, const struct in_addr *);

int dhcp_lease_foreach(struct dhcp_ctx *,
    int (*cb)(void *, struct dhcp_lease *), void *);
int dhcp_lease_foreachaddr(struct dhcp_ctx *,
    int (*cb)(void *, struct dhcp_lease *), void *);
#endif
