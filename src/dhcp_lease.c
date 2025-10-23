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

#include <sys/time.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "common.h"
#include "config.h"
#include "dhcp.h"
#include "dhcp_lease.h"
#include "logerr.h"

static inline uint64_t
dhcp_clientidhash(const uint8_t *key)
{
	return hash_fnv1a(key + 1, key[0]);
}

static inline bool
dhcp_clientidcmp(const uint8_t *a, const uint8_t *b)
{
	if (a[0] != b[0])
		return false;
	return memcmp(a + 1, b + 1, a[0]) == 0;
}

#define NAME	dhcp_lease_map
#define KEY_TY	const uint8_t *
#define VAL_TY	struct dhcp_lease *
#define HASH_FN dhcp_clientidhash
#define CMPR_FN dhcp_clientidcmp
#include "verstable.h"

#define NAME	dhcp_addr_map
#define KEY_TY	uint32_t
#define VAL_TY	struct dhcp_lease *
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

void *
dhcp_lease_map_new(struct dhcp_ctx *ctx)
{
	dhcp_lease_map *map;
	dhcp_addr_map *amap;

	map = malloc(sizeof(*map));
	if (map == NULL) {
		logerr("%s: malloc", __func__);
		return NULL;
	}

	vt_init(map);
	ctx->dhcp_lease_map = map;

	amap = malloc(sizeof(*amap));
	if (amap == NULL) {
		logerr("%s: malloc", __func__);
		return NULL;
	}

	vt_init(amap);
	ctx->dhcp_addr_map = amap;

	return map;
}

struct dhcp_lease *
dhcp_lease_find(struct dhcp_ctx *ctx, const uint8_t *clientid)
{
	dhcp_lease_map *map = ctx->dhcp_lease_map;
	dhcp_lease_map_itr itr;

	itr = vt_get(map, clientid);
	if (vt_is_end(itr)) {
		errno = ESRCH;
		return NULL;
	}
	return itr.data->val;
}

int
dhcp_lease_insert(struct dhcp_ctx *ctx, struct dhcp_lease *lease)
{
	dhcp_lease_map *map = ctx->dhcp_lease_map;
	dhcp_lease_map_itr itr;

	itr = vt_insert(map, lease->dl_clientid, lease);
	if (vt_is_end(itr))
		return -1;

	return 0;
}

int
dhcp_lease_erase(struct dhcp_ctx *ctx, struct dhcp_lease *lease)
{
	dhcp_lease_map *map = ctx->dhcp_lease_map;

	if (lease == NULL)
		return 0;
	return vt_erase(map, lease->dl_clientid) ? 0 : -1;
}

struct dhcp_lease *
dhcp_lease_findaddr(struct dhcp_ctx *ctx, const struct in_addr *addr)
{
	dhcp_addr_map *amap = ctx->dhcp_addr_map;
	dhcp_addr_map_itr itr;

	itr = vt_get(amap, addr->s_addr);
	if (vt_is_end(itr)) {
		errno = ESRCH;
		return NULL;
	}
	return itr.data->val;
}

int
dhcp_lease_eraseaddr(struct dhcp_ctx *ctx, const struct in_addr *addr)
{
	dhcp_addr_map *amap = ctx->dhcp_addr_map;

	return vt_erase(amap, addr->s_addr) ? 0 : -1;
}

int
dhcp_lease_insertaddr(struct dhcp_ctx *ctx, struct dhcp_lease *lease)
{
	dhcp_addr_map *amap = ctx->dhcp_addr_map;
	dhcp_addr_map_itr aitr;

	if (lease->dl_addr.s_addr == INADDR_ANY ||
	    lease->dl_addr.s_addr == INADDR_BROADCAST) {
		errno = EINVAL;
		return -1;
	}

	aitr = vt_insert(amap, lease->dl_addr.s_addr, lease);
	if (vt_is_end(aitr))
		return -1;
	return 0;
}

void
dhcp_lease_map_free(struct dhcp_ctx *ctx)
{
	dhcp_lease_map *map = ctx->dhcp_lease_map;
	dhcp_addr_map *amap = ctx->dhcp_addr_map;
	dhcp_lease_map_itr itr;
	dhcp_addr_map_itr aitr;

	for (itr = vt_first(map); !vt_is_end(itr); itr = vt_next(itr)) {
		if (itr.data->val->dl_flags & DL_ADDRESS)
			vt_erase(amap, itr.data->val->dl_addr.s_addr);
		free(itr.data->val);
	}
	vt_cleanup(map);
	free(map);

	for (aitr = vt_first(amap); !vt_is_end(aitr); aitr = vt_next(aitr)) {
		free(aitr.data->val);
	}
	vt_cleanup(amap);
	free(amap);
}

int
dhcp_lease_foreach(struct dhcp_ctx *ctx, int (*cb)(void *, struct dhcp_lease *),
    void *cb_ctx)
{
	dhcp_lease_map *map = ctx->dhcp_lease_map;
	dhcp_lease_map_itr itr;

	for (itr = vt_first(map); !vt_is_end(itr); itr = vt_next(itr)) {
		if (cb(cb_ctx, itr.data->val) == -1)
			return -1;
	}
	return 0;
}

int
dhcp_lease_foreachaddr(struct dhcp_ctx *ctx,
    int (*cb)(void *, struct dhcp_lease *), void *cb_ctx)
{
	dhcp_addr_map *map = ctx->dhcp_addr_map;
	dhcp_addr_map_itr itr;

	for (itr = vt_first(map); !vt_is_end(itr); itr = vt_next(itr)) {
		if (cb(cb_ctx, itr.data->val) == -1)
			return -1;
	}
	return 0;
}
