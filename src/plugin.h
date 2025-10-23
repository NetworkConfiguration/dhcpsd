/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - Plugin
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

#ifndef PLUGIN_H
#define PLUGIN_H

#include "config.h"

struct ctx;
struct interface;
struct svc_ctx;
struct bootp;
struct dhcp_pool;
struct dhcp_lease;

struct plugin {
	struct ctx *p_ctx;
	const char *p_name;
	const char *p_description;
	void *p_handle;
	void *p_pctx;
	int (*p_init)(struct plugin *);
	int (*p_init_proto)(struct plugin *);
	int (*p_unload)(struct plugin *);
	ssize_t (*p_configure_pools)(struct plugin *, struct interface *ifp);
	int (*p_lookup_addr)(struct plugin *, struct sockaddr *, const char *,
	    const struct bootp *, size_t);
	int (*p_lookup_hostname)(struct plugin *, char *, const struct bootp *,
	    size_t);
	int (*p_addr_to_hostname)(struct plugin *, const struct sockaddr *sa);
	int (*p_validate_addr)(struct plugin *, const struct sockaddr *sa);
	int (*p_test_addr)(struct plugin *, struct interface *ifp,
	    const struct sockaddr *dst, void *data, size_t datalen,
	    void (*release)(struct interface *, void *, size_t, uint32_t));
	int (*p_leased_addr)(struct plugin *, const struct sockaddr *addr,
	    const void *dhcpmsg, size_t dhcpmsglen);
	int (*p_add_dhcp_options)(struct plugin *, struct bootp *bootp,
	    uint8_t **p, const uint8_t *e, const struct dhcp_pool *pool,
	    const struct bootp *req, size_t reqlen);
	int (*p_commit_lease)(struct plugin *, const struct dhcp_lease *,
	    const struct bootp *, size_t, unsigned int *);
	int (*p_expire_lease)(struct plugin *, const struct dhcp_lease *);
	int (*p_store_leases)(struct plugin *);
	ssize_t (*p_dispatch)(struct plugin *, struct svc_ctx *, unsigned int,
	    const void *, size_t);
	int p_unpriv;
};

struct plugin *plugin_first(struct ctx *);
struct plugin *plugin_next(struct plugin *);

#define PLUGIN_FOREACH(ctx, plugin)                       \
	for ((plugin) = plugin_first((ctx));              \
	     (plugin) != NULL && (plugin)->p_ctx != NULL; \
	     plugin = plugin_next((plugin)))

int plugin_init(struct plugin *);
int plugin_load(struct ctx *, const char *);
int plugin_unload(struct plugin *);
int plugin_unloadall(struct ctx *);

#endif
