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

#include <sys/socket.h>
#include <sys/time.h>

#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhcp.h"
#include "dhcpsd.h"
#include "logerr.h"
#include "plugin.h"

struct plugin *
plugin_next(struct plugin *p)
{
	for (p++; p->p_ctx != NULL; p++)
		if (p->p_handle != NULL)
			break;
	if (p->p_handle == NULL)
		return NULL;
	return p;
}

struct plugin *
plugin_first(struct ctx *ctx)
{
	struct plugin *p = ctx->ctx_plugins;

	if (p == NULL || p->p_ctx == NULL)
		return NULL;
	if (p->p_handle != NULL)
		return p;
	return plugin_next(p);
}

int
plugin_load(struct ctx *ctx, const char *name)
{
	void *h;
	int (*fptr)(struct plugin *);
	struct plugin *p;

	if (strchr(name, '/') != NULL) {
		h = dlopen(name, RTLD_LAZY);
	} else {
		char *path;

		if (asprintf(&path, PLUGINDIR "/%s.so", name) == -1)
			return -1;
		h = dlopen(path, RTLD_LAZY);
		free(path);
	}

	if (h == NULL) {
		logerrx("%s: dlopen %s: %s", __func__, name, dlerror());
		return -1;
	}
	fptr = dlsym(h, "plugin_init");
	if (fptr == NULL) {
		logerrx("%s: dlsym plugin_init: %s: %s", __func__, name,
		    dlerror());
		dlclose(h);
		return -1;
	}

	/* Keep a NULL plugin at the back for the FOREACH macro */
	p = realloc(ctx->ctx_plugins, sizeof(*p) * (ctx->ctx_nplugins + 2));
	if (p == NULL) {
		logerr("%s: realloc", __func__);
		dlclose(h);
		return -1;
	}
	ctx->ctx_plugins = p;
	p = ctx->ctx_plugins + (ctx->ctx_nplugins++);
	memset(p, 0, sizeof(*p) * 2);
	p->p_ctx = ctx;
	p->p_handle = h;

	if (fptr(p) == -1) {
		logerr("%s: plugin_init", __func__);
		dlclose(h);
		free(p);
		return -1;
	}

	loginfox("plugin loaded: %s: %s", p->p_name, p->p_description);
	return 0;
}

int
plugin_unload(struct plugin *p)
{
	int result = 0;

	if (!(p->p_ctx->ctx_options & DHCPSD_UNPRIV))
		logdebugx("unloading: %s", p->p_name);
	if (p->p_unload != NULL) {
		int r = p->p_unload(p);
		if (r != 0)
			result = r;
	}
	dlclose(p->p_handle);
	p->p_handle = NULL;
	return result;
}

int
plugin_unloadall(struct ctx *ctx)
{
	struct plugin *p;
	int result = 0, r;

	while ((p = plugin_first(ctx)) != NULL) {
		r = plugin_unload(p);
		if (r != 0)
			result = r;
	}
	free(ctx->ctx_plugins);
	return result;
}
