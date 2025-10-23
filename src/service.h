
/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - service helper
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

#ifndef SERVICE_H
#define SERVICE_H

#include <sys/uio.h>

#include "dhcpsd.h"

struct plugin;

struct svc_ctx {
	struct ctx *svc_ctx;
	int svc_fd;
	void *svc_buf;
	size_t svc_buflen;
	ssize_t (*svc_dispatch)(struct svc_ctx *, struct plugin *, unsigned int,
	    const void *, size_t);
};

struct svc_ctx *svc_init(struct ctx *, const char *,
    ssize_t (*dispatch)(struct svc_ctx *, struct plugin *, unsigned int,
	const void *, size_t));
void svc_free(struct svc_ctx *);
#define svc_dropperms dhcpsd_dropperms
ssize_t svc_send(struct svc_ctx *, struct plugin *, unsigned int, ssize_t,
    const void *, size_t);
ssize_t svc_sendv(struct svc_ctx *, struct plugin *, unsigned int, ssize_t,
    struct iovec *, int);
int svc_run(struct svc_ctx *, struct plugin *, unsigned int, const void *,
    size_t, ssize_t *, void **, size_t *);
int svc_runv(struct svc_ctx *, struct plugin *, unsigned int, struct iovec *,
    int, ssize_t *, void **, size_t *);

#endif
