/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - persistent storage for leases in a file
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

#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "dhcp.h"
#include "dhcp_lease.h"
#include "dhcpsd.h"
#include "eloop.h"
#include "logerr.h"
#include "plugin.h"

#ifdef HAVE_CASPER
#include <sys/capsicum.h>

#include <capsicum_helpers.h>
#endif

static const char lf_name[] = "leasefile";
static const char lf_description[] = "Persistent lease file storage";

struct leasefile_ctx {
	FILE *lf_file;
	bool lf_dirty;
};

#ifndef LEASEFILE
#define LEASEFILE "/var/db/dhcpsd/dhcp.leases"
#endif
#define WRITETIME   30 /* delay updating lease file */

#define ISO8061_FMT "%Y-%m-%dT%H:%M:%SZ"
#define ISO8061_LEN 31

#define LF_HEADER   "# dhcpsd leasefile v1"
#define LF_DESC	    "# Fields are separated by one tab"
#define LF_CHEADER \
	"# address\tleased\t\t\texpires\t\t\tflags\tclientid\t\thostname"
#define LF_FOOTER "# EOF"

static int
lf_write_lease(void *arg, struct dhcp_lease *lease)
{
	struct plugin *p = arg;
	struct leasefile_ctx *lf = p->p_pctx;
	struct tm leased, expires;
	char sleased[ISO8061_LEN], sexpires[ISO8061_LEN];
	char clientidbuf[lease->dl_clientid[0] * 3];
	const char *clientid, *flags;

	gmtime_r(&lease->dl_leased.tv_sec, &leased);
	if (strftime(sleased, sizeof(sleased), ISO8061_FMT, &leased) == 0)
		return -1;
	gmtime_r(&lease->dl_expires.tv_sec, &expires);
	if (strftime(sexpires, sizeof(sexpires), ISO8061_FMT, &expires) == 0)
		return -1;

	clientid = hwaddr_ntoa(lease->dl_clientid + 1, lease->dl_clientid[0],
	    clientidbuf, sizeof(clientidbuf));
	flags = dhcp_ftoa(lease->dl_flags);

	/* clientid and hostname at the end as they are variable length */
	return fprintf(lf->lf_file, "%s\t%s\t%s\t%s\t%s\t%s\n",
	    inet_ntoa(lease->dl_addr), sleased, sexpires, flags,
	    clientid ? clientid : "", lease->dl_hostname);
}

static int
lf_store_leases(struct plugin *p)
{
	struct ctx *ctx = p->p_ctx;
	struct leasefile_ctx *lf = p->p_pctx;
	struct dhcp_ctx *dhcp_ctx = ctx->ctx_dhcp;

	if (!lf->lf_dirty)
		return 0;

	logdebugx("%s: writing %s", lf_name, LEASEFILE);

	if (fflush(lf->lf_file) != 0 ||
	    fseek(lf->lf_file, 0L, SEEK_SET) == -1 ||
	    ftruncate(fileno(lf->lf_file), 0) == -1) {
		logerr("%s: truncating %s", lf_name, LEASEFILE);
		return -1;
	}

	if (fprintf(lf->lf_file, LF_HEADER "\n" LF_DESC "\n" LF_CHEADER "\n") ==
	    -1) {
		logerr("%s: fprintf", lf_name);
		return -1;
	}

	if (dhcp_lease_foreachaddr(dhcp_ctx, lf_write_lease, p) == -1) {
		logerr("%s: dhcp_lease_foreach", lf_name);
		return -1;
	}

	if (fprintf(lf->lf_file, LF_FOOTER "\n") == -1) {
		logerr("%s: fprintf", lf_name);
		return -1;
	}

	if (fflush(lf->lf_file) == -1) {
		logerr("%s: fflush", lf_name);
		return -1;
	}

	lf->lf_dirty = false;
	return 0;
}

static void
lf_store_tick(void *arg)
{
	struct plugin *p = arg;

	lf_store_leases(p);
	eloop_timeout_delete(p->p_ctx->ctx_eloop, lf_store_tick, p);
}

static int
lf_try_tick(struct plugin *p)
{
	struct leasefile_ctx *lf = p->p_pctx;
	/* We do want to tick eventually ... */
	if (lf->lf_dirty)
		return 0;

	lf->lf_dirty = true;
	return eloop_timeout_add_sec(p->p_ctx->ctx_eloop, WRITETIME,
	    lf_store_tick, p);
}

static int
lf_commit_lease(struct plugin *p, __unused const struct dhcp_lease *lease,
    __unused const struct bootp *bootp, __unused size_t bootplen,
    __unused unsigned int *flags)
{
	return lf_try_tick(p);
}

static int
lf_expire_lease(struct plugin *p, __unused const struct dhcp_lease *lease)
{
	return lf_try_tick(p);
}

static int
lf_init_proto(struct plugin *p)
{
	struct ctx *ctx = p->p_ctx;
	struct leasefile_ctx *lf = p->p_pctx;
	char *line = NULL, *l;
	const char *saddr, *sclientid, *sleased, *sexpires, *shostname, *flags;
	size_t size = 0;
	ssize_t nread;
	struct dhcp_lease *lease, *found;
	bool match_header = true;
	uint8_t clientid[DHCP_CLIENTID_LEN + 1];
	struct in_addr addr;
	struct tm leased, expires;
#ifdef HAVE_CASPER
	cap_rights_t rights;
#endif

	lf->lf_file = fopen(LEASEFILE, "r+");
	if (lf->lf_file == NULL && errno == ENOENT)
		lf->lf_file = fopen(LEASEFILE, "w+");
	if (lf->lf_file == NULL) {
		logerr("%s: fopen", lf_name);
		return -1;
	}

#ifdef HAVE_CASPER
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_FTRUNCATE);
	if (caph_rights_limit(fileno(lf->lf_file), &rights) == -1) {
		logerr("%s: cap_limit_rights", __func__);
		return -1;
	}
#endif

	loginfox("%s: using %s", lf_name, LEASEFILE);

	while ((nread = getline(&line, &size, lf->lf_file)) != -1) {
		line[nread - 1] = '\0';
		if (match_header) {
			if (strcmp(line, LF_HEADER) != 0) {
				logwarnx("%s: invalid header: %s", lf_name,
				    line);
				break;
			}
			match_header = false;
			continue;
		}
		if (line[0] == '#')
			continue;

		l = line;
		saddr = strsep(&l, "\t");
		sleased = strsep(&l, "\t");
		sexpires = strsep(&l, "\t");
		flags = strsep(&l, "\t");
		sclientid = strsep(&l, "\t");
		shostname = strsep(&l, "\t");

		if (hwaddr_aton(NULL, sclientid) > UINT_MAX) {
			errno = ENOBUFS;
			logerr("%s: hwaddr_aton: %s", __func__, sclientid);
			continue;
		}
		clientid[0] = (uint8_t)hwaddr_aton(clientid + 1, sclientid);

		if (inet_aton(saddr, &addr) == 0) {
			logerr("%s: inet_aton: %s", __func__, saddr);
			continue;
		}

		if (strptime(sleased, ISO8061_FMT, &leased) == NULL) {
			logerr("%s: strptime: %s", __func__, sleased);
			continue;
		}
		if (strptime(sexpires, ISO8061_FMT, &expires) == NULL) {
			logerr("%s: strptime: %s", __func__, sexpires);
			continue;
		}

		lease = dhcp_alloclease();
		if (lease == NULL) {
			logerr("%s: dhcp_alloclease", __func__);
			continue;
		}

		lease->dl_addr = addr;
		lease->dl_leased.tv_sec = timegm(&leased);
		lease->dl_expires.tv_sec = timegm(&expires);
		lease->dl_flags = dhcp_atof(flags);

		lease->dl_clientid[0] = clientid[0];
		if (clientid[0])
			memcpy(lease->dl_clientid + 1, clientid + 1,
			    clientid[0]);

		memset(lease->dl_hostname, '\0', sizeof(lease->dl_hostname));
		if (shostname != NULL)
			strlcpy(lease->dl_hostname, shostname,
			    sizeof(lease->dl_hostname));

		logdebugx("%s: loaded %s %s %s %s %s", lf_name, saddr, sexpires,
		    flags, sclientid ? sclientid : "", lease->dl_hostname);

		found = dhcp_lease_findaddr(ctx->ctx_dhcp, &lease->dl_addr);
		if (found != NULL && found != lease) {
			if (timespeccmp(&found->dl_leased, &lease->dl_leased,
				>)) {
				logwarnx(
				    "%s: discarding in favour of %s for %s",
				    lf_name, inet_ntoa(lease->dl_addr),
				    sclientid);
				free(lease);
				continue;
			}
			logwarnx(
			    "%s: discarding %s in favour of this one for %s",
			    lf_name, inet_ntoa(found->dl_addr), sclientid);
			dhcp_lease_eraseaddr(ctx->ctx_dhcp, &found->dl_addr);
			if (!(found->dl_flags & DL_ADDRESS))
				free(found);
		}

		if (dhcp_lease_insertaddr(ctx->ctx_dhcp, lease) == -1) {
			logerr("%s: dhcp_lease_insertaddr", __func__);
			free(lease);
			continue;
		}

		found = dhcp_lease_find(ctx->ctx_dhcp, lease->dl_clientid);
		if (found != NULL) {
			/* If we find a newer clientid, just continue. */
			if (timespeccmp(&found->dl_leased, &lease->dl_leased,
				>))
				continue;
			/* Found an older clientid, unlink it. */
			dhcp_lease_erase(ctx->ctx_dhcp, found);
			if (!(found->dl_flags & DL_ADDRESS))
				free(found);
		}

		if (!(lease->dl_flags & DL_ADDRESS)) {
			found = dhcp_alloclease();
			memcpy(found, lease, sizeof(*found));
			lease = found;
		}
		if (dhcp_lease_insert(ctx->ctx_dhcp, lease) == -1) {
			logerr("%s: dhcp_lease_insertaddr", __func__);
			if (lease->dl_flags & DL_ADDRESS)
				dhcp_lease_eraseaddr(ctx->ctx_dhcp,
				    &lease->dl_addr);
			free(lease);
			continue;
		}
	}
	free(line);

	return 0;
}

static int
lf_unload(struct plugin *p)
{
	struct leasefile_ctx *lf = p->p_pctx;

	if (lf->lf_file != NULL)
		(void)fclose(lf->lf_file);
	free(lf);
	return 0;
}

int
plugin_init(struct plugin *p)
{
	struct leasefile_ctx *lf = calloc(1, sizeof(*lf));

	if (lf == NULL)
		return -1;

	p->p_name = lf_name;
	p->p_description = lf_description;
	p->p_pctx = lf;
	p->p_init_proto = lf_init_proto;
	p->p_unload = lf_unload;
	p->p_commit_lease = lf_commit_lease;
	p->p_expire_lease = lf_expire_lease;
	p->p_store_leases = lf_store_leases;
	return 0;
}
