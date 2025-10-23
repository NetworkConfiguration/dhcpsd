/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - DHCP server daemon
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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>

#include <errno.h>
#include <grp.h>
#include <ifaddrs.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "common.h"
#include "config.h"
#include "defs.h"
#include "dhcp.h"
#include "dhcpsd.h"
#include "eloop.h"
#include "if.h"
#include "logerr.h"
#include "plugin.h"
#include "queue.h"
#include "service.h"
#include "unpriv.h"

#ifdef HAVE_CASPER
#include <sys/capsicum.h>

#include <capsicum_helpers.h>
#include <casper/cap_net.h>
#include <libcasper.h>
#endif

#ifdef HAVE_SECCOMP
#include "seccomp.h"
#endif

const int signals[] = { SIGINT, SIGTERM };
const size_t signals_len = ARRAYCOUNT(signals);

static int
dhcpsd_store_leases(struct ctx *ctx)
{
	struct plugin *p;
	int result = 0;

	PLUGIN_FOREACH(ctx, p)
	{
		if (p->p_store_leases != NULL && p->p_store_leases(p) == -1)
			result = -1;
	}
	return result;
}

static void
dhcpsd_signal_cb(int sig, void *arg)
{
	struct ctx *ctx = arg;
	int exit_code = EXIT_FAILURE;

#define SIGMSG "received %s, %s"
	switch (sig) {
	case SIGINT:
		loginfox(SIGMSG, "SIGINT", "stopping");
		break;
	case SIGTERM:
		loginfox(SIGMSG, "SIGTERM", "stopping");
		exit_code = EXIT_SUCCESS;
		break;
	default:
		logerrx("received signal %d, no idea what to do", sig);
		return;
	}

	eloop_exit(ctx->ctx_eloop, exit_code);
}

int
dhcpsd_dropperms(int do_chroot)
{
	struct passwd *pw;

	pw = getpwnam(DHCPSD_USER);
	if (pw == NULL) {
		logerrx("%s: no such user %s", __func__, DHCPSD_USER);
		return -1;
	}

#if !defined(HAVE_CASPER) && !defined(HAVE_PLEDGE)
	if (do_chroot && chroot(pw->pw_dir) == -1) {
		logerr("%s: chroot: %s", __func__, pw->pw_dir);
		return -1;
	}
#else
	UNUSED(do_chroot);
#endif

	if (setgroups(1, &pw->pw_gid) == -1 || setgid(pw->pw_gid) == -1 ||
	    setuid(pw->pw_uid) == -1) {
		logerr("%s: error dropping privileges", __func__);
		return -1;
	}

	return 0;
}

static int
dhcpsd_mkdbdir(void)
{
	struct passwd *pw;

	pw = getpwnam(DHCPSD_USER);

	if (mkdir(DBDIR, 0770) == 0) {
		if (chown(DBDIR, pw->pw_uid, pw->pw_gid) == -1) {
			logerr("%s: chown: %s", __func__, DBDIR);
			return -1;
		}
	} else if (errno != EEXIST) {
		logerr("%s: mkdir: %s", __func__, DBDIR);
		return -1;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct if_head ifaces;
	struct ctx ctx = {
		.ctx_options = DHCPSD_MAIN,
		.ctx_ifaces = &ifaces,
		.ctx_pf_inet_fd = -1,
#ifdef IFLR_ACTIVE
		.ctx_pf_link_fd = -1,
#endif
	};
	int ch, exit_code = EXIT_FAILURE;
	size_t npools;
	struct interface *ifp;
	unsigned int logopts = LOGERR_LOG;
	struct plugin *p;
	struct rlimit rzero = { .rlim_cur = 0, .rlim_max = 0 };
#ifdef HAVE_CASPER
	cap_channel_t *capcas;
	cap_net_limit_t *limit;
#endif

	TAILQ_INIT(ctx.ctx_ifaces);
	closefrom(STDERR_FILENO + 1);

#define OPTS "dfp:"
	while ((ch = getopt(argc, argv, OPTS)) != -1) {
		switch (ch) {
		case 'd':
			logopts |= LOGERR_DEBUG;
			break;
		case 'f':
			logopts |= LOGERR_ERR;	// log to stderr
			logopts &= ~LOGERR_LOG; // don't syslog
			break;
		}
	}

	logsetopts(logopts);
	logopen(NULL);

	loginfox(PACKAGE "-" VERSION " starting");
	if (dhcpsd_mkdbdir() == -1)
		goto exit;

	ctx.ctx_eloop = eloop_new();
	if (ctx.ctx_eloop == NULL) {
		logerr("%s: eloop_new", __func__);
		goto exit;
	}
	eloop_signal_set_cb(ctx.ctx_eloop, signals, signals_len,
	    dhcpsd_signal_cb, &ctx);
	if (eloop_signal_mask(ctx.ctx_eloop) == -1) {
		logerr("%s: eloop_signal_mask", __func__);
		goto exit;
	}

	optind = 1;
	while ((ch = getopt(argc, argv, OPTS)) != -1) {
		switch (ch) {
		case 'p':
			if (plugin_load(&ctx, optarg) == -1)
				goto exit;
			if (ctx.ctx_options & DHCPSD_RUN)
				goto run;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (ctx.ctx_plugins == NULL) {
		loginfox("no plugins specified");
		if (plugin_load(&ctx, "auto") == -1)
			goto exit;
		if (plugin_load(&ctx, "leasefile") == -1)
			goto exit;
	} else {
		if (unpriv_init(&ctx) == NULL)
			goto exit;
	}

	PLUGIN_FOREACH(&ctx, p)
	{
		if (ctx.ctx_options & DHCPSD_UNPRIV && !p->p_unpriv) {
			plugin_unload(p);
			continue;
		}
		if (p->p_init != NULL) {
			ch = p->p_init(p);
			if (ch == -1)
				goto exit;
			if (ch != 0)
				goto run;
		}
	}

	if (ctx.ctx_options & DHCPSD_RUN)
		goto run;

	ctx.ctx_pf_inet_fd = xsocket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ctx.ctx_pf_inet_fd == -1) {
		logerr("%s: PF_INET", __func__);
		goto exit;
	}

#ifdef IFLR_ACTIVE
	ctx.ctx_pf_link_fd = xsocket(PF_LINK, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ctx.ctx_pf_link_fd == -1) {
		logerr("%s: PF_LINK", __func__);
		goto exit;
	}
#endif

	if (getifaddrs(&ctx.ctx_ifa) == -1) {
		logerr("%s: getifaddrs", __func__);
		goto exit;
	}

	if_learnifaces(&ctx);
	npools = 0;
	TAILQ_FOREACH(ifp, ctx.ctx_ifaces, if_next) {
		if (argc == 0)
			ifp->if_flags |= IF_ACTIVE;
		else {
			for (ch = 0; ch < argc; ch++) {
				if (strcmp(argv[ch], ifp->if_name) == 0) {
					ifp->if_flags |= IF_ACTIVE;
					argv[ch][0] = '\0';
					break;
				}
			}
		}
	}

	for (ch = 0; ch < argc; ch++) {
		if (argv[ch][0] != '\0') {
			logerrx("%s: no such interface", argv[ch]);
			goto exit;
		}
	}

	ctx.ctx_dhcp = dhcp_new(&ctx);
	if (ctx.ctx_dhcp == NULL)
		goto exit;

	PLUGIN_FOREACH(&ctx, p)
	{
		if (p->p_init_proto != NULL && p->p_init_proto(p) == -1)
			goto exit;
	}

	TAILQ_FOREACH(ifp, ctx.ctx_ifaces, if_next) {
		if (!(ifp->if_flags & IF_ACTIVE))
			continue;
		PLUGIN_FOREACH(&ctx, p)
		{
			if (p->p_configure_pools == NULL)
				continue;
			ssize_t n = p->p_configure_pools(p, ifp);
			if (n == -1 && argc != 0)
				goto exit;
			/* XXX When we grow DHCPv6 only open BPF if we configure
			 * a DHCPv4 pool. */
			if (n != 0 && dhcp_openbpf(ifp) == -1)
				goto exit;
			/* First plugin with config wins */
			if (n != 0) {
				npools += (size_t)n;
				break;
			}
		}
	}
	if (npools == 0) {
		logerrx("no pools, nothing to serve");
		goto exit;
	}

	/* May as well free this now */
	freeifaddrs(ctx.ctx_ifa);
	ctx.ctx_ifa = NULL;

	loginfox("dropping to user: %s", DHCPSD_USER);
	if (dhcpsd_dropperms(1) == -1)
		goto exit;

	/* If we separate -f from no syslog we need a new variable */
	if (logopts & LOGERR_LOG) {
		if (daemon(0, 0) == -1) {
			logerr("%s: daemon", __func__);
			goto exit;
		}
	}
#ifdef BSD
	setproctitle("DHCP Server Daemon");
#endif

#ifdef HAVE_CASPER
	logdebugx("enabling capsicum");

	caph_cache_catpages();

	capcas = cap_init();
	if (capcas == NULL) {
		logerr("%s: cap_init", __func__);
		goto exit;
	}

	if (caph_enter_casper() == -1) {
		logerr("%s: caph_enter_casper", __func__);
		goto exit;
	}

	ctx.ctx_capnet = cap_service_open(capcas, "system.net");
	if (ctx.ctx_capnet == NULL) {
		logerr("%s: cap_service_open: system.net", __func__);
		goto exit;
	}

	cap_close(capcas);

	limit = cap_net_limit_init(ctx.ctx_capnet,
	    CAPNET_CONNECT | CAPNET_NAME2ADDR);
	if (limit == NULL) {
		logerr("%s: cap_net_limit_init", __func__);
		goto exit;
	}
	if (cap_net_limit(limit) == -1) {
		logerr("%s: cap_net_limit", __func__);
		goto exit;
	}

	caph_limit_stdout();
	caph_limit_stderr();
#endif

/* Prohibit new files, sockets, etc */
/*
 * If poll(2) is called with nfds>RLIMIT_NOFILE then it returns EINVAL.
 * We don't know the final value of nfds at this point *easily*.
 * Sadly, this is a POSIX limitation and most platforms adhere to it.
 * However, some are not that strict and are whitelisted below.
 * Also, if we're not using poll then we can be restrictive.
 *
 * For the non whitelisted platforms there should be a sandbox to
 * fallback to where we don't allow new files, etc:
 *      Linux:seccomp, FreeBSD:capsicum, OpenBSD:pledge
 * Solaris users are sadly out of luck on both counts.
 */
#if defined(__DragonFly__) || defined(__NetBSD__)
	if (setrlimit(RLIMIT_NOFILE, &rzero) == -1)
		logerr("setrlimit RLIMIT_NOFILE");
#endif

/* Prohibit forks */
#ifdef RLIMIT_NPROC
	if (setrlimit(RLIMIT_NPROC, &rzero) == -1)
		logerr("setrlimit RLIMIT_NPROC");
#endif

#ifdef HAVE_PLEDGE
/*
 * stdio is just needed.
 * inet for sendto(2) to work with a non NULL to address.
 */
#define PLEDGE "stdio inet"
	logdebugx("pledge: " PLEDGE);
	if (pledge(PLEDGE, NULL) == -1) {
		logerr("%s: pledge", __func__);
		goto exit;
	}
#endif

#ifdef HAVE_SECCOMP
	logdebugx("enabling SECCOMP");
	if (seccomp_enter() == -1) {
		logerr("%s: seccomp_enter", __func__);
		goto exit;
	}
#endif

	dhcp_expire_leases(ctx.ctx_dhcp);

run:
	exit_code = eloop_start(ctx.ctx_eloop);
	if (exit_code < 0) {
		logerr("%s: eloop_start", __func__);
		exit_code = EXIT_FAILURE;
	} else
		exit_code = EXIT_SUCCESS;

	if (dhcpsd_store_leases(&ctx) == -1)
		exit_code = EXIT_FAILURE;

exit:
	plugin_unloadall(&ctx);
	if (ctx.ctx_ifa)
		freeifaddrs(ctx.ctx_ifa);
	while ((ifp = TAILQ_FIRST(ctx.ctx_ifaces)) != NULL) {
		TAILQ_REMOVE(ctx.ctx_ifaces, ifp, if_next);
		if_free(ifp);
	}
	dhcp_free(ctx.ctx_dhcp);
	eloop_free(ctx.ctx_eloop);
	svc_free(ctx.ctx_unpriv);
#ifdef HAVE_CASPER
	if (ctx.ctx_capnet)
		cap_close(ctx.ctx_capnet);
#endif
	if (ctx.ctx_options & DHCPSD_MAIN)
		logdebugx("dhcpsd exited");
	return exit_code;
}
