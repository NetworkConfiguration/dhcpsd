/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd - lua plugin to configure DHCP replies
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
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "dhcp.h"
#include "dhcpsd.h"
#include "if.h"
#include "logerr.h"
#include "plugin.h"
#include "service.h"

static const char lua_name[] = "lua";
static const char lua_description[] = "Configure the DHCP reply using lua";

#define LUA_CONFIG SYSCONFDIR "/dhcpsd/dhcp.lua"

struct lua_dhcp_opts {
	char ldo_sname[sizeof(((struct bootp *)0)->sname)];
	char ldo_file[sizeof(((struct bootp *)0)->file)];
	size_t ldo_optslen;
	uint8_t ldo_opts[1500];
};

struct lua_ctx {
	lua_State *L;
	const struct bootp *l_req;
	size_t l_reqlen;
	struct lua_dhcp_opts l_dhcp;
	uint8_t *l_p;
	uint8_t *l_e;
};

// XXX How to stash this in lua_State?
static struct lua_ctx lua_ctx;

#define L_LOOKUPHOSTNAME 1U
#define L_LOOKUPADDR	 2U
#define L_CONFIGUREPOOLS 3U
#define L_ADDDHCPOPTIONS 4U
#define L_COMMITLEASE	 5U
#define L_EXPIRELEASE	 6U

static ssize_t
lua_run_configure_pools(struct plugin *p, struct svc_ctx *sctx,
    const char *ifname, size_t ifnamelen)
{
	struct lua_ctx *l = p->p_pctx;
	lua_State *L = l->L;
	size_t npools = 0;
	ssize_t err = -1;
	struct dhcp_pool *pool, *pools = NULL;
	int laddress, lnetmask, lfrom, lto;
	uint8_t cidr;
	const char *saddress, *snetmask, *sfrom, *sto;
	in_addr_t address, netmask, from, to;
	bool first = true, array = true;

	if (ifnamelen == 0 || ifname[ifnamelen - 1] != '\0') {
		errno = EINVAL;
		goto out;
	}

	lua_pop(L, lua_gettop(L));

	lua_getglobal(L, "configure_pools");
	if (lua_isfunction(L, -1) != 1) {
		errno = ENOSYS;
		goto out;
	}

	lua_pushstring(L, ifname);
	if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
		logerrx("%s: configure_pools: %s", lua_name,
		    lua_tostring(L, lua_gettop(L)));
		errno = EINVAL;
		goto out;
	}

	if (lua_isnil(L, -1)) {
		err = 0;
		goto out;
	}

	if (!lua_istable(L, -1)) {
		logerrx("%s: configure_pools: value is not a table", lua_name);
		errno = EINVAL;
		goto out;
	}

	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		if (!lua_istable(L, -1)) {
			if (!first)
				break;
			array = false;
			lua_pop(L, 2);
		}
		first = false;

		laddress = lua_getfield(L, -1, "address");
		lnetmask = lua_getfield(L, -2, "netmask");
		lfrom = lua_getfield(L, -3, "from");
		lto = lua_getfield(L, -4, "to");
		if (laddress != LUA_TSTRING) {
			logerrx("%s: no address in pool", ifname);
			goto skip;
		}
		if (lnetmask != LUA_TSTRING) {
			logerrx("%s: no netmask in pool", ifname);
			goto skip;
		}
		if (lfrom != LUA_TSTRING) {
			logerrx("%s: no from in pool", ifname);
			goto skip;
		}
		if (lto != LUA_TSTRING) {
			logerrx("%s: no too in pool", ifname);
			goto skip;
		}
		saddress = lua_tostring(L, -4);
		snetmask = lua_tostring(L, -3);
		sfrom = lua_tostring(L, -2);
		sto = lua_tostring(L, -1);
		if (inet_pton(AF_INET, saddress, &address) != 1) {
			logerrx("%s: not an ip address %s", lua_name, saddress);
			goto skip;
		}
		if (inet_pton(AF_INET, snetmask, &netmask) != 1) {
			logerrx("%s: not a netmask %s", lua_name, snetmask);
			goto skip;
		}
		if (inet_pton(AF_INET, sfrom, &from) != 1) {
			logerrx("%s: not an ip address %s", lua_name, sfrom);
			goto skip;
		}
		if (inet_pton(AF_INET, sto, &to) != 1) {
			logerrx("%s: not an ip address %s", lua_name, sto);
			goto skip;
		}

		pool = reallocarray(pools, npools + 1, sizeof(*pool));
		if (pool == NULL) {
			logerr("%s: reallocarray", __func__);
			goto out;
		}
		pools = pool;
		pool += npools++;

		pool->dp_addr.s_addr = address;
		pool->dp_mask.s_addr = netmask;
		pool->dp_from.s_addr = from;
		pool->dp_to.s_addr = to;
		cidr = inet_ntocidr(&pool->dp_mask);

		loginfox("%s: %s: pool for %s/%d: %s - %s", ifname, lua_name,
		    saddress, cidr, sfrom, sto);
	skip:
		lua_pop(L, 4);

		lua_gettable(L, -1);
		lua_pop(L, 1);
		if (!array)
			break;
	}

	err = (ssize_t)npools;

out:
	err = svc_send(sctx, p, L_CONFIGUREPOOLS, err, pools,
	    sizeof(*pool) * npools);
	free(pools);
	return err;
}

static ssize_t
lua_run_lookup_hostname(struct plugin *p, struct svc_ctx *sctx,
    const void *data, size_t len)
{
	ssize_t err = -1;
	struct lua_ctx *l = p->p_pctx;
	lua_State *L = l->L;
	const char *hname = NULL;
	size_t hnamelen = 0;

	l->l_req = data;
	l->l_reqlen = len;
	char chaddr[l->l_req->hlen * 3];

	lua_pop(L, lua_gettop(L));

	lua_getglobal(L, "lookup_hostname");
	if (lua_isfunction(L, -1) != 1) {
		errno = ENOSYS;
		goto out;
	}

	lua_pushinteger(L, l->l_req->htype);
	hwaddr_ntoa(l->l_req->chaddr, l->l_req->hlen, chaddr, sizeof(chaddr));
	lua_pushstring(L, chaddr);
	if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
		logerrx("%s: lookup_hostname: %s", lua_name,
		    lua_tostring(L, lua_gettop(L)));
		errno = EINVAL;
		goto out;
	}

	if (!lua_isstring(L, -1)) {
		errno = ESRCH;
		goto out;
	}

	hname = lua_tostring(L, -1);
	hnamelen = strlen(hname) + 1;
	err = 0;

out:
	return svc_send(sctx, p, L_LOOKUPADDR, err, hname, hnamelen);
}

static ssize_t
lua_run_lookup_addr(struct plugin *p, struct svc_ctx *sctx, const void *data,
    size_t len)
{
	ssize_t err = -1;
	struct lua_ctx *l = p->p_pctx;
	lua_State *L = l->L;
	const char *addr;
	char hostname[DHCP_HOSTNAME_LEN];
	memcpy(hostname, data, sizeof(hostname));
	/* Aligns bootp */
	memmove(UNCONST(data), (const char *)data + sizeof(hostname),
	    len - sizeof(hostname));
	len -= sizeof(hostname);

	l->l_req = data;
	l->l_reqlen = len;
	char chaddr[l->l_req->hlen * 3];
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
#ifdef BSD
		.sin_len = sizeof(sin),
#endif
	};
	struct sockaddr *sa = (struct sockaddr *)&sin;
	size_t salen = 0;

	lua_pop(L, lua_gettop(L));

	lua_getglobal(L, "lookup_addr");
	if (lua_isfunction(L, -1) != 1) {
		errno = ENOSYS;
		goto out;
	}

	lua_pushstring(L, hostname);
	lua_pushinteger(L, l->l_req->htype);
	hwaddr_ntoa(l->l_req->chaddr, l->l_req->hlen, chaddr, sizeof(chaddr));
	lua_pushstring(L, chaddr);
	if (lua_pcall(L, 3, 1, 0) != LUA_OK) {
		logerrx("%s: lookup_addr: %s", lua_name,
		    lua_tostring(L, lua_gettop(L)));
		errno = EINVAL;
		goto out;
	}

	if (!lua_isstring(L, -1)) {
		errno = ESRCH;
		goto out;
	}

	addr = lua_tostring(L, -1);
	if (sa_pton(sa, addr) != 1) {
		logerrx("%s: addr is not parseable: %s", lua_name, addr);
		errno = EINVAL;
		goto out;
	}

	err = 0;
	salen = sizeof(sin);

out:
	return svc_send(sctx, p, L_LOOKUPADDR, err, sa, salen);
}

static int
lua_get_dhcp_option(lua_State *L)
{
	struct lua_ctx *l = &lua_ctx;
	long long optn = luaL_checkinteger(L, 1);
	const uint8_t *opt;

	if (optn < 1 || optn > 255) {
		logerrx("%s: option out of range: %lld", lua_name, optn);
		return 0;
	}

	if (l->l_req == NULL || l->l_reqlen == 0) {
		logerrx("%s: cannot get options", lua_name);
		return 0;
	}

	errno = 0;
	opt = dhcp_findoption(l->l_req, l->l_reqlen, (uint8_t)optn);
	if (opt == NULL)
		return 0;

	lua_pushlstring(L, (const char *)(opt + 1), opt[0]);
	return 1;
}

static int
lua_set_bootp_sname(lua_State *L)
{
	struct lua_ctx *l = &lua_ctx;
	const char *data = luaL_checkstring(L, 1);

	if (data == NULL)
		return 0;

	if (l->l_p == NULL || l->l_e == NULL) {
		logerrx("%s: cannot add options", lua_name);
		return 0;
	}

	if (strlen(data) > sizeof(l->l_dhcp.ldo_sname)) {
		logerrx("%s: bootp sname overflow: %s", lua_name, data);
		return 0;
	}

	strncpy(l->l_dhcp.ldo_sname, data, sizeof(l->l_dhcp.ldo_sname));
	return 0;
}

static int
lua_set_bootp_file(lua_State *L)
{
	struct lua_ctx *l = &lua_ctx;
	const char *data = luaL_checkstring(L, 1);

	if (data == NULL)
		return 0;

	if (l->l_p == NULL || l->l_e == NULL) {
		logerrx("%s: cannot add options", lua_name);
		return 0;
	}

	if (strlen(data) > sizeof(l->l_dhcp.ldo_file)) {
		logerrx("%s: bootp file overflow: %s", lua_name, data);
		return 0;
	}

	strncpy(l->l_dhcp.ldo_file, data, sizeof(l->l_dhcp.ldo_file));
	return 0;
}

static int
lua_add_dhcp_ip(lua_State *L)
{
	struct lua_ctx *l = &lua_ctx;
	long long optn = luaL_checkinteger(L, 1);
	const char *data = luaL_checkstring(L, 2);
	char *str, *tok, *next;
	in_addr_t ip;
	uint8_t *opt;

	if (optn < 1 || optn > 255) {
		logerrx("%s: option out of range: %lld", lua_name, optn);
		return 0;
	}

	if (l->l_p == NULL || l->l_e == NULL) {
		logerrx("%s: cannot add options", lua_name);
		return 0;
	}

	str = strdup(data);
	if (str == NULL)
		return 0;

	opt = l->l_p;
	tok = next = str;
	while (tok != NULL) {
		strsep(&next, ", ");
		if (*tok == '\0')
			goto next;
		if (inet_pton(AF_INET, tok, &ip) != 1) {
			logerrx("%s: not an ip address %s", lua_name, tok);
			goto next;
		}
		if (tok == str)
			DHCP_PUT_U32(&l->l_p, l->l_e, (uint8_t)optn, ip);
		else
			DHCP_EXTEND_U32(opt, &l->l_p, l->l_e, ip);
	next:
		tok = next;
	}

	free(str);
	return 0;
}

static int
lua_add_dhcp_string(lua_State *L)
{
	struct lua_ctx *l = &lua_ctx;
	long long optn = luaL_checkinteger(L, 1);
	const char *data = luaL_checkstring(L, 2);

	if (optn < 1 || optn > 255) {
		logerrx("%s: option out of range: %lld", lua_name, optn);
		return 0;
	}

	if (l->l_p == NULL || l->l_e == NULL) {
		logerrx("%s: cannot add options", lua_name);
		return 0;
	}

	DHCP_PUT_STR(&l->l_p, l->l_e, (uint8_t)optn, data);
	return 0;
}

static ssize_t
lua_run_add_dhcp_options(struct plugin *p, struct svc_ctx *sctx,
    const void *dhcp, size_t dhcplen)
{
	struct lua_ctx *l = p->p_pctx;
	lua_State *L = l->L;
	struct lua_dhcp_opts *ldo = &l->l_dhcp;
	const struct bootp *bootp = dhcp;
	char chaddr[bootp->hlen * 3];
	ssize_t err = -1;

	memset(ldo, 0, sizeof(*ldo));
	l->l_p = ldo->ldo_opts;
	l->l_e = l->l_p + sizeof(ldo->ldo_opts);
	l->l_req = dhcp;
	l->l_reqlen = dhcplen;

	lua_pop(L, lua_gettop(L));

	lua_getglobal(L, "add_dhcp_options");
	if (lua_isfunction(L, -1) != 1) {
		errno = ENOSYS;
		goto out;
	}

	lua_pushinteger(L, bootp->htype);
	hwaddr_ntoa(bootp->chaddr, bootp->hlen, chaddr, sizeof(chaddr));
	lua_pushstring(L, chaddr);
	if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
		logerrx("%s: add_dhcp_options: %s", lua_name,
		    lua_tostring(L, lua_gettop(L)));
		errno = EINVAL;
		goto out;
	}

	if (!lua_isinteger(L, -1))
		err = 0;
	else
		err = (ssize_t)lua_tointeger(L, -1);

	ldo->ldo_optslen = (size_t)(l->l_p - ldo->ldo_opts);

out:
	return svc_send(sctx, p, L_ADDDHCPOPTIONS, err, &l->l_dhcp,
	    offsetof(struct lua_dhcp_opts, ldo_optslen) +
		sizeof(l->l_dhcp.ldo_optslen) + l->l_dhcp.ldo_optslen);
}

static ssize_t
lua_run_expire_lease(struct plugin *p, struct svc_ctx *sctx,
    const void *payload, size_t payloadlen)
{
	const struct dhcp_lease *dl = payload;
	ssize_t err = -1;
	struct lua_ctx *l = p->p_pctx;
	lua_State *L = l->L;
	char clientid[sizeof(dl->dl_clientid) * 3];
	char ipbuf[INET_ADDRSTRLEN];
	const char *ip, *flags;

	if (payloadlen < sizeof(dl)) {
		errno = EINVAL;
		goto out;
	}

	l->l_p = NULL;
	l->l_e = NULL;
	l->l_req = NULL;
	l->l_reqlen = 0;

	lua_pop(L, lua_gettop(L));

	lua_getglobal(L, "expire_lease");
	if (lua_isfunction(L, -1) != 1) {
		errno = ENOSYS;
		goto out;
	}

	lua_pushstring(L, dl->dl_hostname);
	hwaddr_ntoa(dl->dl_clientid + 1, dl->dl_clientid[0], clientid,
	    sizeof(clientid));
	lua_pushstring(L, clientid);
	ip = inet_ntop(AF_INET, &dl->dl_addr, ipbuf, sizeof(ipbuf));
	lua_pushstring(L, ip);
	flags = dhcp_ftoa(dl->dl_flags);
	lua_pushstring(L, flags);

	if (lua_pcall(L, 4, 1, 0) != LUA_OK) {
		logerrx("%s: expire_lease: %s", lua_name,
		    lua_tostring(L, lua_gettop(L)));
		errno = EINVAL;
		goto out;
	}

	if (!lua_isinteger(L, -1))
		err = 0;
	else
		err = (ssize_t)lua_tointeger(L, -1);

out:
	return svc_send(sctx, p, L_EXPIRELEASE, err, NULL, 0);
}

static ssize_t
lua_run_commit_lease(struct plugin *p, struct svc_ctx *sctx,
    const void *payload, size_t payloadlen)
{
	struct dhcp_lease dl;
	const struct bootp *bootp;
	ssize_t err = -1;
	uint8_t *pl = UNCONST(payload);
	struct lua_ctx *l = p->p_pctx;
	lua_State *L = l->L;
	char chaddr[sizeof(bootp->chaddr) * 3];
	char clientid[sizeof(dl.dl_clientid) * 3];
	char ipbuf[INET_ADDRSTRLEN];
	const char *ip, *flags;
	int nresults;
	unsigned int f = 0;

	if (payloadlen < sizeof(dl) + sizeof(*bootp)) {
		errno = EINVAL;
		goto out;
	}

	/*
	 * Copy out the lease and move the rest and assign.
	 * As the underlying buffer is malloced, struct bootp is now aligned.
	 */
	memcpy(&dl, pl, sizeof(dl));
	memmove(pl, pl + sizeof(dl), payloadlen - sizeof(dl));
	bootp = payload;

	l->l_p = NULL;
	l->l_e = NULL;
	l->l_req = bootp;
	l->l_reqlen = payloadlen - sizeof(dl);

	lua_pop(L, lua_gettop(L));

	lua_getglobal(L, "commit_lease");
	if (lua_isfunction(L, -1) != 1) {
		errno = ENOSYS;
		goto out;
	}

	lua_pushstring(L, dl.dl_hostname);
	lua_pushinteger(L, bootp->htype);
	hwaddr_ntoa(bootp->chaddr, bootp->hlen, chaddr, sizeof(chaddr));
	lua_pushstring(L, chaddr);

	hwaddr_ntoa(dl.dl_clientid + 1, dl.dl_clientid[0], clientid,
	    sizeof(clientid));
	lua_pushstring(L, clientid);
	ip = inet_ntop(AF_INET, &dl.dl_addr, ipbuf, sizeof(ipbuf));
	lua_pushstring(L, ip);
	flags = dhcp_ftoa(dl.dl_flags);
	lua_pushstring(L, flags);

	lua_pushinteger(L, dl.dl_leased.tv_sec);
	lua_pushinteger(L, dl.dl_expires.tv_sec);

	if (lua_pcall(L, 8, 2, 0) != LUA_OK) {
		logerrx("%s: commit_lease: %s", lua_name,
		    lua_tostring(L, lua_gettop(L)));
		errno = EINVAL;
		goto out;
	}

	nresults = lua_gettop(L);
	/* LUA argumemt return argument order is revered? */
	if (nresults > 1) {
		flags = luaL_checkstring(L, -1);
		if (flags != NULL)
			f |= dhcp_atof(flags);
		lua_remove(L, -1);
	}

	if (nresults == 0 || !lua_isinteger(L, -1))
		err = 0;
	else
		err = (ssize_t)lua_tointeger(L, -1);

out:
	return svc_send(sctx, p, L_COMMITLEASE, err, &f, sizeof(f));
}

static int
lua_init(struct plugin *p)
{
	struct lua_ctx *l = p->p_pctx;
	lua_State *L;
	const struct luaL_Reg reg[] = {
		{ "set_bootp_sname", lua_set_bootp_sname },
		{ "set_bootp_file", lua_set_bootp_file },
		{ "get_option", lua_get_dhcp_option },
		{ "add_ip", lua_add_dhcp_ip },
		{ "add_string", lua_add_dhcp_string },
		{ NULL, NULL },
	};

	l->L = L = luaL_newstate();
	if (L == NULL) {
		logerr("%s: luaL_newstate", __func__);
		return -1;
	}
	luaL_openlibs(L);

	/* We want to sanitize the LUA script in the main process so we
	 * can give a visible error to the user and abort startup early */
	if (luaL_dofile(L, LUA_CONFIG) != LUA_OK) {
		if (!(p->p_ctx->ctx_options & DHCPSD_UNPRIV))
			logerrx("%s: %s", lua_name,
			    lua_tostring(l->L, lua_gettop(l->L)));
		return -1;
	}
	if (!(p->p_ctx->ctx_options & DHCPSD_UNPRIV)) {
		lua_close(L);
		l->L = NULL;
		return 0;
	}

	lua_newtable(L);
	luaL_setfuncs(L, reg, 0);
	lua_setglobal(L, "dhcp");

	loginfox("%s: loaded: %s", lua_name, LUA_CONFIG);

	lua_getglobal(L, "configure_pools");
	logdebugx("%s: function configure_pools %s", lua_name,
	    lua_isfunction(L, -1) == 1 ? "found" : "NOT found");
	lua_pop(L, 1);
	lua_getglobal(L, "lookup_hostname");
	logdebugx("%s: function lookup_hostname %s", lua_name,
	    lua_isfunction(L, -1) == 1 ? "found" : "NOT found");
	lua_pop(L, 1);
	lua_getglobal(L, "lookup_addr");
	logdebugx("%s: function lookup_addr %s", lua_name,
	    lua_isfunction(L, -1) == 1 ? "found" : "NOT found");
	lua_pop(L, 1);
	lua_getglobal(L, "add_dhcp_options");
	logdebugx("%s: function add_dhcp_options %s", lua_name,
	    lua_isfunction(L, -1) == 1 ? "found" : "NOT found");
	lua_pop(L, 1);
	lua_getglobal(L, "commit_lease");
	logdebugx("%s: function commit_lease %s", lua_name,
	    lua_isfunction(L, -1) == 1 ? "found" : "NOT found");
	lua_pop(L, 1);
	lua_getglobal(L, "expire_lease");
	logdebugx("%s: function expire_lease %s", lua_name,
	    lua_isfunction(L, -1) == 1 ? "found" : "NOT found");
	lua_pop(L, 1);

	return 0;
}

static int
lua_lookup_hostname(struct plugin *p, char *hostname, const struct bootp *bootp,
    size_t bootplen)
{
	ssize_t err, result;
	void *hname;
	size_t hnamelen;

	err = svc_run(p->p_ctx->ctx_unpriv, p, L_LOOKUPHOSTNAME, bootp,
	    bootplen, &result, &hname, &hnamelen);

	if (err == -1 || result == -1)
		return -1;
	if (hnamelen == 0)
		return 0;
	if (hnamelen > DHCP_HOSTNAME_LEN || ((char *)hname)[hnamelen] != '\0') {
		errno = EINVAL;
		return -1;
	}

	memcpy(hostname, hname, hnamelen);
	return (int)hnamelen - 1;
}

static int
lua_lookup_addr(struct plugin *p, struct sockaddr *sa, const char *hostname,
    const struct bootp *bootp, size_t bootplen)
{
	char hname[DHCP_HOSTNAME_LEN] = { '\0' };
	struct iovec iov[] = {
		{ .iov_base = hname, .iov_len = sizeof(hname) },
		{ .iov_base = UNCONST(bootp), .iov_len = bootplen },
	};
	ssize_t err, result;
	void *_sa;
	size_t salen;

	if (hostname != NULL)
		strlcpy(hname, hostname, sizeof(hname));
	err = svc_runv(p->p_ctx->ctx_unpriv, p, L_LOOKUPADDR, iov,
	    ARRAYCOUNT(iov), &result, &_sa, &salen);

	if (err == -1 || result == -1)
		return -1;
	memcpy(sa, _sa, salen);
	return 0;
}

static ssize_t
lua_configure_pools(struct plugin *p, struct interface *ifp)
{
	ssize_t err, result;
	void *_pools;
	size_t poolslen, npools;
	struct dhcp_pool *pool;

	err = svc_run(p->p_ctx->ctx_unpriv, p, L_CONFIGUREPOOLS, ifp->if_name,
	    strlen(ifp->if_name) + 1, &result, &_pools, &poolslen);
	if (err == -1 || result == -1)
		return -1;
	if (poolslen == 0)
		return 0;

	npools = poolslen / sizeof(*pool);
	pool = reallocarray(ifp->if_pools, ifp->if_npools + npools,
	    sizeof(*pool));
	if (pool == NULL)
		return -1;
	ifp->if_pools = pool;
	pool += ifp->if_npools;
	memcpy(pool, _pools, poolslen);
	ifp->if_npools += npools;
	return (ssize_t)npools;
}

static int
lua_add_dhcp_options(struct plugin *plug, struct bootp *bootp, uint8_t **p,
    const uint8_t *e, __unused const struct dhcp_pool *pool,
    const struct bootp *req, size_t reqlen)
{
	ssize_t err, result;
	void *opts;
	size_t optslen;
	struct lua_dhcp_opts *ldo;

	err = svc_run(plug->p_ctx->ctx_unpriv, plug, L_ADDDHCPOPTIONS, req,
	    reqlen, &result, &opts, &optslen);
	if (err == -1 || result == -1)
		return -1;
	if (optslen < offsetof(struct lua_dhcp_opts, ldo_opts)) {
		errno = EINVAL;
		return -1;
	}

	ldo = opts;
	memcpy(bootp->sname, ldo->ldo_sname, sizeof(bootp->sname));
	memcpy(bootp->file, ldo->ldo_file, sizeof(bootp->file));

	if (*p + ldo->ldo_optslen > e) {
		errno = ENOBUFS;
		return -1;
	}

	if (ldo->ldo_optslen != 0) {
		memcpy(*p, ldo->ldo_opts, ldo->ldo_optslen);
		*p = *p + ldo->ldo_optslen;
	}
	return (int)result;
}

static int
lua_commit_lease(struct plugin *p, const struct dhcp_lease *lease,
    const struct bootp *bootp, size_t bootplen, unsigned int *flags)
{
	struct iovec iov[] = {
		{
		    .iov_base = UNCONST(lease),
		    .iov_len = sizeof(*lease),
		},
		{ .iov_base = UNCONST(bootp), .iov_len = bootplen },
	};
	ssize_t err, result;
	unsigned int *f = NULL;
	size_t flen;

	err = svc_runv(p->p_ctx->ctx_unpriv, p, L_COMMITLEASE, iov,
	    ARRAYCOUNT(iov), &result, (void *)&f, &flen);
	if (err == -1)
		return -1;
	if (flen == sizeof(*f) && f != NULL && flags != NULL)
		*flags = *f;
	return (int)result;
}

static int
lua_expire_lease(struct plugin *p, const struct dhcp_lease *lease)
{
	ssize_t err, result;

	err = svc_run(p->p_ctx->ctx_unpriv, p, L_EXPIRELEASE, lease,
	    sizeof(*lease), &result, NULL, NULL);
	if (err == -1)
		return -1;
	return (int)result;
}

static ssize_t
lua_dispatch(struct plugin *p, struct svc_ctx *sctx, unsigned int cmd,
    const void *data, size_t len)
{
	switch (cmd) {
	case L_LOOKUPHOSTNAME:
		return lua_run_lookup_hostname(p, sctx, data, len);
	case L_LOOKUPADDR:
		return lua_run_lookup_addr(p, sctx, data, len);
	case L_CONFIGUREPOOLS:
		return lua_run_configure_pools(p, sctx, data, len);
	case L_ADDDHCPOPTIONS:
		return lua_run_add_dhcp_options(p, sctx, data, len);
	case L_COMMITLEASE:
		return lua_run_commit_lease(p, sctx, data, len);
	case L_EXPIRELEASE:
		return lua_run_expire_lease(p, sctx, data, len);
	default:
		errno = ENOTSUP;
		return -1;
	}
}

static int
lua_unload(struct plugin *p)
{
	struct lua_ctx *l = p->p_pctx;

	if (l->L != NULL)
		lua_close(l->L);
#if 0
	free(l);
#endif
	return 0;
}

int
plugin_init(struct plugin *p)
{
#if 0
	struct lua_ctx *l;

	l = calloc(1, sizeof(*l));
	if (l == NULL)
		return -1;
#endif

	p->p_name = lua_name;
	p->p_description = lua_description;
	p->p_pctx = &lua_ctx;
	p->p_init = lua_init;
	p->p_unload = lua_unload;
	p->p_configure_pools = lua_configure_pools;
	p->p_lookup_hostname = lua_lookup_hostname;
	p->p_lookup_addr = lua_lookup_addr;
	p->p_add_dhcp_options = lua_add_dhcp_options;
	p->p_dispatch = lua_dispatch;
	p->p_commit_lease = lua_commit_lease;
	p->p_expire_lease = lua_expire_lease;
	p->p_unpriv = 1;
	return 0;
}
