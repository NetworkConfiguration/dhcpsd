/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpsd: Ethernet output
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
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "dhcp.h"
#include "if.h"
#include "if_ether.h"

ssize_t
if_ether_output(const struct interface *ifp, int fd, const struct iovec *_iov,
    int iovcnt)
{
	struct ether_header eh = {};
	struct iovec iov[iovcnt + 1];
	struct ip *ip = _iov[0].iov_base;
	struct bootp *bootp = _iov[iovcnt - 1].iov_base;

	if (ifp->if_hwlen != sizeof(eh.ether_shost)) {
		errno = EINVAL;
		return -1;
	}
	memcpy(eh.ether_shost, ifp->if_hwaddr, ifp->if_hwlen);
	if (ip->ip_p != IPPROTO_UDP || ntohs(bootp->flags) & BROADCAST_FLAG)
		memset(eh.ether_dhost, 0xff, sizeof(eh.ether_dhost));
	else {
		if (bootp->hlen != sizeof(eh.ether_dhost)) {
			errno = ENOTSUP;
			return -1;
		}
		memcpy(eh.ether_dhost, bootp->chaddr, bootp->hlen);
	}
	eh.ether_type = htons(ETHERTYPE_IP);

	iov[0].iov_base = &eh;
	iov[0].iov_len = sizeof(eh);
	memcpy(iov + 1, _iov, sizeof(*iov) * (size_t)iovcnt);

	return writev(fd, iov, ++iovcnt);
}
