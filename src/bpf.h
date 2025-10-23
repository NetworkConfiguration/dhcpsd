/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dhcpcd: BPF bootp filtering
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

#ifndef BPF_HEADER
#define BPF_HEADER

struct bpf {
	const struct interface *bpf_if;
	int bpf_fd;
	unsigned int bpf_flags;
#define BPF_EOF		0x01U
#define BPF_PARTIALCSUM 0x02U
#define BPF_BCAST	0x04U
	void *bpf_buffer;
	size_t bpf_size;
	size_t bpf_len;
	size_t bpf_pos;
};

struct interface;
struct bpf *bpf_open(const struct interface *,
    int (*filter)(const struct bpf *), unsigned int);
ssize_t bpf_read(struct bpf *, void *, size_t);
void bpf_close(struct bpf *);

int bpf_bootp(const struct bpf *);
int bpf_icmp(const struct bpf *);

#endif
