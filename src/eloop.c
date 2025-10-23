/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * eloop - portable event based main loop.
 * Copyright (c) 2006-2025 Roy Marples <roy@marples.name>
 * All rights reserved.

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

/* This eloop implementation just uses ppoll as we only support modern stuff. */
#include <sys/param.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "eloop.h"
#include "queue.h"

/*
 * Allow a backlog of signals.
 * If you use many eloops in the same process, they should all
 * use the same signal handler or have the signal handler unset.
 * Otherwise the signal might not behave as expected.
 */
#define ELOOP_NSIGNALS 5

/*
 * time_t is a signed integer of an unspecified size.
 * To adjust for time_t wrapping, we need to work the maximum signed
 * value and use that as a maximum.
 */
#ifndef TIME_MAX
#define TIME_MAX ((1ULL << (sizeof(time_t) * NBBY - 1)) - 1)
#endif
/* The unsigned maximum is then simple - multiply by two and add one. */
#ifndef UTIME_MAX
#define UTIME_MAX (TIME_MAX * 2) + 1
#endif

struct eloop_event {
	TAILQ_ENTRY(eloop_event) next;
	int fd;
	void (*cb)(void *, unsigned short);
	void *cb_arg;
	unsigned short events;
	struct pollfd *pollfd;
};

struct eloop_timeout {
	TAILQ_ENTRY(eloop_timeout) next;
	unsigned int seconds;
	unsigned int nseconds;
	void (*callback)(void *);
	void *arg;
	int queue;
};

struct eloop {
	TAILQ_HEAD(event_head, eloop_event) events;
	nfds_t nevents;
	struct event_head free_events;

	struct timespec now;
	TAILQ_HEAD(timeout_head, eloop_timeout) timeouts;
	struct timeout_head free_timeouts;

	const int *signals;
	size_t nsignals;
	sigset_t sigset;
	void (*signal_cb)(int, void *);
	void *signal_cb_ctx;

	struct pollfd *fds;
	nfds_t nfds;

	struct eloop_event *one_event;
	int exitcode;
	bool exitnow;
	bool endwait;
	bool events_need_setup;
};

#ifdef HAVE_REALLOCARRAY
#define eloop_realloca reallocarray
#else
/* Handy routing to check for potential overflow.
 * reallocarray(3) and reallocarr(3) are not portable. */
#define SQRT_SIZE_MAX (((size_t)1) << (sizeof(size_t) * CHAR_BIT / 2))
static void *
eloop_realloca(void *ptr, size_t n, size_t size)
{
	if ((n | size) >= SQRT_SIZE_MAX && n > SIZE_MAX / size) {
		errno = EOVERFLOW;
		return NULL;
	}
	return realloc(ptr, n * size);
}
#endif

static int
eloop_event_setup_fds(struct eloop *eloop)
{
	struct eloop_event *e, *ne;
	struct pollfd *pfd;

	if (eloop->nfds < eloop->nevents) {
		pfd = eloop_realloca(eloop->fds, eloop->nevents, sizeof(*pfd));
		if (pfd == NULL)
			return -1;
		eloop->fds = pfd;
		eloop->nfds = eloop->nevents;
	}

	pfd = eloop->fds;
	TAILQ_FOREACH_SAFE(e, &eloop->events, next, ne) {
		if (e->fd == -1) {
			TAILQ_REMOVE(&eloop->events, e, next);
			TAILQ_INSERT_TAIL(&eloop->free_events, e, next);
			continue;
		}
		e->pollfd = pfd;
		pfd->fd = e->fd;
		pfd->events = 0;
		if (e->events & ELE_READ)
			pfd->events |= POLLIN;
		if (e->events & ELE_WRITE)
			pfd->events |= POLLOUT;
		pfd->revents = 0;
		pfd++;
	}

	eloop->events_need_setup = false;
	return 0;
}

size_t
eloop_event_count(const struct eloop *eloop)
{
	return eloop->nevents;
}

int
eloop_event_add(struct eloop *eloop, int fd, unsigned short events,
    void (*cb)(void *, unsigned short), void *cb_arg)
{
	struct eloop_event *e;

	if (fd == -1 || !(events & (ELE_READ | ELE_WRITE | ELE_HANGUP))) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_FOREACH(e, &eloop->events, next) {
		if (e->fd == fd)
			break;
	}

	if (e == NULL) {
		e = TAILQ_FIRST(&eloop->free_events);
		if (e != NULL)
			TAILQ_REMOVE(&eloop->free_events, e, next);
		else {
			e = malloc(sizeof(*e));
			if (e == NULL) {
				return -1;
			}
		}
		TAILQ_INSERT_HEAD(&eloop->events, e, next);
		eloop->nevents++;
		e->fd = fd;
		e->events = 0;
	}

	e->cb = cb;
	e->cb_arg = cb_arg;

	e->pollfd = NULL;
	e->events = events;
	eloop->events_need_setup = true;
	return 0;
}

int
eloop_event_delete(struct eloop *eloop, int fd)
{
	struct eloop_event *e;

	if (fd == -1) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_FOREACH(e, &eloop->events, next) {
		if (e->fd == fd)
			break;
	}
	if (e == NULL) {
		errno = ENOENT;
		return -1;
	}

	e->fd = -1;
	eloop->nevents--;
	eloop->events_need_setup = true;
	return 1;
}

unsigned long long
eloop_timespec_diff(const struct timespec *tsp, const struct timespec *usp,
    unsigned int *nsp)
{
	unsigned long long tsecs, usecs, secs;
	long nsecs;

	if (tsp->tv_sec < 0) /* time wrapped */
		tsecs = UTIME_MAX - (unsigned long long)(-tsp->tv_sec);
	else
		tsecs = (unsigned long long)tsp->tv_sec;
	if (usp->tv_sec < 0) /* time wrapped */
		usecs = UTIME_MAX - (unsigned long long)(-usp->tv_sec);
	else
		usecs = (unsigned long long)usp->tv_sec;

	if (usecs > tsecs) /* time wrapped */
		secs = (UTIME_MAX - usecs) + tsecs;
	else
		secs = tsecs - usecs;

	nsecs = tsp->tv_nsec - usp->tv_nsec;
	if (nsecs < 0) {
		if (secs == 0)
			nsecs = 0;
		else {
			secs--;
			nsecs += NSEC_PER_SEC;
		}
	}
	if (nsp != NULL)
		*nsp = (unsigned int)nsecs;
	return secs;
}

static void
eloop_reduce_timers(struct eloop *eloop)
{
	struct timespec now;
	unsigned long long secs;
	unsigned int nsecs;
	struct eloop_timeout *t;

	clock_gettime(CLOCK_MONOTONIC, &now);
	secs = eloop_timespec_diff(&now, &eloop->now, &nsecs);

	TAILQ_FOREACH(t, &eloop->timeouts, next) {
		if (secs > t->seconds) {
			t->seconds = 0;
			t->nseconds = 0;
		} else {
			t->seconds -= (unsigned int)secs;
			if (nsecs > t->nseconds) {
				if (t->seconds == 0)
					t->nseconds = 0;
				else {
					t->seconds--;
					t->nseconds = NSEC_PER_SEC -
					    (nsecs - t->nseconds);
				}
			} else
				t->nseconds -= nsecs;
		}
	}

	eloop->now = now;
}

/*
 * This implementation should cope with UINT_MAX seconds on a system
 * where time_t is INT32_MAX. It should also cope with the monotonic timer
 * wrapping, although this is highly unlikely.
 * unsigned int should match or be greater than any on wire specified timeout.
 */
static int
eloop_q_timeout_add(struct eloop *eloop, int queue, unsigned int seconds,
    unsigned int nseconds, void (*callback)(void *), void *arg)
{
	struct eloop_timeout *t, *tt = NULL;

	/* Remove existing timeout if present. */
	TAILQ_FOREACH(t, &eloop->timeouts, next) {
		if (t->callback == callback && t->arg == arg) {
			TAILQ_REMOVE(&eloop->timeouts, t, next);
			break;
		}
	}

	if (t == NULL) {
		/* No existing, so allocate or grab one from the free pool. */
		if ((t = TAILQ_FIRST(&eloop->free_timeouts))) {
			TAILQ_REMOVE(&eloop->free_timeouts, t, next);
		} else {
			if ((t = malloc(sizeof(*t))) == NULL)
				return -1;
		}
	}

	eloop_reduce_timers(eloop);

	t->seconds = seconds;
	t->nseconds = nseconds;
	t->callback = callback;
	t->arg = arg;
	t->queue = queue;

	/* The timeout list should be in chronological order,
	 * soonest first. */
	TAILQ_FOREACH(tt, &eloop->timeouts, next) {
		if (t->seconds < tt->seconds ||
		    (t->seconds == tt->seconds && t->nseconds < tt->nseconds)) {
			TAILQ_INSERT_BEFORE(tt, t, next);
			return 0;
		}
	}
	TAILQ_INSERT_TAIL(&eloop->timeouts, t, next);
	return 0;
}

int
eloop_q_timeout_add_tv(struct eloop *eloop, int queue,
    const struct timespec *when, void (*callback)(void *), void *arg)
{
	if (when->tv_sec < 0 || (unsigned long)when->tv_sec > UINT_MAX) {
		errno = EINVAL;
		return -1;
	}
	if (when->tv_nsec < 0 || when->tv_nsec > NSEC_PER_SEC) {
		errno = EINVAL;
		return -1;
	}

	return eloop_q_timeout_add(eloop, queue, (unsigned int)when->tv_sec,
	    (unsigned int)when->tv_sec, callback, arg);
}

int
eloop_q_timeout_add_sec(struct eloop *eloop, int queue, unsigned int seconds,
    void (*callback)(void *), void *arg)
{
	return eloop_q_timeout_add(eloop, queue, seconds, 0, callback, arg);
}

int
eloop_q_timeout_add_msec(struct eloop *eloop, int queue, unsigned long when,
    void (*callback)(void *), void *arg)
{
	unsigned long seconds, nseconds;

	seconds = when / MSEC_PER_SEC;
	if (seconds > UINT_MAX) {
		errno = EINVAL;
		return -1;
	}

	nseconds = (when % MSEC_PER_SEC) * NSEC_PER_MSEC;
	return eloop_q_timeout_add(eloop, queue, (unsigned int)seconds,
	    (unsigned int)nseconds, callback, arg);
}

int
eloop_q_timeout_delete(struct eloop *eloop, int queue, void (*callback)(void *),
    void *arg)
{
	struct eloop_timeout *t, *tt;
	int n;

	n = 0;
	TAILQ_FOREACH_SAFE(t, &eloop->timeouts, next, tt) {
		if ((queue == 0 || t->queue == queue) && t->arg == arg &&
		    (!callback || t->callback == callback)) {
			TAILQ_REMOVE(&eloop->timeouts, t, next);
			TAILQ_INSERT_TAIL(&eloop->free_timeouts, t, next);
			n++;
		}
	}
	return n;
}

void
eloop_exit(struct eloop *eloop, int code)
{
	eloop->exitcode = code;
	eloop->exitnow = true;
}

void
eloop_endwait(struct eloop *eloop, int code)
{
	eloop->exitcode = code;
	eloop->endwait = true;
}

void
eloop_enter(struct eloop *eloop)
{
	eloop->exitnow = false;
}

int
eloop_signal_set_cb(struct eloop *eloop, const int *signals, size_t nsignals,
    void (*signal_cb)(int, void *), void *signal_cb_ctx)
{
	int error = 0;

	eloop->signals = signals;
	eloop->nsignals = nsignals;
	eloop->signal_cb = signal_cb;
	eloop->signal_cb_ctx = signal_cb_ctx;

	return error;
}

static volatile int eloop_sig[ELOOP_NSIGNALS];
static volatile size_t eloop_nsig;

static void
eloop_signal3(int sig, siginfo_t *siginfo, void *arg)
{
	(void)(siginfo);
	(void)(arg);

	if (eloop_nsig == sizeof(eloop_sig) / sizeof(eloop_sig[0])) {
#ifdef ELOOP_DEBUG
		fprintf(stderr, "%s: signal storm, discarding signal %d\n",
		    __func__, sig);
#endif
		return;
	}
	eloop_sig[eloop_nsig++] = sig;
}

int
eloop_signal_mask(struct eloop *eloop)
{
	sigset_t newset;
	size_t i;
	struct sigaction sa = {
		.sa_sigaction = eloop_signal3,
		.sa_flags = SA_SIGINFO,
	};

	sigemptyset(&newset);
	for (i = 0; i < eloop->nsignals; i++)
		sigaddset(&newset, eloop->signals[i]);
	if (sigprocmask(SIG_SETMASK, &newset, &eloop->sigset) == -1)
		return -1;

	sigemptyset(&sa.sa_mask);

	for (i = 0; i < eloop->nsignals; i++) {
		if (sigaction(eloop->signals[i], &sa, NULL) == -1)
			return -1;
	}

	return 0;
}

struct eloop *
eloop_new(void)
{
	struct eloop *eloop;

	eloop = calloc(1, sizeof(*eloop));
	if (eloop == NULL)
		return NULL;

	/* Check we have a working monotonic clock. */
	if (clock_gettime(CLOCK_MONOTONIC, &eloop->now) == -1) {
		free(eloop);
		return NULL;
	}

	TAILQ_INIT(&eloop->events);
	TAILQ_INIT(&eloop->free_events);
	TAILQ_INIT(&eloop->timeouts);
	TAILQ_INIT(&eloop->free_timeouts);
	eloop->exitcode = EXIT_FAILURE;

	return eloop;
}

void
eloop_free(struct eloop *eloop)
{
	struct eloop_event *e, *en;
	struct eloop_timeout *t, *tn;

	if (eloop == NULL)
		return;

	TAILQ_FOREACH_SAFE(e, &eloop->events, next, en) {
		if (e->fd != -1)
			close(e->fd);
		free(e);
	}

	free(eloop->fds);

	TAILQ_FOREACH_SAFE(e, &eloop->free_events, next, en)
		free(e);

	TAILQ_FOREACH_SAFE(t, &eloop->timeouts, next, tn)
		free(t);

	TAILQ_FOREACH_SAFE(t, &eloop->free_timeouts, next, tn)
		free(t);

	free(eloop);
}

static int
eloop_run_ppoll(struct eloop *eloop, const struct timespec *ts)
{
	int n, nn;
	struct eloop_event *e;
	struct pollfd *pfd;
	unsigned short events;

	if (eloop->one_event != NULL)
		n = ppoll(eloop->one_event->pollfd, 1, ts, &eloop->sigset);
	else
		n = ppoll(eloop->fds, eloop->nevents, ts, &eloop->sigset);
	if (n == -1 || n == 0)
		return n;

	nn = n;
	if (eloop->one_event != NULL) {
		e = eloop->one_event;
		goto one;
	}

	TAILQ_FOREACH(e, &eloop->events, next) {
	one:
		if (eloop->exitnow)
			break;
		/* Skip freshly added events */
		if ((pfd = e->pollfd) == NULL)
			continue;
		if (e->pollfd->revents) {
			nn--;
			events = 0;
			if (pfd->revents & POLLIN)
				events |= ELE_READ;
			if (pfd->revents & POLLOUT)
				events |= ELE_WRITE;
			if (pfd->revents & POLLHUP)
				events |= ELE_HANGUP;
			if (pfd->revents & POLLERR)
				events |= ELE_ERROR;
			if (pfd->revents & POLLNVAL)
				events |= ELE_NVAL;
			if (events)
				e->cb(e->cb_arg, events);
		}
		if (nn == 0 || eloop->one_event != NULL)
			break;
	}
	return n;
}

int
eloop_start(struct eloop *eloop)
{
	int error;
	struct eloop_timeout *t;
	struct timespec ts, *tsp;

	for (;;) {
		if (eloop->exitnow || eloop->endwait)
			break;

		if (eloop_nsig != 0) {
			int n = eloop_sig[--eloop_nsig];

			if (eloop->signal_cb != NULL)
				eloop->signal_cb(n, eloop->signal_cb_ctx);
			continue;
		}

		t = TAILQ_FIRST(&eloop->timeouts);
		if (t == NULL && eloop->nevents == 0)
			break;

		if (t != NULL)
			eloop_reduce_timers(eloop);

		if (t != NULL && t->seconds == 0 && t->nseconds == 0) {
			TAILQ_REMOVE(&eloop->timeouts, t, next);
			t->callback(t->arg);
			TAILQ_INSERT_TAIL(&eloop->free_timeouts, t, next);
			continue;
		}

		if (t != NULL) {
			if (t->seconds > INT_MAX) {
				ts.tv_sec = (time_t)INT_MAX;
				ts.tv_nsec = 0;
			} else {
				ts.tv_sec = (time_t)t->seconds;
				ts.tv_nsec = (long)t->nseconds;
			}
			tsp = &ts;
		} else
			tsp = NULL;

		if (eloop->events_need_setup)
			eloop_event_setup_fds(eloop);

		error = eloop_run_ppoll(eloop, tsp);
		if (error == -1) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
	}

	return eloop->exitcode;
}

int
eloop_wait(struct eloop *eloop, int fd, unsigned short events,
    void (*cb)(void *, unsigned short), void *cb_arg)
{
	struct pollfd pfd = { .fd = fd };
	struct eloop_event event = { .fd = fd,
		.events = events,
		.cb = cb,
		.cb_arg = cb_arg,
		.pollfd = &pfd };
	int err;

	if (eloop->one_event != NULL) {
		errno = EBUSY;
		return -errno;
	}

	if (events & ELE_READ)
		pfd.events |= POLLIN;
	if (events & ELE_WRITE)
		pfd.events |= POLLOUT;

	eloop->one_event = &event;
	err = eloop_start(eloop);
	eloop->one_event = NULL;
	eloop->endwait = false;
	return err;
}
