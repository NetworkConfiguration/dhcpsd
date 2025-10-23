# dhcpsd Makefile

PROG=		dhcpsd
SRCS=		dhcpsd.c common.c eloop.c if.c logerr.c
SRCS+=		bpf.c dhcp.c dhcp_lease.c
SRCS+=		if_none.c if_ether.c
SRCS+=		service.c unpriv.c
SRCS+=		plugin.c
OBJS+=          ${SRCS:.c=.o}

PVENDOR_SRCS=	${VENDOR_SRCS:vendor/%=${TOP}/vendor/%}
OBJS+=		${PVENDOR_SRCS:.c=.o}

PCOMPAT_SRCS=	${COMPAT_SRCS:compat/%=${TOP}/compat/%}
OBJS+=		${PCOMPAT_SRCS:.c=.o}

CFLAGS?=	-O2
SUBDIRS=	plugins

TOP=		..
include		${TOP}/iconfig.mk

CSTD?=		c11
CFLAGS+=	-std=${CSTD}
CPPFLAGS+=	-I${TOP} -I${TOP}/src -I ${TOP}/vendor
LDFLAGS+=	-rdynamic

MAN8=		dhcpsd.8
CLEANFILES+=	dhcpsd.8

DEPEND!=	test -e .depend && echo ".depend" || echo ""

CLEANFILES+=	*.tar.xz

.PHONY:		import import-bsd dev test

.SUFFIXES:	.in

.in:
	${SED} ${SEC_DBDIR} ${SED_PLUGINDIR} $< > $@

all: ${TOP}/config.h ${PROG} ${SCRIPTS} ${MAN5} ${MAN8}
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@ || exit $$?; cd ..; done

dev:
	cd dev && ${MAKE}

# verstable.h has a few compiler warnings so we hide it away
# in a small stub file
dhcp_lease.o:
	${CC} ${CFLAGS} ${CPPFLAGS} ${VERSTABLE_CFLAGS} -c dhcp_lease.c -o $@

# NetBSD's rbtree is pretty portable, but we need to give it a define
# so it knows to include the local rbtree.h rather than the one in sys
${TOP}/vendor/rbtree.o:
	${CC} ${CFLAGS} ${CPPFLAGS} ${RBTREE_CPPFLAGS} -c ${TOP}/vendor/rbtree.c -o $@

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

${PROG}: ${DEPEND} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${SBINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${SBINDIR}
	${INSTALL} -m ${DBMODE} -d ${DESTDIR}${DBDIR}
	for x in ${SUBDIRS}; do ${MAKE} -C $$x $@ || exit $$?; done

maninstall: ${MAN8}
	${INSTALL} -d ${DESTDIR}${MANDIR}/man8
	${INSTALL} -m ${MANMODE} ${MAN8} ${DESTDIR}${MANDIR}/man8
	for x in ${SUBDIRS}; do ${MAKE} -C $$x $@ || exit $$?; done

install: proginstall maninstall

clean:
	rm -f -- ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@ || exit $$?; cd ..; done

distclean: clean
	rm -f .depend
	rm -f *.diff *.patch *.orig *.rej

import-src: ${SRCS} ${MAN5} ${MAN8}
	@if ! [ -e ../config.h ]; then \
		echo "Cowardly refusing to import-src unless configured" >&2; \
		exit 1; \
	fi
	${INSTALL} -d ${DESTDIR}/src
	for x in defs.h ${SRCS} ${SRCS:.c=.h} dev.h ${MAN5} ${MAN8}; do \
		[ ! -e "$$x" ] || cp $$x ${DESTDIR}/src; \
	done
	${INSTALL} -d ${DESTDIR}/vendor
	cp ${TOP}/vendor/README.md ${DESTDIR}/vendor
	cp ${TOP}/vendor/queue.h ${TOP}/vendor/verstable.h ${DESTDIR}/vendor
	if [ -z "${RBTREE_CFLAGS}" ]; then \
		cp ${TOP}/vendor/rbtree.c ${DESTDIR}/vendor; \
		cp ${TOP}/vendor/rbtree.h ${DESTDIR}/vendor; \
	fi
	if [ -n "${COMPAT_SRCS}" ]; then \
		${INSTALL} -d ${DESTDIR}/compat; \
		for x in ${COMPAT_SRCS} ${COMPAT_SRCS:.c=.h}; do \
			[ ! -e "../$$x" ] || cp "../$$x" ${DESTDIR}/compat; \
		done; \
	fi

include Makefile.inc
