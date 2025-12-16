TOP=		..
include		${TOP}/iconfig.mk

CSTD?=		c11
CFLAGS+=	-std=${CSTD}
CPPFLAGS+=	-I${TOP} -I${TOP}/src -I ${TOP}/vendor
LDFLAGS+=	-rdynamic

DEPEND!=	test -e .depend && echo ".depend" || echo ""

HOSTNAME_SRCS=	hostname.c ../src/common.c
HOSTNAME_OBJS+= ${HOSTNAME_SRCS:.c=.o}

SRCS=		${HOSTNAME_SRCS}
OBJS=		${HOSTNAME_OBJS}

CLEANFILES+=	*.tar.xz


all: ${TOP}/config.h hostname
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@ || exit $$?; cd ..; done

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

hostname: ${HOSTNAME_OBJS}
	${CC} ${LDFLAGS} -o $@ ${HOSTNAME_OBJS} ${LDADD}

test: hostname
	./hostname

clean:
	rm -f -- ${OBJS} hostname ${hostname}.core ${HOSTNAME_OBJS} ${CLEANFILES}
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@ || exit $$?; cd ..; done

lint: _lint

include ${TOP}/src/Makefile.inc
