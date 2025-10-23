TOP=	../../
include ${TOP}/Makefile.inc
include ${TOP}/iconfig.mk

CFLAGS?=	-O2
CSTD?=		c11
CFLAGS+=	-std=${CSTD}
CPPFLAGS+=	-I${TOP} -I${TOP}/src -I${TOP}/vendor

PLUGINDIR=	${LIBDIR}/dhcpsd

PLUGINS=	auto leasefile icmp
PLUGINS+=	addrinfo ethers
PLUGINS+=	${LUA_PLUGIN}
SRCS=		${PLUGINS:=.c}
OBJS=		${SRCS:.c=.o}
SOBJS=		${OBJS:.o=.So}
PLUGS=		${PLUGINS:=.so}

MAN8=		dhcpsd_auto.8 dhcpsd_leasefile.8
MAN8+=		dhcpsd_addrinfo.8 dhcpsd_ethers.8
MAN8+=		dhcpsd_icmp.8
MAN8+=		${LUA_MAN8}

CLEANFILES+=	${OBJS} ${SOBJS} ${PLUGS}
CLEANFILES+=	dhcpsd_leasefile.8 ${LUA_MAN8}

.SUFFIXES:	.So .so .in

.c.So:
	${CC} ${PICFLAG} -DPIC ${CFLAGS} ${CDBGFLAGS} ${CPPFLAGS} -c $< -o $@

.So.so:
	${CC} ${LDFLAGS} -shared -Wl,-x -o $@ -Wl,-soname,$@ $< ${LIBS}

.in:
	${SED} ${SED_CONFDIR} ${SED_DBDIR} ${SED_PLUGINDIR} $< > $@

all: ${PLUGS} ${MAN8}

# verstable.h has a few compiler warnings so we hide it away
icmp.So:
	${CC} ${PICFLAG} -DPIC ${CFLAGS} ${CPPFLAGS} ${VERSTABLE_CFLAGS} -c icmp.c -o $@

lua.So:
	${CC} ${PICFLAG} -DPIC ${CFLAGS} ${CDBGFLAGS} ${LUA_CFLAGS} ${CPPFLAGS} -c lua.c -o $@

lua.so: lua.So
	${CC} ${LDFLAGS} -shared -Wl,-x -o $@ -Wl,-soname,$@ lua.So ${LUA_LIBS}

proginstall: ${PLUGS}
	${INSTALL} -d ${DESTDIR}${PLUGINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${PLUGS} ${DESTDIR}${PLUGINDIR}

maninstall: ${MAN8}
	${INSTALL} -d ${DESTDIR}${MANDIR}/man8
	${INSTALL} -m ${MANMODE} ${MAN8} ${DESTDIR}${MANDIR}/man8

install: proginstall maninstall

clean:
	rm -f -- ${CLEANFILES}

include ../Makefile.inc
