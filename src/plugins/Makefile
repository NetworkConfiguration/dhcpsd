TOP=	../../
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
PLUGS=		${PLUGINS:=.so}

MAN8=		dhcpsd_auto.8 dhcpsd_leasefile.8
MAN8+=		dhcpsd_addrinfo.8 dhcpsd_ethers.8
MAN8+=		dhcpsd_icmp.8
MAN8+=		${LUA_MAN8}

CLEANFILES+=	${OBJS} ${PLUGS}
CLEANFILES+=	dhcpsd_leasefile.8 ${LUA_MAN8}

.SUFFIXES:	.in .so

.c.o:
	${CC} ${PICFLAG} -DPIC ${CFLAGS} ${CDBGFLAGS} ${CPPFLAGS} -c $< -o $@

.o.so:
	${CC} ${LDFLAGS} ${LDFLAGS_SO} -shared -Wl,-x -o $@ $< ${LIBS}

.in:
	${SED} ${SED_CONFDIR} ${SED_DBDIR} ${SED_PLUGINDIR} $< > $@

all: ${PLUGS} ${MAN8}

# verstable.h has a few compiler warnings so we hide it away
icmp.o: icmp.c
	${CC} ${PICFLAG} -DPIC ${CFLAGS} ${CPPFLAGS} ${VERSTABLE_CFLAGS} -c icmp.c -o $@

lua.o: lua.c
	${CC} ${PICFLAG} -DPIC ${CFLAGS} ${CDBGFLAGS} ${LUA_CFLAGS} ${CPPFLAGS} -c lua.c -o $@

lua.so: lua.o
	${CC} ${LDFLAGS} ${LDFLAGS_SO} -shared -Wl,-x -o $@ lua.soo ${LUA_LIBS}

lint: _lint

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
