# System definitions

PICFLAG?=	-fPIC

BINMODE?=	0555
NONBINMODE?=	0444
MANMODE?=	${NONBINMODE}
CONFMODE?=	0644
DBMODE?=	0750

CC?=		cc
ECHO?=		echo
INSTALL?=	install
LINT?=		lint
SED?=		sed
HOST_SH?=	/bin/sh

# This isn't very portable, but I generaly make releases from NetBSD
SHA256?=	sha256
# Force gpg2 to avoid SHA1 signatures from gpg1
PGP?=		gpg2

SED_CONFDIR=		-e 's:@CONFDIR@:${CONFDIR}:g'
SED_PLUGINDIR=		-e 's:@PLUGINDIR@:${PLUGINDIR}:g'
SED_DBDIR=		-e 's:@DBDIR@:${DBDIR}:g'
