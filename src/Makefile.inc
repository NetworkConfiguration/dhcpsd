# Remove some warnings
VERSTABLE_CFLAGS=	-Wno-cast-align -Wno-cast-qual -Wno-conversion
VERSTABLE_CFLAGS+=	-Wno-sign-conversion -Wno-inline

check-format:
	find . -iname "*.c" -o -iname "*.h" -not -name verstable.h | \
		xargs clang-format --dry-run --Werror

format:
	find . -iname "*.c" -o -iname "*.h" -not -name verstable.h | \
		xargs clang-format -i

_lint:
	clang-tidy ${SRCS} -- ${CPPFLAGS} ${CFLAGS} -isystem ${TOP}/vendor

include ${TOP}/Makefile.inc
