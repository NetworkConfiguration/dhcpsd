# Remove some warnings
VERSTABLE_CFLAGS=	-Wno-cast-align -Wno-cast-qual -Wno-conversion -Wno-sign-conversion

check-format:
	find . -iname "*.c" -o -iname "*.h" -not -name verstable.h | \
		xargs clang-format --dry-run --Werror

format:
	find . -iname "*.c" -o -iname "*.h" -not -name verstable.h | \
		xargs clang-format -i

lint:
	clang-tidy ${SRCS} -- ${CPPFLAGS} ${CFLAGS} -isystem ${TOP}/vendor

include ${TOP}/Makefile.inc
