#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static void
test(const char *src, const char *expect)
{
	char *h = strdup(src);

	if (h == NULL) {
		(void)fprintf(stderr, "strdup %s", src);
		exit(EXIT_FAILURE);
	}

	sanitize_rfc1035(h);
	if (strcmp(h, expect) != 0) {
		(void)fprintf(stderr, "%s: %s != %s\n", src, expect, h);
		(void)fprintf(stderr, "HOSTNAME TEST FAILURE\n");
		exit(EXIT_FAILURE);
	}
	(void)fprintf(stderr, "%s: %s\n", src, expect);
}

int
main(void)
{
	char tst[2048], expect[2048];
	size_t i, j;

	(void)fprintf(stderr, "TESTING WE CAN SANITIZE HOSTNAMES FOR RFC1035\n");

	test("valid.hostname", "valid.hostname");
	test("invalid hostname", "invalid-hostname");
	test(" invalid hostname", "");
	test("invalid hostname ", "invalid-hostname");
	test("valid.invalid hostname.valid", "valid.invalid-hostname.valid");
	test("valid. invalid hostname.valid", "valid");
	test("valid.invalid hostname .invalid .valid",
	    "valid.invalid-hostname.invalid.valid");
	test(".invalid hostname ", "");
	test("invalid hostname.", "invalid-hostname");
	test("invalid hostname. ", "invalid-hostname");
	test("invalid hostname..", "invalid-hostname");

	/* Test for one character too long for a max label */
	test(
	    "valid.1234567890123456789012345678901234567890123456789012345678901234",
	    "valid.123456789012345678901234567890123456789012345678901234567890123");
	test(
	    "valid.1234567890123456789012345678901234567890123456789012345678901234.valid",
	    "valid.123456789012345678901234567890123456789012345678901234567890123.valid");

	/* Test for one too many labels */
	for (i = 0, j = 0; j < 128; i++) {
		if (i % 2 == 0)
			tst[i] = 'a';
		else {
			tst[i] = '.';
			j++;
		}
	}
	tst[i] = '\0';
	memcpy(expect, tst, i);
	// Expect to be trimmed by one
	expect[i - 1] = '\0';
	test(tst, expect);

	/* Test for one character too big for the whole domain. */
	for (i = 0, j = 0; i <= 256; i++, j++) {
		if (j == 63) {
			tst[i] = '.';
			j = 0;
		} else
			tst[i] = 'a';
	}
	tst[i] = '\0';
	memcpy(expect, tst, i);
	// Expect to be trimmed by one
	expect[i - 1] = '\0';
	test(tst, expect);

	(void)fprintf(stderr, "HOSTNAME TESTS PASS\n");
	exit(EXIT_SUCCESS);
}
