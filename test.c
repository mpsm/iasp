#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libiasp/streambuf.h"


static void test_streambuf_read(void **state)
{
    static uint8_t buf[] = {"test test"};
    static uint8_t obuf[16];
    streambuf_t sb;

    streambuf_init(&sb, buf, strlen((char *)buf));
    assert_int_equal(streambuf_read(&sb, obuf, 4), 4);
    assert_true(strncmp((char *)obuf, "test", 4) == 0);

    assert_int_equal(streambuf_read(&sb, obuf, 6), 5);
    assert_true(strncmp((char *)obuf, " test", 5) == 0);
}



int main(int argc, char *argv[])
{
    const struct CMUnitTest streambuf_tests[] = {
            cmocka_unit_test(test_streambuf_read),
    };

    printf("IASP test utility.\n");


    cmocka_run_group_tests(streambuf_tests, NULL, NULL);


    return 0;
}
