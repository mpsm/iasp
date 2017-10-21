#include <arpa/inet.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libiasp/streambuf.h"


static void test_streambuf_init(void **state)
{
    static uint8_t buf[] = {"test test"};
    size_t bufsize = strlen((char *)buf);
    streambuf_t sb;

    streambuf_init(&sb, buf, bufsize, bufsize);

    assert_int_equal(sb.size, 9);
    assert_int_equal(sb.max_size, sb.size);
    assert_int_equal(sb.read_index, 0);
}


static void test_streambuf_read(void **state)
{
    static uint8_t buf[] = {"test test"};
    static uint8_t obuf[16];
    size_t bufsize = strlen((char *)buf);
    streambuf_t sb;

    streambuf_init(&sb, buf, bufsize, bufsize);
    assert_true(streambuf_read(&sb, obuf, 4));
    assert_true(strncmp((char *)obuf, "test", 4) == 0);

    assert_false(streambuf_read(&sb, obuf, 6));
    assert_true(streambuf_read(&sb, obuf, 5));
    assert_true(strncmp((char *)obuf, " test", 5) == 0);
}


static void test_streambuf_write(void **state)
{
    static uint8_t buf[7];
    static uint8_t buf2[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    streambuf_t sb;
    uint16_t v1 = htons(0x1122);
    uint32_t v2 = htonl(0x33445566);
    uint8_t v3 = 0x77;

    streambuf_init(&sb, buf, 0, sizeof(buf));
    assert_true(streambuf_write(&sb, (uint8_t *)&v1, sizeof(v1)));
    assert_int_equal(sb.size, sizeof(v1));

    assert_true(streambuf_write(&sb, (uint8_t *)&v2, sizeof(v2)));
    assert_int_equal(sb.size, sizeof(v1) + sizeof(v2));

    assert_false(streambuf_write(&sb, (uint8_t *)&v2, sizeof(v2)));

    assert_true(streambuf_write(&sb, (uint8_t *)&v3, sizeof(v3)));
    assert_int_equal(sb.size, sizeof(v1) + sizeof(v2) + sizeof(v3));

    assert_false(streambuf_write(&sb, (uint8_t *)&v3, sizeof(v3)));

    assert_int_equal(sb.size, sb.max_size);
    assert_int_equal(sb.size, sizeof(buf2));
    assert_true(memcmp(buf, buf2, sizeof(buf)) == 0);
}


static void test_streambuf_read_write(void **state)
{
    static uint8_t buf[4];
    streambuf_t sb;
    uint32_t v1 = htonl(0x11223344);
    uint16_t rv1;
    uint8_t rv2;

    streambuf_init(&sb, buf, 0, sizeof(buf));
    assert_true(streambuf_write(&sb, (uint8_t *)&v1, 3));
    assert_int_equal(sb.size, 3);

    assert_true(streambuf_read(&sb, (uint8_t *)&rv1, sizeof(rv1)));
    assert_int_equal(ntohs(rv1), 0x1122);

    assert_false(streambuf_read(&sb, (uint8_t *)&rv1, sizeof(rv1)));
    assert_true(streambuf_read(&sb, (uint8_t *)&rv2, sizeof(rv2)));
    assert_int_equal(rv2, 0x33);
}


int main(int argc, char *argv[])
{
    const struct CMUnitTest streambuf_tests[] = {
            cmocka_unit_test(test_streambuf_init),
            cmocka_unit_test(test_streambuf_read),
            cmocka_unit_test(test_streambuf_write),
            cmocka_unit_test(test_streambuf_read_write),
    };

    printf("IASP test utility.\n");


    cmocka_run_group_tests(streambuf_tests, NULL, NULL);


    return 0;
}
