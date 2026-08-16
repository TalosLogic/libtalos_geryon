/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Minimal in-house unit-test harness for geryon.  No third-party test
 * framework, to keep licensing and dependencies trivial.  A test source
 * defines its cases with TEST(...) and emits an entry point with
 * GY_TEST_MAIN(...); the exit status is nonzero if any assertion failed.
 *
 * Plain memcmp (not gy_const_memcmp) is fine here: tests are not library
 * code and carry no constant-time obligation.
 */

#ifndef GY_TEST_H
#define GY_TEST_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Assertion tallies for the single translation unit that includes this. */
static int gy_test_asserts;
static int gy_test_failures;

/* Define a test case body: static void <name>(void) { ... }. */
#define TEST(name) static void name(void)

#define ASSERT_TRUE(cond, msg)                                                 \
    do {                                                                       \
        gy_test_asserts++;                                                     \
        if (!(cond)) {                                                         \
            gy_test_failures++;                                                \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));    \
        }                                                                      \
    } while (0)

#define ASSERT_EQ(a, b)                                                        \
    do {                                                                       \
        long long gy_a = (long long)(a);                                       \
        long long gy_b = (long long)(b);                                       \
        gy_test_asserts++;                                                     \
        if (gy_a != gy_b) {                                                    \
            gy_test_failures++;                                                \
            fprintf(stderr, "FAIL %s:%d: ASSERT_EQ(%s, %s): %lld != %lld\n",   \
                    __FILE__, __LINE__, #a, #b, gy_a, gy_b);                   \
        }                                                                      \
    } while (0)

#define ASSERT_MEMEQ(a, b, n)                                                  \
    do {                                                                       \
        gy_test_asserts++;                                                     \
        if (memcmp((a), (b), (n)) != 0) {                                      \
            gy_test_failures++;                                                \
            fprintf(stderr, "FAIL %s:%d: ASSERT_MEMEQ(%s, %s, %s)\n",          \
                    __FILE__, __LINE__, #a, #b, #n);                           \
        }                                                                      \
    } while (0)

/* One registered test: display name plus its function. */
struct gy_test_case {
    const char *name;
    void (*fn)(void);
};

#define GY_TEST(name)                                                          \
    {                                                                          \
#name, name                                                            \
    }

static int
gy_test_run(const struct gy_test_case *cases, size_t n)
{
    size_t i;
    int before;

    for (i = 0; i < n; i++) {
        before = gy_test_failures;
        cases[i].fn();
        printf("%-44s %s\n", cases[i].name,
               gy_test_failures == before ? "ok" : "FAILED");
    }
    printf("\n%d assertions, %d failures\n", gy_test_asserts, gy_test_failures);
    return gy_test_failures == 0 ? 0 : 1;
}

#define GY_TEST_MAIN(...)                                                      \
    int main(void)                                                             \
    {                                                                          \
        static const struct gy_test_case gy_cases[] = {__VA_ARGS__};           \
        return gy_test_run(gy_cases, sizeof(gy_cases) / sizeof(gy_cases[0]));  \
    }

/* Decode one hex nibble, or -1 if c is not a hex digit. */
static inline int
gy_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/*
 * Decode a NUL-terminated hex string into out (capacity out_cap).  Returns
 * the number of bytes written, or -1 on odd length, overflow, or a non-hex
 * character.  For loading test vectors.
 */
static inline int
gy_hex_decode(uint8_t *out, size_t out_cap, const char *hex)
{
    size_t i, nbytes;
    int hi, lo;

    nbytes = strlen(hex) / 2;
    if (strlen(hex) % 2 != 0 || nbytes > out_cap)
        return -1;
    for (i = 0; i < nbytes; i++) {
        hi = gy_hex_nibble(hex[2 * i]);
        lo = gy_hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)nbytes;
}

/*
 * Read one line from f into buf (capacity cap), stripping a trailing CR/LF.
 * Returns 1 on a line read, 0 at end of file.  For walking vector files.
 */
static inline int
gy_read_line(FILE *f, char *buf, size_t cap)
{
    size_t n;

    if (fgets(buf, (int)cap, f) == NULL)
        return 0;
    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return 1;
}

#endif /* GY_TEST_H */
