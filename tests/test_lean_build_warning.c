/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_lean_build_warning.c - lean-build mismatch notice.
 *
 * Validates that voleith_aes_dispatch_init() emits a notice on stderr
 * when the host CPU has AES-NI but the library was built without the
 * aes-ni backend (VOLEITH_HAVE_AES_NI not defined), and that the notice
 * is suppressed by VOLEITH_QUIET=1.
 *
 * In fat builds (VOLEITH_HAVE_AES_NI defined) no notice is emitted and
 * the test exits immediately with PASS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aes.h"
#include "cpu.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-55s ", tests_run, name);                             \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("PASS\n");                                                      \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("FAIL: %s\n", msg);                                             \
    } while (0)

#ifndef VOLEITH_HAVE_AES_NI

static int
stderr_capture_start(int *read_end, int *saved_fd)
{
    int fds[2];

    if (pipe(fds) < 0)
        return -1;
    *saved_fd = dup(STDERR_FILENO);
    if (*saved_fd < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (dup2(fds[1], STDERR_FILENO) < 0) {
        close(fds[0]);
        close(fds[1]);
        close(*saved_fd);
        return -1;
    }
    close(fds[1]);
    *read_end = fds[0];
    return 0;
}

static ssize_t
stderr_capture_stop(int read_end, int saved_fd, char *buf, size_t bufsz)
{
    ssize_t n;

    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);
    n = read(read_end, buf, bufsz - 1);
    close(read_end);
    if (n < 0)
        n = 0;
    buf[n] = '\0';
    return n;
}

static void
test_quiet_suppresses(void)
{
    int read_fd, saved_fd;
    char buf[512];

    TEST("VOLEITH_QUIET=1 suppresses lean-build notice");

    setenv("VOLEITH_QUIET", "1", 1);
    voleith_aes_dispatch_reset();

    if (stderr_capture_start(&read_fd, &saved_fd) < 0) {
        FAIL("pipe setup failed");
        unsetenv("VOLEITH_QUIET");
        return;
    }
    voleith_aes_dispatch_init();
    stderr_capture_stop(read_fd, saved_fd, buf, sizeof(buf));
    unsetenv("VOLEITH_QUIET");

    if (strstr(buf, "voleith: notice:") == NULL)
        PASS();
    else
        FAIL("notice printed despite VOLEITH_QUIET=1");
}

static void
test_notice_fires(void)
{
    int read_fd, saved_fd;
    char buf[512];

    TEST("lean-build notice fires on first dispatch init");

    voleith_aes_dispatch_reset();

    if (stderr_capture_start(&read_fd, &saved_fd) < 0) {
        FAIL("pipe setup failed");
        return;
    }
    voleith_aes_dispatch_init();
    stderr_capture_stop(read_fd, saved_fd, buf, sizeof(buf));

    if (strstr(buf, "voleith: notice:") != NULL)
        PASS();
    else
        FAIL("expected lean-build notice on stderr, got none");
}

static void
test_notice_once(void)
{
    int read_fd, saved_fd;
    char buf[512];

    TEST("lean-build notice fires at most once per process");

    voleith_aes_dispatch_reset();

    if (stderr_capture_start(&read_fd, &saved_fd) < 0) {
        FAIL("pipe setup failed");
        return;
    }
    voleith_aes_dispatch_init();
    stderr_capture_stop(read_fd, saved_fd, buf, sizeof(buf));

    if (strstr(buf, "voleith: notice:") == NULL)
        PASS();
    else
        FAIL("notice printed a second time");
}

#endif /* !VOLEITH_HAVE_AES_NI */

int
main(void)
{
    printf("lean-build mismatch warning tests\n");

#ifdef VOLEITH_HAVE_AES_NI
    /*
     * Fat build: all backends compiled in, no lean-build notice
     * expected.  This variant is a pass-through.
     */
    printf("  (fat build; no lean-build warning tests to run)\n");
    printf("\n1/1 tests passed\n");
    return 0;
#else
    unsigned host = voleith_cpu_features();

    if (!(host & VOLEITH_CPU_AES_NI)) {
        /*
         * Lean build but host has no AES-NI: the warning path is
         * unreachable (the feature bit check inside dispatch_init is
         * false).  Skip gracefully.
         */
        printf("  (host has no AES-NI; lean-build warning path not"
               " reachable, skipping)\n");
        printf("\n1/1 tests passed\n");
        return 0;
    }

    /*
     * Run quiet-suppression test first: when VOLEITH_QUIET is set the
     * atomic flag inside dispatch_init is not consumed, so the
     * subsequent fire test can still trigger the warning.
     */
    test_quiet_suppresses();
    test_notice_fires();
    test_notice_once();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
#endif
}
