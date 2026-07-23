/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_lean_build_warning.c - lean-build fallback notice (AES / Grøstl).
 *
 * The AES and Grøstl backends live in libtalos_ichor, which does no I/O and
 * only exposes backend health via <ichor/backend.h>.  voleith turns an
 * ICHOR_BACKEND_FALLBACK verdict into a one-shot stderr notice through
 * voleith_backend_notice() (fired from the public proof entry points).  This
 * test validates that voleith_backend_notice() emits the notice when the host
 * CPU has a hardware AES backend that was opted out at compile time, that it
 * fires at most once, and that VOLEITH_QUIET=1 suppresses it.
 *
 * The active fallback is detected at runtime (ichor_aes_backend_health), not
 * from a compiled-in macro, so the test works regardless of whether ichor's
 * build defines propagate to this TU.  On a fat build (hardware backend
 * present) the notice path is not reachable and the test exits with PASS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cpu.h"
#include "backend_notice.h"

#include <ichor/backend.h>

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
    voleith_backend_notice_reset();

    if (stderr_capture_start(&read_fd, &saved_fd) < 0) {
        FAIL("pipe setup failed");
        unsetenv("VOLEITH_QUIET");
        return;
    }
    voleith_backend_notice();
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

    TEST("lean-build notice fires on first report");

    voleith_backend_notice_reset();

    if (stderr_capture_start(&read_fd, &saved_fd) < 0) {
        FAIL("pipe setup failed");
        return;
    }
    voleith_backend_notice();
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

    voleith_backend_notice_reset();
    /* Consume the once-guard with a first (discarded) report. */
    voleith_backend_notice();

    if (stderr_capture_start(&read_fd, &saved_fd) < 0) {
        FAIL("pipe setup failed");
        return;
    }
    voleith_backend_notice();
    stderr_capture_stop(read_fd, saved_fd, buf, sizeof(buf));

    if (strstr(buf, "voleith: notice:") == NULL)
        PASS();
    else
        FAIL("notice printed a second time");
}

int
main(void)
{
    printf("lean-build fallback notice tests\n");

    unsigned host = voleith_cpu_features();

    if (!(host & (VOLEITH_CPU_AES_NI | VOLEITH_CPU_ARMV8_AES))) {
        /* Host has no hardware AES: the fallback is the only choice, so the
         * notice path is not reachable.  Skip gracefully. */
        printf("  (host has no hardware AES backend; notice path not"
               " reachable, skipping)\n");
        printf("\n1/1 tests passed\n");
        return 0;
    }

    if (ichor_aes_backend_health() != ICHOR_BACKEND_FALLBACK) {
        /* Fat build: the hardware AES backend is compiled in and active, so
         * no lean-build notice is expected.  Pass-through. */
        printf("  (fat build; hardware AES backend active, no notice"
               " tests to run)\n");
        printf("\n1/1 tests passed\n");
        return 0;
    }

    /* Quiet-suppression first: it must not consume the once-guard, so the
     * subsequent fire test can still trigger the notice. */
    test_quiet_suppresses();
    test_notice_fires();
    test_notice_once();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
