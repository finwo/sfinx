#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

static unsigned test_no;
static unsigned test_failures;

static void tap_begin(const char *name) {
  printf("TAP version 13\n");
  printf("# %s\n", name);
}

static void tap(uint32_t ok, const char *what, const char *fmt, ...) {
  test_no++;
  printf("%s %u - %s\n", ok ? "ok" : "not ok", test_no, what);
  if (!ok) {
    va_list ap;
    va_start(ap, fmt);
    fputs("# ", stdout);
    vprintf(fmt, ap);
    fputc('\n', stdout);
    va_end(ap);
    test_failures++;
  }
}

static int tap_plan(void) {
  printf("1..%u\n", test_no);
  if (test_failures) {
    printf("# %u of %u assertions failed\n", test_failures, test_no);
    return 1;
  }
  return 0;
}
