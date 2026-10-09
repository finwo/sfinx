#include "common.h"

#include <stdlib.h>
#include <string.h>

#include "util/file.h"

int cli_read_message(const char *message, const char *file, uint8_t **out, size_t *len_out) {
  uint8_t *buf;
  size_t   len;
  if (message) {
    len = strlen(message);
    buf = malloc(len + 1);
    if (!buf) return -1;
    memcpy(buf, message, len + 1);
    *out     = buf;
    *len_out = len;
    return 0;
  }
  return util_file_read(file, out, len_out);
}

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int cli_hex_decode(const char *hex, uint8_t **out, size_t *len_out) {
  size_t   len = strlen(hex);
  size_t   n;
  uint8_t *buf;
  if (len % 2 != 0) return -1;
  n   = len / 2;
  buf = malloc(n + 1);
  if (!buf) return -1;
  for (size_t i = 0; i < n; i++) {
    int hi = hexval(hex[i * 2]);
    int lo = hexval(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      free(buf);
      return -1;
    }
    buf[i] = (uint8_t)((hi << 4) | lo);
  }
  *out     = buf;
  *len_out = n;
  return 0;
}
