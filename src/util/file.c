#include "file.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_fd(int fd, uint8_t **out, size_t *len_out) {
  size_t   cap = 65536;
  size_t   len = 0;
  uint8_t *buf = malloc(cap + 1);
  if (!buf) return -1;
  for (;;) {
    if (len == cap) {
      size_t   ncap = cap * 2;
      uint8_t *nbuf = realloc(buf, ncap + 1);
      if (!nbuf) {
        free(buf);
        return -1;
      }
      buf = nbuf;
      cap = ncap;
    }
    ssize_t n = read(fd, buf + len, cap - len);
    if (n < 0) {
      free(buf);
      return -1;
    }
    if (n == 0) break;
    len += (size_t)n;
  }
  buf[len] = 0;
  *out     = buf;
  *len_out = len;
  return 0;
}

static int write_fd(int fd, const uint8_t *data, size_t len) {
  size_t put = 0;
  while (put < len) {
    ssize_t n = write(fd, data + put, len - put);
    if (n <= 0) return -1;
    put += (size_t)n;
  }
  return 0;
}

int util_file_read(const char *path, uint8_t **out, size_t *len_out) {
  int fd;
  int rc;
  if (!out || !len_out) return -1;
  if (!path || strcmp(path, "-") == 0) {
    return read_fd(STDIN_FILENO, out, len_out);
  }
  fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  rc = read_fd(fd, out, len_out);
  close(fd);
  return rc;
}

int util_file_write(const char *path, const uint8_t *data, size_t len, unsigned mode, int force) {
  int fd;
  int rc;
  int flags = O_WRONLY | O_CREAT | O_TRUNC;
  if (!data && len) return -1;
  if (!path || strcmp(path, "-") == 0) {
    return write_fd(STDOUT_FILENO, data, len);
  }
  if (!force) flags |= O_EXCL;
  fd = open(path, flags, mode);
  if (fd < 0) return -1;
  rc = write_fd(fd, data, len);
  close(fd);
  return rc;
}
