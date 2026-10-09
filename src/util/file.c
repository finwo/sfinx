#include "file.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int util_file_read(const char *path, uint8_t **out, size_t *len_out) {
  struct stat st;
  uint8_t    *buf;
  size_t      len;
  size_t      got = 0;
  int         fd;

  if (!path || !out || !len_out) return -1;
  fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  if (fstat(fd, &st) != 0) {
    close(fd);
    return -1;
  }
  len = (size_t)st.st_size;
  buf = malloc(len + 1);
  if (!buf) {
    close(fd);
    return -1;
  }
  while (got < len) {
    ssize_t n = read(fd, buf + got, len - got);
    if (n <= 0) {
      free(buf);
      close(fd);
      return -1;
    }
    got += (size_t)n;
  }
  close(fd);
  buf[len] = 0;
  *out     = buf;
  *len_out = len;
  return 0;
}

int util_file_write(const char *path, const uint8_t *data, size_t len, unsigned mode, int force) {
  size_t put = 0;
  int    fd;
  int    flags = O_WRONLY | O_CREAT | O_TRUNC;

  if (!path || (!data && len)) return -1;
  if (!force) flags |= O_EXCL;
  fd = open(path, flags, mode);
  if (fd < 0) return -1;
  while (put < len) {
    ssize_t n = write(fd, data + put, len - put);
    if (n <= 0) {
      close(fd);
      return -1;
    }
    put += (size_t)n;
  }
  return close(fd);
}
