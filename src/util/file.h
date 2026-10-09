#ifndef __SFINX_UTIL_FILE_H__
#define __SFINX_UTIL_FILE_H__

#include <stddef.h>
#include <stdint.h>

// File {{{
//
// Whole-file IO for the CLI, "-" or NULL means stdin or stdout
//   read mallocs len + 1 and NUL terminates, write sets the mode and O_EXCL
//   exists answers whether a path is already taken

int util_file_read(const char *path, uint8_t **out, size_t *len_out);
int util_file_write(const char *path, const uint8_t *data, size_t len, unsigned mode, int force);
int util_file_exists(const char *path);
// }}}

#endif  // __SFINX_UTIL_FILE_H__
