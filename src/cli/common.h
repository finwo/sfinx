#ifndef __SFINX_CLI_COMMON_H__
#define __SFINX_CLI_COMMON_H__

#include <stddef.h>
#include <stdint.h>

// Common {{{
//
// Message reading and hex helpers shared by the commands

int cli_read_message(const char *message, const char *file, uint8_t **out, size_t *len_out);
int cli_hex_decode(const char *hex, uint8_t **out, size_t *len_out);
// }}}

#endif  // __SFINX_CLI_COMMON_H__
