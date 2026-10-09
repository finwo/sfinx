#ifndef __SFINX_CLI_COMMON_H__
#define __SFINX_CLI_COMMON_H__

#include <stddef.h>
#include <stdint.h>

#include "sfinx.h"

// Common {{{
//
// Message reading and hex helpers shared by the commands

int cli_read_message(const char *message, const char *file, uint8_t **out, size_t *len_out);
int cli_hex_decode(const char *hex, uint8_t **out, size_t *len_out);
// }}}

// Seed {{{
//
// The optional length argument and the random bytes it describes

#define CLI_SEED_LEN_DEFAULT 32

int          cli_seed_length(const char *text, size_t *len_out);
sfinx_status cli_seed_random(size_t len, uint8_t **out);
// }}}

#endif  // __SFINX_CLI_COMMON_H__
