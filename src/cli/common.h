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

// Key derive {{{
//
// Derive the public half of a key for one key mode
//   single selects the N = 0 key, otherwise the stacked subtrees
//   a seed in the key wins over a stored public key, so --hash cannot disagree with the file

sfinx_status cli_key_derive(sfinx_key *key, int single);
// }}}

#endif  // __SFINX_CLI_COMMON_H__
