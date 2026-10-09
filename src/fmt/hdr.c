#include <stdlib.h>
#include <string.h>

#include "../sfinx.h"

// hdr format {{{
//
// Text key file, self-describing by label, unknown labels are ignored
//   hash: <bits>
//   seed: <hex | (no seed)>
//   public-key: <hex>
//   labels are case-insensitive, first valid occurrence wins, a lone seed derives its public half

static int hdr_hexval(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static uint8_t *hdr_hex_decode(const uint8_t *in, size_t in_len, size_t *out_len) {
  uint8_t *out;
  if (in_len % 2 != 0) {
    return NULL;
  }
  out = malloc(in_len / 2 + 1);
  if (!out) {
    return NULL;
  }
  for (size_t i = 0; i < in_len / 2; i++) {
    int hi = hdr_hexval(in[i * 2]);
    int lo = hdr_hexval(in[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      free(out);
      return NULL;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  *out_len = in_len / 2;
  return out;
}

static void hdr_hex_encode(uint8_t *out, const uint8_t *in, size_t in_len) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < in_len; i++) {
    out[i * 2]     = (uint8_t)digits[(in[i] >> 4) & 0x0f];
    out[i * 2 + 1] = (uint8_t)digits[in[i] & 0x0f];
  }
}

static int hdr_match(const uint8_t *line, size_t len, const char *label, const uint8_t **val, size_t *val_len) {
  size_t at        = 0;
  size_t label_len = strlen(label);
  while (at < len && (line[at] == ' ' || line[at] == '\t')) at++;
  if (at + label_len > len) return 0;
  for (size_t i = 0; i < label_len; i++) {
    uint8_t c = line[at + i];
    if (c >= 'A' && c <= 'Z') c = (uint8_t)(c - 'A' + 'a');
    if (c != (uint8_t)label[i]) return 0;
  }
  at += label_len;
  while (at < len && (line[at] == ' ' || line[at] == '\t')) at++;
  if (at >= len || line[at] != ':') return 0;
  at++;
  while (at < len && (line[at] == ' ' || line[at] == '\t')) at++;
  size_t end = len;
  while (end > at && (line[end - 1] == ' ' || line[end - 1] == '\t' || line[end - 1] == '\r')) end--;
  *val     = line + at;
  *val_len = end - at;
  return 1;
}

static int hdr_detect(const uint8_t *data, size_t len) {
  const uint8_t *val;
  size_t         val_len;
  for (size_t pos = 0; pos < len;) {
    size_t end = pos;
    while (end < len && data[end] != '\n') end++;
    if (hdr_match(data + pos, end - pos, "seed", &val, &val_len) ||
        hdr_match(data + pos, end - pos, "public-key", &val, &val_len)) {
      return 1;
    }
    pos = end + 1;
  }
  return 0;
}

static sfinx_status hdr_decode(const uint8_t *data, size_t len, sfinx_key *out) {
  int seen_hash = 0;
  int seen_seed = 0;
  int seen_pub  = 0;

  for (size_t pos = 0; pos < len;) {
    const uint8_t *val;
    size_t         val_len;
    size_t         end = pos;
    while (end < len && data[end] != '\n') end++;

    if (!seen_hash && hdr_match(data + pos, end - pos, "hash", &val, &val_len)) {
      seen_hash     = 1;
      uint32_t bits = 0;
      int      ok   = val_len > 0;
      for (size_t i = 0; i < val_len && ok; i++) {
        if (val[i] < '0' || val[i] > '9') {
          ok = 0;
          break;
        }
        bits = bits * 10 + (uint32_t)(val[i] - '0');
      }
      if (ok && sfinx_hash_len((sfinx_hash)bits) != 0) {
        out->hash = (sfinx_hash)bits;
      }
    } else if (!seen_seed && hdr_match(data + pos, end - pos, "seed", &val, &val_len)) {
      seen_seed = 1;
      if (val_len > 0 && val[0] != '(') {
        out->seed = hdr_hex_decode(val, val_len, &out->seed_len);
        if (!out->seed) return SFINX_ERR_FORMAT;
      }
    } else if (!seen_pub && hdr_match(data + pos, end - pos, "public-key", &val, &val_len)) {
      seen_pub = 1;
      if (val_len > 0 && val[0] != '(') {
        out->pub = hdr_hex_decode(val, val_len, &out->pub_len);
        if (!out->pub) return SFINX_ERR_FORMAT;
      }
    }
    pos = end + 1;
  }

  if (!seen_seed && !seen_pub) return SFINX_ERR_FORMAT;
  if (!out->seed && !out->pub) return SFINX_ERR_FORMAT;
  if (out->seed && !out->pub && sfinx_key_derive(out) != SFINX_OK) {
    return SFINX_ERR_FORMAT;
  }
  return SFINX_OK;
}

static size_t hdr_encode_len(const sfinx_key *key) {
  size_t need = strlen("hash: 000\n");
  need += strlen("seed: \n") + (key->seed ? key->seed_len * 2 : strlen("(no seed)"));
  need += strlen("public-key: \n") + (key->pub ? key->pub_len * 2 : strlen("(no public key)"));
  return need;
}

static sfinx_status hdr_encode(const sfinx_key *key, uint8_t *out, size_t cap, size_t *len_out) {
  uint32_t bits = (uint32_t)key->hash;
  size_t   at   = 0;
  if (cap < hdr_encode_len(key)) {
    return SFINX_ERR_NOSPACE;
  }

  memcpy(out + at, "hash: ", 6);
  at += 6;
  out[at++] = (uint8_t)('0' + (bits / 100) % 10);
  out[at++] = (uint8_t)('0' + (bits / 10) % 10);
  out[at++] = (uint8_t)('0' + bits % 10);
  out[at++] = '\n';

  memcpy(out + at, "seed: ", 6);
  at += 6;
  if (key->seed) {
    hdr_hex_encode(out + at, key->seed, key->seed_len);
    at += key->seed_len * 2;
  } else {
    memcpy(out + at, "(no seed)", 9);
    at += 9;
  }
  out[at++] = '\n';

  memcpy(out + at, "public-key: ", 12);
  at += 12;
  if (key->pub) {
    hdr_hex_encode(out + at, key->pub, key->pub_len);
    at += key->pub_len * 2;
  } else {
    memcpy(out + at, "(no public key)", 15);
    at += 15;
  }
  out[at++] = '\n';

  if (len_out) {
    *len_out = at;
  }
  return SFINX_OK;
}

static sfinx_format hdr_format = {
    .name       = "hdr",
    .detect     = hdr_detect,
    .decode     = hdr_decode,
    .encode_len = hdr_encode_len,
    .encode     = hdr_encode,
};

__attribute__((constructor)) static void hdr_register(void) {
  sfinx_format_register(&hdr_format);
}
// }}}

// vim:fdm=marker:fdl=0
