#ifndef SRC_BASE64_INL_H_
#define SRC_BASE64_INL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "base64.h"
#include "base64_data.h"
#include "util.h"

namespace node {

extern const int8_t unbase64_table[256];

#define BADCHAR 0x01FFFFFF

template <typename TypeName>
bool base64_decode_group_slow(char* const dst, const size_t dstlen,
                              const TypeName* const src, const size_t srclen,
                              size_t* const i, size_t* const k) {
  uint8_t hi;
  uint8_t lo;
#define V(expr)                                                                \
  for (;;) {                                                                   \
    const uint8_t c = static_cast<uint8_t>(src[*i]);                           \
    lo = unbase64_table[c];                                                    \
    *i += 1;                                                                   \
    if (lo < 64) break;                         /* Legal character. */         \
    if (c == '=' || *i >= srclen) return false; /* Stop decoding. */           \
  }                                                                            \
  expr;                                                                        \
  if (*i >= srclen) return false;                                              \
  if (*k >= dstlen) return false;                                              \
  hi = lo;
  V(/* Nothing. */);
  V(dst[(*k)++] = ((hi & 0x3F) << 2) | ((lo & 0x30) >> 4));
  V(dst[(*k)++] = ((hi & 0x0F) << 4) | ((lo & 0x3C) >> 2));
  V(dst[(*k)++] = ((hi & 0x03) << 6) | ((lo & 0x3F) >> 0));
#undef V
  return true;  // Continue decoding.
}

template <typename TypeName>
inline size_t modp_b64_decode(char* dest, const TypeName* src, size_t len, bool strict) {
  if (len == 0) return 0;

  /* there can be at most 2 pad chars at the end */
  if (src[len - 1] == CHARPAD) {
    len--;
    if (src[len - 1] == CHARPAD) {
      len--;
    }
  }

  size_t i;
  int leftover = len % 4;
  size_t chunks = (leftover == 0) ? len / 4 - 1 : len / 4;

  uint8_t* p = (uint8_t*)dest;
  uint32_t x = 0;
  uint8_t _0;
  uint8_t _1;
  uint8_t _2;
  uint8_t _3;
  const TypeName* y = src;
  const TypeName* end = src + len;
  for (i = 0; i < chunks; ++i, y += 4) {
    _0 = static_cast<uint8_t>(y[0]);
    _1 = static_cast<uint8_t>(y[1]);
    _2 = static_cast<uint8_t>(y[2]);
    _3 = static_cast<uint8_t>(y[3]);

    x = d0[_0] | d1[_1] | d2[_2] | d3[_3];
    if (x >= BADCHAR) {
      if (!strict) {
        if (!base64_decode_group_slow())
      } else {
        return MODP_B64_ERROR;
      }
    }

    *p++ = ((uint8_t*)(&x))[0];
    *p++ = ((uint8_t*)(&x))[1];
    *p++ = ((uint8_t*)(&x))[2];
  }

  switch (leftover) {
    case 0:
      x = d0[static_cast<uint8_t>(y[0])] | d1[static_cast<uint8_t>(y[1])] |
          d2[static_cast<uint8_t>(y[2])] | d3[static_cast<uint8_t>(y[3])];

      if (x >= BADCHAR) {
        if (!strict) {
          int how_many_p;
          x = b64_ignore_space(&y, end, &how_many_p);
          if (x >= BADCHAR) return MODP_B64_ERROR;
          for (int j = 0; j < how_many_p; j++) {
            *p++ = ((uint8_t*)(&x))[j];
          }
          return chunks * 3 + (6 * how_many_p) / 8;
        } else {
          return MODP_B64_ERROR;
        }
      }

      *p++ = ((uint8_t*)(&x))[0];
      *p++ = ((uint8_t*)(&x))[1];
      *p = ((uint8_t*)(&x))[2];
      return (chunks + 1) * 3;

    case 1: /* with padding this is an impossible case */
      x = d0[static_cast<uint8_t>(y[0])];
      *p = *((uint8_t*)(&x));  // i.e. first char/byte in int
      break;

    case 2:  // * case 2, 1  output byte */
      x = d0[static_cast<uint8_t>(y[0])] | d1[static_cast<uint8_t>(y[1])];
      *p = *((uint8_t*)(&x));  // i.e. first char
      break;

    default: /* case 3, 2 output bytes */
      x = d0[static_cast<uint8_t>(y[0])] | d1[static_cast<uint8_t>(y[1])] |
          d2[static_cast<uint8_t>(y[2])]; /* 0x3c */
      *p++ = ((uint8_t*)(&x))[0];
      *p = ((uint8_t*)(&x))[1];
      break;
  }

  if (x >= BADCHAR) {
    if (!strict) {
      int how_many_p;
      x = b64_ignore_space(&y, end, &how_many_p);
      if (x >= BADCHAR) return MODP_B64_ERROR;
      for (int j = 0; j < how_many_p; j++) {
        *p++ = ((uint8_t*)(&x))[j];
      }
      return chunks * 3 + (6 * how_many_p) / 8;
    } else {
      return MODP_B64_ERROR;
    }
  }

  return 3 * chunks + (6 * leftover) / 8;
}

inline size_t modp_b64_encode(char* dest,
                              const char* str,
                              size_t len,
                              const char e0[],
                              const char e1[],
                              const char e2[],
                              bool do_pad) {
  size_t i = 0;
  uint8_t* p = (uint8_t*)dest;

  /* unsigned here is important! */
  uint8_t t1, t2, t3;

  if (len > 2) {
    for (; i < len - 2; i += 3) {
      t1 = str[i];
      t2 = str[i + 1];
      t3 = str[i + 2];
      *p++ = e0[t1];
      *p++ = e1[((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F)];
      *p++ = e1[((t2 & 0x0F) << 2) | ((t3 >> 6) & 0x03)];
      *p++ = e2[t3];
    }
  }

  switch (len - i) {
    case 0:
      break;
    case 1:
      t1 = str[i];
      *p++ = e0[t1];
      *p++ = e1[(t1 & 0x03) << 4];

      if (do_pad) {
        *p++ = CHARPAD;
        *p++ = CHARPAD;
      }

      break;
    default: /* case 2 */
      t1 = str[i];
      t2 = str[i + 1];
      *p++ = e0[t1];
      *p++ = e1[((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F)];
      *p++ = e2[(t2 & 0x0F) << 2];

      if (do_pad) {
        *p++ = CHARPAD;
      }
  }

  *p = '\0';
  return p - (uint8_t*)dest;
}

template <typename TypeName>
size_t base64_decode(char* const dst,
                     const size_t dstlen,
                     const TypeName* const src,
                     const size_t srclen) {
  int retlen = modp_b64_decode(dst, src, srclen);
  return retlen < 0 ? 0 : retlen;
}

inline size_t base64_encode(
    const char* src, size_t slen, char* dst, size_t dlen, Base64Mode mode) {
  if (mode == Base64Mode::kNormal) {
    CHECK(dlen >= modp_b64_encode_len(slen) &&
          "not enough space provided for base64 encode");
    dlen =
        modp_b64_encode(dst, src, slen, normal_e0, normal_e1, normal_e2, true);
  } else {
    CHECK(dlen >= modp_b64_encode_len_without_pad(slen) &&
          "not enough space provided for base64 encode");
    dlen = modp_b64_encode(dst, src, slen, url_e0, url_e1, url_e2, false);
  }

  return dlen;
}

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_BASE64_INL_H_
