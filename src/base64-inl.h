#ifndef SRC_BASE64_INL_H_
#define SRC_BASE64_INL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "base64.h"
#include "base64_data.h"

namespace node {

#define BADCHAR 0x01FFFFFF
extern const int8_t unbase64_table[256];

inline static int8_t unbase64(uint8_t x) {
  return unbase64_table[x];
}

inline size_t b64_encode(char* dest,
                         const char* str,
                         size_t len,
                         Base64Mode mode) {
  size_t i = 0;
  uint8_t* p = (uint8_t*)dest;
  const char* e0;
  const char* e1;
  const char* e2;
  char pad;
  if (mode == Base64Mode::kNormal) {
    e0 = normal_e0;
    e1 = normal_e1;
    e2 = normal_e2;
    pad = CHARPAD;
  } else {
    e0 = url_e0;
    e1 = url_e1;
    e2 = url_e2;
    pad = 0;
  }

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
      *p++ = pad;
      *p++ = pad;
      break;
    default: /* case 2 */
      t1 = str[i];
      t2 = str[i + 1];
      *p++ = e0[t1];
      *p++ = e1[((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F)];
      *p++ = e2[(t2 & 0x0F) << 2];
      *p++ = pad;
  }

  *p = '\0';
  return p - (uint8_t*)dest;
}

inline size_t b64_decode_with_invalid(const uint8_t** y,
                                      const uint8_t* end,
                                      int* avail,
                                      bool* stopped,
                                      int* leftover) {
  *stopped = false;
  uint8_t group[] = {0, 0, 0, 0};
  *avail = 0;
  uint8_t temp;
  for (int i = 0; i < 4 && *y < end && !stopped; i++) {
    for (; *y < end; (*y)++) {
      temp = unbase64(**y);
      if (temp < 64) {
        (*leftover)--;
        if (*leftover < 0) *leftover = 3;
        continue;
      } else if (**y == '=') {
        *stopped = true;
        break;
      }

      group[i] = **y;
      (*y)++;
      *avail = i + 1;
      break;
    }
  }

  if (*y >= end) *stopped = true;

  return d0[group[0]] | d1[group[1]] | d2[group[2]] | d3[group[3]];
}

#define CHECK_BADCHAR(x, expr)                                                 \
  if (x >= BADCHAR) {                                                          \
    if (strict) return B64_ERROR;                                              \
                                                                               \
    x = b64_decode_with_invalid(&y, end, &avail, &stopped, &leftover);         \
    switch (avail) {                                                           \
      case 4:                                                                  \
        *p++ = ((uint8_t*)(&x))[0];                                            \
        *p++ = ((uint8_t*)(&x))[1];                                            \
        *p++ = ((uint8_t*)(&x))[2];                                            \
        break;                                                                 \
      case 3:                                                                  \
        *p++ = ((uint8_t*)(&x))[0];                                            \
        *p++ = ((uint8_t*)(&x))[1];                                            \
        break;                                                                 \
      case 2:                                                                  \
      case 1:                                                                  \
        *p++ = *((uint8_t*)(&x));                                              \
        break;                                                                 \
    }                                                                          \
                                                                               \
    if (avail < 4 || stopped) {                                                \
      return (i * 3) + avail <= 1 ? avail : (avail - 1);                       \
    }                                                                          \
                                                                               \
    expr;                                                                      \
  }

inline size_t b64_decode(char* dest, const char* src, size_t len, bool strict) {
  if (len == 0) return 0;

  if (src[len - 1] == CHARPAD && (len < 4 || (len % 4 != 0)))
    return B64_ERROR; /* error */

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
  const uint8_t* y = (uint8_t*)src;
  const uint8_t* end = y + len;
  bool stopped;
  int avail;
  for (i = 0; i < chunks && end - y >= 3; ++i, y += 4) {
    x = d0[y[0]] | d1[y[1]] | d2[y[2]] | d3[y[3]];
    CHECK_BADCHAR(x, continue);
    *p++ = ((uint8_t*)(&x))[0];
    *p++ = ((uint8_t*)(&x))[1];
    *p++ = ((uint8_t*)(&x))[2];
  }

  chunks = i;
  switch (leftover) {
    case 0:
      x = d0[y[0]] | d1[y[1]] | d2[y[2]] | d3[y[3]];
      CHECK_BADCHAR(x, break);

      *p++ = ((uint8_t*)(&x))[0];
      *p++ = ((uint8_t*)(&x))[1];
      *p = ((uint8_t*)(&x))[2];
      return (chunks + 1) * 3;
      break;
  }

  switch (leftover) {
    case 0:
      x = d0[y[0]] | d1[y[1]] | d2[y[2]] | d3[y[3]];
      CHECK_BADCHAR(x, break);

      *p++ = ((uint8_t*)(&x))[0];
      *p++ = ((uint8_t*)(&x))[1];
      *p = ((uint8_t*)(&x))[2];
      return (chunks + 1) * 3;
      break;

    case 1: /* with padding this is an impossible case */
      x = d0[y[0]];
      if (x == BADCHAR) return 3 * chunks;

      *p = *((uint8_t*)(&x));  // i.e. first char/byte in int
      break;

    case 2:  // * case 2, 1  output byte */
      x = d0[y[0]] | d1[y[1]];
      CHECK_BADCHAR(x, break);
      *p = *((uint8_t*)(&x));  // i.e. first char
      break;

    default:                              /* case 3, 2 output bytes */
      x = d0[y[0]] | d1[y[1]] | d2[y[2]]; /* 0x3c */
      CHECK_BADCHAR(x, break);
      *p++ = ((uint8_t*)(&x))[0];
      *p = ((uint8_t*)(&x))[1];
      break;
  }

  if (x >= BADCHAR) return B64_ERROR;

  return 3 * chunks + (6 * leftover) / 8;
}

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_BASE64_INL_H_
