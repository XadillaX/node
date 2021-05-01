#ifndef SRC_BASE64_H_
#define SRC_BASE64_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "util.h"

#include <cmath>
#include <cstddef>
#include <cstdint>

namespace node {

enum class Base64Mode {
  kNormal,
  kUrl,
};

/**
 * These two functions are inspired from modp_b64
 * Refs:
 * https://github.com/chromium/chromium/blob/92.0.4491.1/third_party/modp_b64
 */
inline size_t b64_encode(char* dest,
                         const char* str,
                         size_t len,
                         Base64Mode mode = Base64Mode::kNormal);
inline size_t b64_decode(char* dest,
                         size_t destlen,
                         const char* src,
                         size_t len,
                         bool strict = false);

#define b64_encode_len(A) ((A + 2) / 3 * 4 + 1)
#define b64_decode_len(A) (A / 4 * 3 + 2)
#define b64_encode_strlen(A) ((A + 2) / 3 * 4)
#define B64_ERROR ((size_t)-1)

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_BASE64_H_
