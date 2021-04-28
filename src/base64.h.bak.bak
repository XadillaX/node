#ifndef SRC_BASE64_H_
#define SRC_BASE64_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "util.h"

#include <cmath>
#include <cstddef>
#include <cstdint>

namespace node {
enum class Base64Mode { kNormal, kURL };

/**
 * Code with prefix `modp_b64` is extracted from Chromium's modp_b64 and do some
 * modifing to adapt Node.js' source code.
 *
 * MODP_B64 - High performance base64 encoder/decoder
 */
inline size_t modp_b64_encode(char* dest,
                              const char* str,
                              size_t len,
                              const char e0[],
                              const char e1[],
                              const char e2[],
                              bool do_pad);
template <typename TypeName>
inline size_t modp_b64_decode(char* dest, const TypeName* src, size_t len, bool strict = false);

#define modp_b64_encode_len(A) ((A + 2) / 3 * 4 + 1)
#define modp_b64_encode_strlen(A) ((A + 2) / 3 * 4)
#define modp_b64_encode_len_without_pad(A)                                     \
  (modp_b64_encode_strlen_without_pad(A) + 1)
#define modp_b64_encode_strlen_without_pad(A)                                  \
  (size_t)(std::ceil((double)(A * 4) / 3))
#define modp_b64_decode_len(A) (A > 1 ? (A / 4 * 3 + 2) : 0)
#define MODP_B64_ERROR ((size_t)-1)

template <typename TypeName>
size_t base64_decode(char* const dst,
                     const size_t dstlen,
                     const TypeName* const src,
                     const size_t srclen);

inline size_t base64_encode(const char* src,
                            size_t slen,
                            char* dst,
                            size_t dlen,
                            Base64Mode mode = Base64Mode::kNormal);
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_BASE64_H_
