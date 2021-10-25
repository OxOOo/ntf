#ifndef MAIN_COMMON_CRYPTO_H_
#define MAIN_COMMON_CRYPTO_H_

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace common {
namespace crypto {

// Returns a 32-length upper md5 hashed value.
std::string Md5(absl::string_view data);

// Returns a 64-length upper sha256 hashed value.
std::string Sha256(absl::string_view data);

// Encrypts `plain_data` using aes-256-cbc method, `key` and `iv` should be
// 256-bit size.
absl::StatusOr<std::string> AesEncrypt(absl::string_view plain_data,
                                       absl::string_view key,
                                       absl::string_view iv);

// Decrypts `encrypted_data` using aes-256-cbc method, `key` and `iv` should be
// 256-bit size.
absl::StatusOr<std::string> AesDecrypt(absl::string_view encrypted_data,
                                       absl::string_view key,
                                       absl::string_view iv);

// Returns a 64-length upper sha256 hmac value.
absl::StatusOr<std::string> Sha256Hmac(absl::string_view plain_data,
                                       absl::string_view key);

}  // namespace crypto
}  // namespace common

#endif  // MAIN_COMMON_CRYPTO_H_