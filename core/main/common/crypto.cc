#include "main/common/crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <functional>

#include "absl/strings/str_format.h"

namespace common {
namespace crypto {
namespace {

constexpr char kHexUpper[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

class CallOnDestruct {
   public:
    CallOnDestruct(std::function<void()> func) : func_(std::move(func)) {}
    ~CallOnDestruct() { func_(); }

   private:
    std::function<void()> func_;
};
}  // namespace

std::string Md5(absl::string_view data) {
    unsigned char md[MD5_DIGEST_LENGTH];
    ::MD5((const unsigned char*)data.data(), data.length(), md);

    std::string result;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        result.push_back(kHexUpper[md[i] >> 4]);
        result.push_back(kHexUpper[md[i] & 0xF]);
    }

    return result;
}

std::string Sha256(absl::string_view data) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    ::SHA256((const unsigned char*)data.data(), data.length(), md);

    std::string result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result.push_back(kHexUpper[md[i] >> 4]);
        result.push_back(kHexUpper[md[i] & 0xF]);
    }

    return result;
}

absl::StatusOr<std::string> AesEncrypt(absl::string_view plain_data,
                                       absl::string_view key,
                                       absl::string_view iv) {
    if (key.length() != 32) {
        return absl::InvalidArgumentError(
            absl::StrFormat("key.length = %d which is not 32", key.length()));
    }
    if (iv.length() != 32) {
        return absl::InvalidArgumentError(
            absl::StrFormat("iv.length = %d which is not 32", iv.length()));
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    CallOnDestruct ctx_auto_free([ctx]() { EVP_CIPHER_CTX_free(ctx); });

    int ret = -1;

    ret = EVP_EncryptInit(ctx, EVP_aes_256_cbc(),
                          (const unsigned char*)key.data(),
                          (const unsigned char*)iv.data());
    if (ret != 1) {
        return absl::InternalError(
            absl::StrFormat("EVP_EncryptInit returns error ret = %d", ret));
    }

    const int block_size = EVP_CIPHER_CTX_block_size(ctx);
    uint8_t* out_data = new uint8_t[plain_data.length() + block_size];
    size_t out_size = 0;
    CallOnDestruct out_data_auto_free([out_data]() { delete[] out_data; });

    size_t pos = 0;
    while (pos < plain_data.length()) {
        const int batch_size = std::min(1024UL, plain_data.length() - pos);
        int this_out_size = 0;
        ret = EVP_EncryptUpdate(ctx, out_data + out_size, &this_out_size,
                                (const unsigned char*)plain_data.data() + pos,
                                batch_size);
        if (ret != 1) {
            return absl::InternalError(absl::StrFormat(
                "EVP_EncryptUpdate returns error ret = %d", ret));
        }
        out_size += this_out_size;
        pos += batch_size;
    }

    int final_out_size = 0;
    ret = EVP_EncryptFinal(ctx, out_data + out_size, &final_out_size);
    if (ret != 1) {
        return absl::InternalError(
            absl::StrFormat("EVP_EncryptFinal returns error ret = %d", ret));
    }
    out_size += final_out_size;

    return std::string((const char*)out_data, out_size);
}

absl::StatusOr<std::string> AesDecrypt(absl::string_view encrypted_data,
                                       absl::string_view key,
                                       absl::string_view iv) {
    if (key.length() != 32) {
        return absl::InvalidArgumentError(
            absl::StrFormat("key.length = %d which is not 32", key.length()));
    }
    if (iv.length() != 32) {
        return absl::InvalidArgumentError(
            absl::StrFormat("iv.length = %d which is not 32", iv.length()));
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    CallOnDestruct ctx_auto_free([ctx]() { EVP_CIPHER_CTX_free(ctx); });

    int ret = -1;

    ret = EVP_DecryptInit(ctx, EVP_aes_256_cbc(),
                          (const unsigned char*)key.data(),
                          (const unsigned char*)iv.data());
    if (ret != 1) {
        return absl::InternalError(
            absl::StrFormat("EVP_DecryptInit returns error ret = %d", ret));
    }

    const int block_size = EVP_CIPHER_CTX_block_size(ctx);
    uint8_t* out_data = new uint8_t[encrypted_data.length() + block_size];
    size_t out_size = 0;
    CallOnDestruct out_data_auto_free([out_data]() { delete[] out_data; });

    size_t pos = 0;
    while (pos < encrypted_data.length()) {
        const int batch_size = std::min(1024UL, encrypted_data.length() - pos);
        int this_out_size = 0;
        ret = EVP_DecryptUpdate(
            ctx, out_data + out_size, &this_out_size,
            (const unsigned char*)encrypted_data.data() + pos, batch_size);
        if (ret != 1) {
            return absl::InternalError(absl::StrFormat(
                "EVP_DecryptUpdate returns error ret = %d", ret));
        }
        out_size += this_out_size;
        pos += batch_size;
    }

    int final_out_size = 0;
    ret = EVP_DecryptFinal(ctx, out_data + out_size, &final_out_size);
    if (ret != 1) {
        return absl::InternalError(
            absl::StrFormat("EVP_DecryptFinal returns error ret = %d", ret));
    }
    out_size += final_out_size;

    return std::string((const char*)out_data, out_size);
}

absl::StatusOr<std::string> Sha256Hmac(absl::string_view plain_data,
                                       absl::string_view key) {
    HMAC_CTX* ctx = HMAC_CTX_new();
    CallOnDestruct ctx_auto_free([ctx]() { HMAC_CTX_free(ctx); });

    int ret = -1;

    ret = HMAC_Init_ex(ctx, key.data(), key.length(), EVP_sha256(), NULL);
    if (ret != 1) {
        return absl::InternalError(
            absl::StrFormat("HMAC_Init_ex returns error ret = %d", ret));
    }

    ret = HMAC_Update(ctx, (const unsigned char*)plain_data.data(),
                      plain_data.length());
    if (ret != 1) {
        return absl::InternalError(
            absl::StrFormat("HMAC_Update returns error ret = %d", ret));
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = EVP_MAX_MD_SIZE;
    ret = HMAC_Final(ctx, md, &md_len);
    if (ret != 1) {
        return absl::InternalError(
            absl::StrFormat("HMAC_Final returns error ret = %d", ret));
    }

    std::string result;
    for (int i = 0; i < (int)md_len; i++) {
        result.push_back(kHexUpper[md[i] >> 4]);
        result.push_back(kHexUpper[md[i] & 0xF]);
    }
    return result;
}

}  // namespace crypto
}  // namespace common
