#include "main/common/message.h"

#include <arpa/inet.h>

#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/time/time.h"
#include "main/common/crypto.h"
#include "utils/status_macros.h"

namespace common {
namespace message {

absl::StatusOr<std::string> Serialize(absl::string_view id,
                                      absl::string_view key,
                                      const proto::Content& content) {
    std::string key_md5 = common::crypto::Md5(key);

    std::string content_plain;
    if (!content.SerializeToString(&content_plain)) {
        return absl::InternalError("Content::SerializeToString failed");
    }
    ASSIGN_OR_RETURN(
        std::string content_encrypted,
        common::crypto::AesEncrypt(content_plain, key_md5, key_md5));
    ASSIGN_OR_RETURN(std::string encrypted_content_hmac,
                     common::crypto::Sha256Hmac(content_encrypted, key));

    proto::Header header;
    header.set_time_second(absl::ToUnixSeconds(absl::Now()));
    header.set_encrypted_content_size(content_encrypted.length());
    header.set_encrypted_content_hmac(encrypted_content_hmac);

    std::string header_plain;
    if (!header.SerializeToString(&header_plain)) {
        return absl::InternalError("Header::SerializeToString failed");
    }
    ASSIGN_OR_RETURN(std::string header_hmac,
                     common::crypto::Sha256Hmac(header_plain, key));

    uint32_t header_length = htonl(header_plain.length());

    uint32_t id_length = htonl(id.length());

    return absl::StrCat(
        absl::string_view((const char*)&id_length, sizeof(id_length)), id,
        absl::string_view((const char*)&header_length, sizeof(header_length)),
        header_hmac, header_plain, content_encrypted);
}

absl::StatusOr<absl::optional<std::string>> TryParseID(absl::string_view data) {
    uint64_t pos = 0;

    uint32_t id_length = 0;
    if (data.length() < pos + sizeof(id_length)) {
        return absl::nullopt;
    }
    id_length = ntohl(*(const uint32_t*)(data.data() + pos));
    pos += sizeof(id_length);

    if (id_length > (1 << 10)) {
        return absl::InternalError(
            absl::StrFormat("ID length = %d is too large", id_length));
    }

    if (data.length() < pos + id_length) {
        return absl::nullopt;
    }
    return std::string(data.substr(pos, id_length));
}

absl::StatusOr<absl::optional<proto::Content>> TryParse(
    absl::string_view id, absl::string_view key, absl::string_view data,
    uint64_t* consumed_length) {
    std::string key_md5 = common::crypto::Md5(key);

    uint64_t pos = 0;

    uint32_t id_length = 0;
    if (data.length() < pos + sizeof(id_length)) {
        return absl::nullopt;
    }
    id_length = ntohl(*(const uint32_t*)(data.data() + pos));
    pos += sizeof(id_length);

    if (id_length > (1 << 10)) {
        return absl::InternalError(
            absl::StrFormat("ID length = %d is too large", id_length));
    }

    if (data.length() < pos + id_length) {
        return absl::nullopt;
    }
    if (id != data.substr(pos, id_length)) {
        return absl::InternalError("ID missmatch");
    }
    pos += id_length;

    uint32_t header_length = 0;
    if (data.length() < pos + sizeof(header_length)) {
        return absl::nullopt;
    }
    header_length = ntohl(*(const uint32_t*)(data.data() + pos));
    pos += sizeof(header_length);

    if (header_length > (1 << 20)) {
        return absl::InternalError(
            absl::StrFormat("Header length = %d is too large", header_length));
    }

    if (data.length() < pos + 64) {
        return absl::nullopt;
    }
    absl::string_view header_hmac = data.substr(pos, 64);
    pos += 64;

    if (data.length() < pos + header_length) {
        return absl::nullopt;
    }
    absl::string_view header_plain = data.substr(pos, header_length);
    pos += header_length;
    ASSIGN_OR_RETURN(std::string expected_header_hmac,
                     common::crypto::Sha256Hmac(header_plain, key));

    if (header_hmac != expected_header_hmac) {
        return absl::InternalError(
            absl::StrFormat("Wrong header hmac : expected `%s` vs given `%s`",
                            expected_header_hmac, header_hmac));
    }

    proto::Header header;
    if (!header.ParseFromString(std::string(header_plain))) {
        return absl::InternalError("Header::ParseFromString failed");
    }

    if (abs(header.time_second() - absl::ToUnixSeconds(absl::Now())) > 60) {
        return absl::InternalError("Wrong time");
    }

    uint64_t encrypted_content_size = header.encrypted_content_size();
    if (data.length() < pos + encrypted_content_size) {
        return absl::nullopt;
    }
    absl::string_view encrypted_content =
        data.substr(pos, encrypted_content_size);
    pos += encrypted_content_size;

    ASSIGN_OR_RETURN(std::string content_hmac,
                     common::crypto::Sha256Hmac(encrypted_content, key));
    if (header.encrypted_content_hmac() != content_hmac) {
        return absl::InternalError("Wrong content hmac");
    }

    ASSIGN_OR_RETURN(
        auto plain_content,
        common::crypto::AesDecrypt(encrypted_content, key_md5, key_md5));

    proto::Content content;
    if (!content.ParseFromString(plain_content)) {
        return absl::InternalError("Content::ParseFromString failed");
    }

    if (consumed_length) {
        *consumed_length = pos;
    }

    return content;
}

}  // namespace message
}  // namespace common