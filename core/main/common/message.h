#ifndef MAIN_COMMON_MESSAGE_H_
#define MAIN_COMMON_MESSAGE_H_

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "main/proto/message.pb.h"

namespace common {
namespace message {

// Serializes the content to a string.
// `key` can be any-length-string.
absl::StatusOr<std::string> Serialize(absl::string_view id,
                                      absl::string_view key,
                                      const proto::Content& content);

// Try to parse id from `data`;
absl::StatusOr<absl::optional<std::string>> TryParseID(absl::string_view data);

// Try to parse a content from `data`.
// `id` and `key` should be same as `Serialize`.
// Will return empty if the `data` does not have enough data.
// Will return error if parse error or auth failed.
// If parsed a content from data, `consumed_length` will be filled as the
// number of the bytes consumed in `data`.
absl::StatusOr<absl::optional<proto::Content>> TryParse(
    absl::string_view id, absl::string_view key, absl::string_view data,
    uint64_t* consumed_length);

}  // namespace message
}  // namespace common

#endif  // MAIN_COMMON_MESSAGE_H_