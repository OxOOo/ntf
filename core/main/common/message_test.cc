#include "main/common/message.h"

#include "absl/strings/str_cat.h"
#include "gtest/gtest.h"
#include "main/proto/message.pb.h"
#include "utils/testing.h"

namespace common {
namespace message {
namespace {

using ::utils::testing::IsOkAndHolds;
using ::utils::testing::StatusIs;

TEST(SerializeAndParse, SerializeAndParse) {
    proto::Ping ping;
    ping.set_message("hello world");
    proto::Content content;
    *content.mutable_ping() = ping;

    auto data = Serialize("id", "key", content);
    EXPECT_OK(data);

    auto id = TryParseID(*data);
    EXPECT_OK(id);
    EXPECT_TRUE(id->has_value());
    EXPECT_EQ(**id, "id");

    auto decrypt = TryParse("id", "key", *data, NULL);
    EXPECT_OK(decrypt);
    EXPECT_TRUE(decrypt->has_value());
    EXPECT_EQ((**decrypt).ping().message(), "hello world");
}

TEST(SerializeAndParse, NoEnoughData) {
    proto::Ping ping;
    ping.set_message("hello world");
    proto::Content content;
    *content.mutable_ping() = ping;

    auto data = Serialize("id", "key", content);
    EXPECT_OK(data);

    absl::string_view data_view = *data;
    data_view.remove_suffix(1);

    auto decrypt = TryParse("id", "key", data_view, NULL);
    EXPECT_OK(decrypt);
    EXPECT_FALSE(decrypt->has_value());
}

TEST(SerializeAndParse, MultiData) {
    std::string data;

    for (int i = 0; i < 10; i++) {
        proto::Ping ping;
        ping.set_message(absl::StrCat("hello world", i));
        proto::Content content;
        *content.mutable_ping() = ping;

        auto piece_data = Serialize("id", "key", content);
        EXPECT_OK(piece_data);
        absl::StrAppend(&data, *piece_data);
    }
    absl::string_view data_view = data;

    for (int i = 0; i < 10; i++) {
        uint64_t consumed_length = 0;
        auto decrypt = TryParse("id", "key", data_view, &consumed_length);
        EXPECT_OK(decrypt);
        EXPECT_TRUE(decrypt->has_value());
        EXPECT_EQ((**decrypt).ping().message(), absl::StrCat("hello world", i));
        data_view.remove_prefix(consumed_length);
    }
}

TEST(SerializeAndParse, WrongKey) {
    proto::Ping ping;
    ping.set_message("hello world");
    proto::Content content;
    *content.mutable_ping() = ping;

    auto data = Serialize("id", "key", content);
    EXPECT_OK(data);

    auto decrypt = TryParse("id", "key2", *data, NULL);
    EXPECT_THAT(decrypt, StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace message
}  // namespace common
