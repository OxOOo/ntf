#include "main/common/crypto.h"

#include "gtest/gtest.h"
#include "utils/testing.h"

namespace common {
namespace crypto {
namespace {

using ::utils::testing::IsOkAndHolds;
using ::utils::testing::StatusIs;

TEST(Md5, EmptyInput) {
    EXPECT_EQ(Md5(""), "D41D8CD98F00B204E9800998ECF8427E");
}

TEST(Md5, HashHelloWorld) {
    EXPECT_EQ(Md5("hello world"), "5EB63BBBE01EEED093CB22BB8F5ACDC3");
}

TEST(Sha256, EmptyInput) {
    EXPECT_EQ(
        Sha256(""),
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
}

TEST(Sha256, HashHelloWorld) {
    EXPECT_EQ(
        Sha256("hello world"),
        "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9");
}

TEST(AES, WrongKey) {
    EXPECT_THAT(
        AesEncrypt("", "123412341234123", "12341234123412341234123412341234"),
        StatusIs(absl::StatusCode::kInvalidArgument));
    EXPECT_THAT(
        AesDecrypt("", "123412341234123", "12341234123412341234123412341234"),
        StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AES, WrongIv) {
    EXPECT_THAT(
        AesEncrypt("", "12341234123412341234123412341234", "123412341234123"),
        StatusIs(absl::StatusCode::kInvalidArgument));
    EXPECT_THAT(
        AesDecrypt("", "12341234123412341234123412341234", "123412341234123"),
        StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AES, AES) {
    constexpr absl::string_view message = "hello world";
    constexpr absl::string_view key1 = "12341234123412341234123412341234";
    constexpr absl::string_view iv1 = "12341234123412341234123412341234";
    constexpr absl::string_view key2 = "123412341234123412341234123412ff";
    constexpr absl::string_view iv2 = "ff341234123412341234123412341234";

    auto encrypt1 = AesEncrypt(message, key1, iv1);
    EXPECT_OK(encrypt1);
    EXPECT_THAT(AesDecrypt(*encrypt1, key1, iv1), IsOkAndHolds(message));

    auto encrypt2 = AesEncrypt(message, key1, iv2);
    EXPECT_OK(encrypt2);
    EXPECT_THAT(AesDecrypt(*encrypt2, key1, iv2), IsOkAndHolds(message));

    auto encrypt3 = AesEncrypt(message, key2, iv1);
    EXPECT_OK(encrypt3);
    EXPECT_THAT(AesDecrypt(*encrypt3, key2, iv1), IsOkAndHolds(message));

    auto encrypt4 = AesEncrypt(message, key2, iv2);
    EXPECT_OK(encrypt4);
    EXPECT_THAT(AesDecrypt(*encrypt4, key2, iv2), IsOkAndHolds(message));

    EXPECT_NE(*encrypt1, *encrypt2);
    EXPECT_NE(*encrypt1, *encrypt3);
    EXPECT_NE(*encrypt1, *encrypt4);
    EXPECT_NE(*encrypt2, *encrypt3);
    EXPECT_NE(*encrypt2, *encrypt4);
    EXPECT_NE(*encrypt3, *encrypt4);
}

TEST(Sha256Hmac, Sha256Hmac) {
    EXPECT_THAT(Sha256Hmac("hello world", "key1"),
                IsOkAndHolds("59373F076F0B856D2F9279F1B94B734E14AC824419C382B30"
                             "3F1059E6141BAB2"));
    EXPECT_THAT(Sha256Hmac("hello world2", "key1"),
                IsOkAndHolds("EEF854AB2BD146806D00BF7C0141FDBD121C89808ABE35E50"
                             "D98C3F8F2519335"));
    EXPECT_THAT(
        Sha256Hmac(
            "hello world",
            "1234567812345678123456781234567812345678123456781234567812345678"),
        IsOkAndHolds("12343ACCEA967933FC1ADA0F73723605F8A2BC99A06C9A508A420316E"
                     "64715AE"));
    EXPECT_THAT(
        Sha256Hmac(
            "hello world",
            "1234567812345678123456781234567812345678123456781234567812345670"),
        IsOkAndHolds("DDA3F5E3E1F775743CC5DA3915B6E137976B03576EF9B399846E8E49A"
                     "EFB9C9E"));
}

}  // namespace
}  // namespace crypto
}  // namespace common
