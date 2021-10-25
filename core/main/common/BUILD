package(default_visibility = ["//visibility:public"])

cc_library(
    name = "thread_manager",
    srcs = ["thread_manager.cc"],
    hdrs = ["thread_manager.h"],
    linkopts = ["-lpthread"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_glog//:glog",
    ],
)

cc_test(
    name = "thread_manager_test",
    srcs = ["thread_manager_test.cc"],
    deps = [
        ":thread_manager",
        "@com_google_googletest//:gtest_main",
        "@toolbase//utils:testing",
    ],
)

cc_library(
    name = "crypto",
    srcs = ["crypto.cc"],
    hdrs = ["crypto.h"],
    linkopts = [
        "-lssl",
        "-lcrypto",
    ],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "crypto_test",
    srcs = ["crypto_test.cc"],
    deps = [
        ":crypto",
        "@com_google_googletest//:gtest_main",
        "@toolbase//utils:testing",
    ],
)

cc_library(
    name = "message",
    srcs = ["message.cc"],
    hdrs = ["message.h"],
    deps = [
        ":crypto",
        "//main/proto:message_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
        "@toolbase//utils:status_macros",
    ],
)

cc_test(
    name = "message_test",
    srcs = ["message_test.cc"],
    deps = [
        ":message",
        "@com_google_googletest//:gtest_main",
        "@toolbase//utils:testing",
    ],
)
