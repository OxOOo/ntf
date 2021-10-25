cc_binary(
    name = "server",
    srcs = ["server.cc"],
    deps = [
        "//main/common:message",
        "//main/common:thread_manager",
        "//main/proto:message_cc_proto",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_glog//:glog",
        "@nlohmann_json//:json",
        "@toolbase//file:epoll",
        "@toolbase//file:filesystem",
        "@toolbase//net",
        "@toolbase//utils:status_macros",
    ],
)

cc_binary(
    name = "client",
    srcs = ["client.cc"],
    deps = [
        "//main/common:message",
        "//main/common:thread_manager",
        "//main/proto:message_cc_proto",
        "@com_google_glog//:glog",
        "@toolbase//file:epoll",
        "@toolbase//file:filesystem",
        "@toolbase//net",
        "@toolbase//utils:status_macros",
    ],
)
