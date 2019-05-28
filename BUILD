package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":pkm_provider",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_cc_library(
    name = "pkm_provider",
    srcs = ["pkm_provider.cc"],
    hdrs = ["pkm_provider.h"],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/server:transport_socket_config_interface",
        "@envoy//include/envoy/ssl:tls_certificate_config_interface",
        "@envoy//include/envoy/ssl/private_key:private_key_config_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
    ],
)

sh_test(
    name = "envoy_binary_test",
    srcs = ["envoy_binary_test.sh"],
    data = [":envoy"],
)
