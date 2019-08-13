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
        "@tspi//:lib"
    ],
)

envoy_cc_library(
    name = "pkm_provider",
    srcs = ["pkm_provider.cc", "pkm_provider_tss.cc", "tpm/tpm_key.cc", "tpm/tpm_privkey_operator.cc", "tpm/tpm_error.cc", "util.cc"],
    hdrs = ["pkm_provider.h", "pkm_provider_tss.h", "tpm/tpm_key.h", "tpm/tpm_privkey_operator.h", "tpm/tpm_error.h", "util.h"],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/server:transport_socket_config_interface",
        "@envoy//include/envoy/ssl:tls_certificate_config_interface",
        "@envoy//include/envoy/ssl/private_key:private_key_config_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
    ],
    copts = ["-fpermissive", "-Wno-error"]
)



sh_test(
    name = "envoy_binary_test",
    srcs = ["envoy_binary_test.sh"],
    data = [":envoy"],
)
