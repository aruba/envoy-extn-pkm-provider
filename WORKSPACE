workspace(name = "envoy_filter_example")

local_repository(
    name = "envoy",
    path = "envoy",
)

new_local_repository(
    name = "tspi",
    path = "/usr/lib/x86_64-linux-gnu",
    build_file = "tspi.BUILD"
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()
