#!/bin/bash -e

export PATH=/usr/lib/llvm-7/bin:$PATH
# Commenting following lines due to build issues using envoy-build-ubuntu image
# Defaulting to gcc
#export CC=clang
#export CXX=clang++
export ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-7/bin/llvm-symbolizer
echo "$CC/$CXX toolchain configured"

if [[ -f "${HOME:-/root}/.gitconfig" ]]; then
    mv "${HOME:-/root}/.gitconfig" "${HOME:-/root}/.gitconfig_save"
fi

function do_build () {
    bazel build -s --verbose_failures=true //:envoy
    cp bazel-bin/envoy /build/envoy
}

function do_release_build () {
    bazel build -s --verbose_failures=true -c opt //:envoy
    cp bazel-bin/envoy /build/envoy
}

function do_test() {
    bazel test --test_output=all --test_env=ENVOY_IP_TEST_VERSIONS=v4only \
      //:echo2_integration_test
}

case "$1" in
  build)
    do_build
  ;;
  release-build)
    do_release_build
  ;;
  test)
    do_test
  ;;
  *)
    echo "must be one of [build,test]"
    exit 1
  ;;
esac
