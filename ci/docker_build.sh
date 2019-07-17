#!/bin/sh

set -ex

mkdir -p build_release_stripped
strip bazel-bin/envoy -o build_release_stripped/envoy
docker build -f ci/Dockerfile-envoy-image -t envoy:latest .
