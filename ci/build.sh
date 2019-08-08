#!/bin/bash
set -ex

SCRIPTDIR=$(dirname $0)

# first build the build image
cd ${SCRIPTDIR} && docker build -t envoyproxy/envoy-build-ubuntu:local -f Dockerfile-build-image . && cd -

# build envoy using this image
ENVOY_DOCKER_BUILD_DIR=$(pwd)/build IMAGE_ID=local envoy/ci/run_envoy_docker.sh './ci/do_ci.sh release-build'

# envoy is in build folder, let's build the envoy docker image
mkdir -p build_release_stripped
strip build/envoy -o build_release_stripped/envoy


[[ -z "${IMAGE_TARGET}" ]] && IMAGE_TARGET="envoy:latest"
docker build -f ${SCRIPTDIR}/Dockerfile-envoy-image -t ${IMAGE_TARGET} .

