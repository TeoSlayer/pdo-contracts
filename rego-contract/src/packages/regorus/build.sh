#! /bin/bash
# Copyright 2026 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

source ${PDO_HOME}/bin/lib/common.sh

# The exact regorus revision this build targets. Pinned to a commit (not a
# branch or tag ref) so the produced artifact is reproducible.
REGORUS_REPO=https://github.com/microsoft/regorus.git
REGORUS_COMMIT=acf7f7a25ec718be7c0d58eb2bd8dd1e6c0163df  # regorus-v0.10.1

OUTPUT_DIR=${PWD}/precompiled

while getopts "o:" opt; do
    case $opt in
        o)
            OUTPUT_DIR=$OPTARG ;;
        \?)
            die "Invalid option: -$OPTARG" >&2 ;;
    esac
done

# Clone the pinned regorus revision into a temporary directory.
REGORUS_SRC=$(mktemp -d /tmp/regorus-src.XXXXXXXX)
try git clone "${REGORUS_REPO}" "${REGORUS_SRC}"
try git -C "${REGORUS_SRC}" checkout -q "${REGORUS_COMMIT}"

WASI_SDK_DIR=/opt/wasi-sdk
if [ ! -d "${WASI_SDK_DIR}" ]; then
    die "WASI SDK not found at ${WASI_SDK_DIR}"
fi

if ! command -v cargo >/dev/null 2>&1; then
    die "cargo not found in PATH; install rustup and run 'rustup target add wasm32-wasip1'"
fi

# Use wasi-sdk's clang as the linker driver for wasm32-wasip1. Not strictly
# required for a staticlib (the archive is just packed object files) but keeps
# the toolchain consistent if cargo ever links a final wasm artifact.
export CARGO_TARGET_WASM32_WASIP1_LINKER="${WASI_SDK_DIR}/bin/clang"

# Force panic=abort: with no_std + wasm32-wasip1, unwinding is unavailable.
export CARGO_PROFILE_RELEASE_PANIC=abort

pushd "${REGORUS_SRC}/bindings/ffi" >/dev/null
# regorus-ffi's Cargo.toml declares both `cdylib` and `staticlib`. The cdylib
# variant fails to link for wasm32-wasip1 (no `_initialize` entry symbol). We
# only need the staticlib, so use `cargo rustc --crate-type staticlib` to
# build that variant alone.
try cargo rustc \
    --release \
    --target wasm32-wasip1 \
    --locked \
    --no-default-features \
    --features "custom_allocator,regorus/opa-no-std" \
    --crate-type staticlib
popd >/dev/null

STATIC_LIB="${REGORUS_SRC}/bindings/ffi/target/wasm32-wasip1/release/libregorus_ffi.a"
HEADER_FILE="${REGORUS_SRC}/bindings/ffi/regorus.h"

if [ ! -f "${STATIC_LIB}" ]; then
    die "cargo did not produce ${STATIC_LIB}"
fi
if [ ! -f "${HEADER_FILE}" ]; then
    die "cargo did not produce ${HEADER_FILE} (cbindgen step failed?)"
fi

mkdir -p "${OUTPUT_DIR}/lib"
try cp "${STATIC_LIB}" "${OUTPUT_DIR}/lib/"

mkdir -p "${OUTPUT_DIR}/include/regorus"
try cp "${HEADER_FILE}" "${OUTPUT_DIR}/include/regorus/"

say "regorus build complete: ${OUTPUT_DIR}/lib/libregorus_ffi.a"
