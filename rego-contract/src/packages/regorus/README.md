<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# regorus for WebAssembly

Builds the [regorus](https://github.com/microsoft/regorus) Rego interpreter
as a static library (`libregorus_ffi.a`) for the `wasm32-wasip1` target
using `wasi-sdk-27`. The result is linked into PDO contracts to evaluate
Rego policies inside a wawaka contract.

`build.sh` fetches the regorus source itself: it clones a pinned commit
(`REGORUS_REPO` / `REGORUS_COMMIT` at the top of the script) into a temporary
directory under `/tmp`. To move to a newer regorus, bump those two values.

## Build configuration

The crate built is `regorus-ffi` (under `bindings/ffi/`) with:

  - target: `wasm32-wasip1`
  - features: `custom_allocator,regorus/opa-no-std`
  - panic strategy: `abort`

`opa-no-std` enables `opa-runtime, arc, base64, base64url, hex, regex,
semver, graph, coverage`. None of these introduce WASI syscalls.

`custom_allocator` swaps Rust's global allocator for two symbols the
contract must define:

  - `regorus_aligned_alloc(size_t alignment, size_t size) -> uint8_t*`
  - `regorus_free(uint8_t* ptr)`

These shims are provided by `src/methods/rego_evaluator.cpp`.

## Inputs

  - `-o <path>`: where to install `lib/libregorus_ffi.a` and
    `include/regorus/regorus.h`. Defaults to `${PWD}/precompiled`.

CMake passes `-o`. `git` and `cargo` must be on `PATH` and the `wasm32-wasip1`
target installed (`rustup target add wasm32-wasip1`).
