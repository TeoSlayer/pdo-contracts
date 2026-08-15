INCLUDE(exchange-contract/methods)
INCLUDE(identity-contract/methods)
INCLUDE(methods.cmake)

# -----------------------------------------------------------------
ADD_LIBRARY(${${CF_HANDLE}_LIB} STATIC ${${CF_HANDLE}_SOURCES})
SET_PROPERTY(TARGET ${${CF_HANDLE}_LIB} APPEND_STRING PROPERTY COMPILE_OPTIONS "${WASM_BUILD_OPTIONS}" "-Wno-deprecated")
SET_PROPERTY(TARGET ${${CF_HANDLE}_LIB} APPEND_STRING PROPERTY LINK_OPTIONS "${WASM_LINK_OPTIONS}")
SET_TARGET_PROPERTIES(${${CF_HANDLE}_LIB} PROPERTIES EXCLUDE_FROM_ALL TRUE)

TARGET_INCLUDE_DIRECTORIES(${${CF_HANDLE}_LIB} PUBLIC ${${CF_HANDLE}_INCLUDES})
TARGET_INCLUDE_DIRECTORIES(${${CF_HANDLE}_LIB} PUBLIC ${EXCHANGE_INCLUDES})
TARGET_INCLUDE_DIRECTORIES(${${CF_HANDLE}_LIB} PUBLIC ${IDENTITY_INCLUDES})
TARGET_INCLUDE_DIRECTORIES(${${CF_HANDLE}_LIB} PUBLIC ${WASM_INCLUDES})
TARGET_INCLUDE_DIRECTORIES(${${CF_HANDLE}_LIB} PUBLIC ${OPENSSL_WASM_INCLUDE_DIR})

ADD_DEPENDENCIES(${${CF_HANDLE}_LIB} openssl_wasm)


# TIDY command is used to generate "lint" messages during the
# build. Adjust the parameters to your liking.
# SET(CLANG_TIDY_COMMAND "/opt/wasi-sdk/bin/clang-tidy" "-checks=-*,modernize-*")
SET(CLANG_TIDY_COMMAND "/opt/wasi-sdk/bin/clang-tidy")
SET_TARGET_PROPERTIES(${${CF_HANDLE}_LIB} PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")

# -----------------------------------------------------------------
FOREACH(contract ${CF_CONTRACTS})
  MESSAGE(NOTICE "Building contract ${contract}")
  BUILD_CONTRACT(${CF_NAME}_${contract} src/contracts/${contract}.cpp
    HEADERS ${EXCHANGE_INCLUDES} ${IDENTITY_INCLUDES} ${${CF_HANDLE}_INCLUDES}
    LIBRARIES ${EXCHANGE_LIB} ${IDENTITY_LIB} ${${CF_HANDLE}_LIB} ${OPENSSL_WASM_CRYPTO_LIB}
  )
ENDFOREACH()

# -----------------------------------------------------------------
INCLUDE(Python)
LIST(TRANSFORM CF_CONTRACTS PREPEND ${CF_NAME}_ OUTPUT_VARIABLE expanded_contracts)
BUILD_WHEEL(${CF_NAME} ${expanded_contracts})

# -----------------------------------------------------------------
INCLUDE(Test)
ADD_SHELL_TEST(download script SCRIPT test/script_test.sh)
