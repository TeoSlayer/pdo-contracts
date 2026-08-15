INCLUDE(${CMAKE_CURRENT_LIST_DIR}/family.cmake)

IF(NOT DEFINED IDENTITY_INCLUDES)
  MESSAGE(FATAL_ERROR "IDENTITY_INCLUDES is not defined")
ENDIF()

IF(NOT DEFINED EXCHANGE_INCLUDES)
  MESSAGE(FATAL_ERROR "EXCHANGE_INCLUDES is not defined")
ENDIF()

# ---------------------------------------------
# Set up the include list
# ---------------------------------------------
SET (${CF_HANDLE}_INCLUDES ${WASM_INCLUDES})
LIST(APPEND ${CF_HANDLE}_INCLUDES ${EXCHANGE_INCLUDES})
LIST(APPEND ${CF_HANDLE}_INCLUDES ${IDENTITY_INCLUDES})
LIST(APPEND ${CF_HANDLE}_INCLUDES ${CMAKE_CURRENT_LIST_DIR}/src)

# ---------------------------------------------
# Set up the default source list
# ---------------------------------------------
FILE(GLOB ${CF_HANDLE}_COMMON_SOURCE ${CMAKE_CURRENT_LIST_DIR}/src/common/[A-Za-z]*.cpp)
FILE(GLOB ${CF_HANDLE}_CONTRACT_SOURCE ${CMAKE_CURRENT_LIST_DIR}/src/methods/[A-Za-z]*.cpp)

SET (${CF_HANDLE}_SOURCES)
LIST(APPEND ${CF_HANDLE}_SOURCES ${${CF_HANDLE}_COMMON_SOURCE})
LIST(APPEND ${CF_HANDLE}_SOURCES ${${CF_HANDLE}_CONTRACT_SOURCE})

# ---------------------------------------------
# Build the wawaka contract common library
# ---------------------------------------------
SET(${CF_HANDLE}_LIB ww_${CF_NAME})
