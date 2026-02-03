cmake_minimum_required(VERSION 3.31)
project(charon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR})

set(CHARON_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(CHARON_CLIENT_DIR ${CHARON_SRC_DIR}/network/client)

set(CHARON_COMMON_LIBS
  sockpp-shared
  lz4
  nlohmann_json::nlohmann_json
  tiny-aes
)

if(WIN32)
  set(CHARON_PLATFORM_LIBS ws2_32)
else()
  set(CHARON_PLATFORM_LIBS crypto)
endif()

add_subdirectory(vendor/sockpp)
add_subdirectory(vendor/zydis-bridge)
add_subdirectory(vendor/lz4/build/cmake)
add_subdirectory(vendor/json)
add_subdirectory(vendor/tiny_aes)

function(charon_target_setup target)
  target_include_directories(${target} PRIVATE ${CHARON_SRC_DIR})
  target_link_libraries(${target} PRIVATE
    ${CHARON_COMMON_LIBS}
    ${CHARON_PLATFORM_LIBS}
  )
endfunction()

add_library(charon SHARED
  src/main.cpp
)

target_link_libraries(charon PRIVATE zydis-bridge)
charon_target_setup(charon)

if(EXISTS ${CHARON_CLIENT_DIR})
  add_executable(tcp_client_example
    ${CHARON_CLIENT_DIR}/tcp_example.cpp
  )
  charon_target_setup(tcp_client_example)
endif()
