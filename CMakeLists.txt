cmake_minimum_required(VERSION 3.31)
project(charclient)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_subdirectory(vendor/sockpp)
add_subdirectory(vendor/zydis-bridge)
add_subdirectory(vendor/lz4/build/cmake)
add_subdirectory(vendor/json)
add_subdirectory(vendor/tiny_aes)

add_library(${PROJECT_NAME} SHARED
  src/main.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
  src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  sockpp-shared
  zydis-bridge
  lz4
  nlohmann_json::nlohmann_json
  tiny-aes

  ws2_32
)
