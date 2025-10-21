cmake_minimum_required(VERSION 3.31)
project(charclient)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(vendor/sockpp)
add_subdirectory(vendor/zydis-bridge)

add_library(${PROJECT_NAME} SHARED
  src/main.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
  src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  sockpp-shared
  zydis-bridge
)
