# https://libcheck.github.io/check/
cmake_minimum_required(VERSION 2.8)

project(pc-2020b-6 C)

# Determine minimum C
set(CMAKE_C_STANDARD 11)

# Enable debugging
set(CMAKE_BUILD_TYPE Debug)

# Show all warning messages
set(CMAKE_C_FLAGS "-Wall -Wextra -g -std=c11 -fsanitize=address -D_POSIX_C_SOURCE=200112L -fno-omit-frame-pointer -Wno-unused-parameter")

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src)
add_executable(client client/client.c)