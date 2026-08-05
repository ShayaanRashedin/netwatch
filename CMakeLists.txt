cmake_minimum_required(VERSION 3.25)

project(
    NetWatch
    VERSION 0.1.0
    DESCRIPTION "Linux network and process observability agent"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(netwatch
    src/main.cpp
)

target_compile_options(netwatch PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
)