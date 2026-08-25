cmake_minimum_required(VERSION 3.25)

project(
    NetWatch
    VERSION 0.1.0
    DESCRIPTION "Linux network and process observability agent"
    LANGUAGES CXX
)

include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.8.1
    GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(Catch2)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(netwatch_core
    src/procfs/ProcNetSocketParser.cpp
    src/procfs/ProcessResolver.cpp
)

target_include_directories(netwatch_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_options(netwatch_core PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
)

add_executable(netwatch
    src/main.cpp
)

target_link_libraries(netwatch PRIVATE
    netwatch_core
)

target_compile_options(netwatch PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
)

add_executable(netwatch_tests
    tests/unit/ProcNetSocketParserTests.cpp
)

target_link_libraries(netwatch_tests PRIVATE
    netwatch_core
    Catch2::Catch2WithMain
)

target_compile_options(netwatch_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
)

include(CTest)
include(Catch)

catch_discover_tests(netwatch_tests)