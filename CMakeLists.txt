cmake_minimum_required(VERSION 3.25)

project(
    NetWatch
    VERSION 0.5.0
    DESCRIPTION "Linux network and process observability agent"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)

set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_INSTALL OFF CACHE BOOL "" FORCE)
set(HTTPLIB_TEST OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.54.0
    GIT_SHALLOW TRUE
)

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
    GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(cpp_httplib nlohmann_json)

function(netwatch_enable_warnings target_name)
    target_compile_options(${target_name} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
    )
endfunction()

add_library(netwatch_core
    src/core/SocketSnapshot.cpp
    src/detection/Alert.cpp
    src/detection/DetectionEngine.cpp
    src/monitoring/SnapshotDiffer.cpp
    src/persistence/EventWriter.cpp
    src/procfs/ProcNetSocketParser.cpp
    src/procfs/ProcSocketCollector.cpp
    src/procfs/ProcessResolver.cpp
    src/storage/SQLiteEventRepository.cpp
)

target_include_directories(netwatch_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(netwatch_core PUBLIC
    SQLite::SQLite3
    Threads::Threads
)

netwatch_enable_warnings(netwatch_core)

add_executable(netwatch
    src/main.cpp
)

target_link_libraries(netwatch PRIVATE
    netwatch_core
)

netwatch_enable_warnings(netwatch)

add_library(netwatch_api_core
    src/api/ApiServer.cpp
    src/api/ApiService.cpp
)

target_include_directories(netwatch_api_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(netwatch_api_core PUBLIC
    netwatch_core
    httplib::httplib
    nlohmann_json::nlohmann_json
)

netwatch_enable_warnings(netwatch_api_core)

add_executable(netwatch_api
    src/api_main.cpp
)

target_compile_definitions(netwatch_api PRIVATE
    NETWATCH_WEB_ROOT="${PROJECT_SOURCE_DIR}/web"
)

target_link_libraries(netwatch_api PRIVATE
    netwatch_api_core
)

netwatch_enable_warnings(netwatch_api)

include(CTest)

if(BUILD_TESTING)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.8.1
        GIT_SHALLOW TRUE
    )

    FetchContent_MakeAvailable(Catch2)

    add_executable(netwatch_tests
        tests/unit/AlertTests.cpp
        tests/unit/ApiServiceTests.cpp
        tests/unit/BoundedQueueTests.cpp
        tests/unit/DetectionEngineTests.cpp
        tests/unit/EventWriterTests.cpp
        tests/unit/ProcNetSocketParserTests.cpp
        tests/unit/ProcSocketCollectorTests.cpp
        tests/unit/ProcessResolverTests.cpp
        tests/unit/SnapshotDifferTests.cpp
        tests/unit/SocketSnapshotTests.cpp
        tests/unit/SQLiteEventRepositoryTests.cpp
    )

    target_link_libraries(netwatch_tests PRIVATE
        netwatch_core
        netwatch_api_core
        Catch2::Catch2WithMain
    )

    netwatch_enable_warnings(netwatch_tests)

    include(Catch)
    catch_discover_tests(netwatch_tests)
endif()

