cmake_minimum_required(VERSION 3.25)

project(
    NetWatch
    VERSION 1.0.0
    DESCRIPTION "Linux network and process observability agent"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)
include(GNUInstallDirs)

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

target_compile_definitions(netwatch_core PUBLIC
    NETWATCH_VERSION="${PROJECT_VERSION}"
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
    NETWATCH_DEVELOPMENT_WEB_ROOT="${PROJECT_SOURCE_DIR}/web"
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

install(
    TARGETS netwatch netwatch_api
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Runtime
)

install(
    DIRECTORY web/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/netwatch/web
    COMPONENT Runtime
)

install(
    DIRECTORY packaging/systemd/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/netwatch/systemd
    COMPONENT Runtime
    FILES_MATCHING PATTERN "*.service"
)

install(
    FILES packaging/systemd/netwatch.env
    DESTINATION ${CMAKE_INSTALL_DATADIR}/netwatch/examples
    COMPONENT Runtime
)

install(
    PROGRAMS
        scripts/demo.sh
        scripts/install-systemd.sh
        scripts/smoke-test.sh
    DESTINATION ${CMAKE_INSTALL_DATADIR}/netwatch/scripts
    COMPONENT Runtime
)

install(
    FILES
        README.md
        CHANGELOG.md
        CONTRIBUTING.md
        LICENSE
        SECURITY.md
        THIRD_PARTY_NOTICES.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    COMPONENT Runtime
)

install(
    FILES ${cpp_httplib_SOURCE_DIR}/LICENSE
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses
    RENAME cpp-httplib.txt
    COMPONENT Runtime
)

install(
    FILES ${nlohmann_json_SOURCE_DIR}/LICENSE.MIT
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses
    RENAME nlohmann-json.txt
    COMPONENT Runtime
)

set(CPACK_PACKAGE_NAME "netwatch")
set(CPACK_PACKAGE_VENDOR "ShayaanRashedin")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME
    "netwatch-${PROJECT_VERSION}-linux-${CMAKE_SYSTEM_PROCESSOR}"
)
set(CPACK_PACKAGE_CHECKSUM SHA256)
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README.md")
set(CPACK_GENERATOR TGZ)
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_STRIP_FILES TRUE)

include(CPack)

