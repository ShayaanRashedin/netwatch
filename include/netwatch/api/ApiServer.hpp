#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

namespace netwatch {

class ApiServer {
public:
    ApiServer(
        const std::filesystem::path& databasePath,
        const std::filesystem::path& webRoot
    );

    ~ApiServer();

    ApiServer(const ApiServer&) = delete;
    ApiServer& operator=(const ApiServer&) = delete;

    bool listen(
        const std::string& address,
        std::uint16_t port
    );

    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace netwatch

