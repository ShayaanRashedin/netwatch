#pragma once

#include "netwatch/storage/SQLiteEventRepository.hpp"

#include <cstddef>
#include <filesystem>
#include <string>

namespace netwatch {

struct ApiResponse {
    int status {200};
    std::string body;
};

class ApiService {
public:
    explicit ApiService(
        const std::filesystem::path& databasePath
    );

    [[nodiscard]]
    ApiResponse health() const;

    [[nodiscard]]
    ApiResponse summary() const;

    [[nodiscard]]
    ApiResponse events(std::size_t limit) const;

    [[nodiscard]]
    ApiResponse alerts(
        std::size_t limit,
        int minimumRiskScore
    ) const;

private:
    SQLiteEventRepository repository_;
};

} // namespace netwatch

