#include "netwatch/api/ApiServer.hpp"

#include "netwatch/api/ApiService.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace netwatch {

namespace {

using Json = nlohmann::json;

void sendJson(
    const ApiResponse& response,
    httplib::Response& httpResponse)
{
    httpResponse.status = response.status;
    httpResponse.set_content(response.body, "application/json");
    httpResponse.set_header("Cache-Control", "no-store");
}

void sendError(
    httplib::Response& response,
    const int status,
    const std::string& message)
{
    response.status = status;
    response.set_content(
        Json {
            {"error", message},
            {"status", status}
        }.dump(),
        "application/json"
    );
    response.set_header("Cache-Control", "no-store");
}

std::optional<int> boundedQueryInteger(
    const httplib::Request& request,
    const std::string& name,
    const int defaultValue,
    const int minimum,
    const int maximum,
    std::string& error)
{
    if (!request.has_param(name)) {
        return defaultValue;
    }

    const std::string valueText = request.get_param_value(name);
    int value {};

    const auto [ptr, parseError] = std::from_chars(
        valueText.data(),
        valueText.data() + valueText.size(),
        value
    );

    if (parseError != std::errc {}
        || ptr != valueText.data() + valueText.size()
        || value < minimum
        || value > maximum) {
        error = name
            + " must be an integer between "
            + std::to_string(minimum)
            + " and "
            + std::to_string(maximum);
        return std::nullopt;
    }

    return value;
}

} // namespace

struct ApiServer::Impl {
    Impl(
        const std::filesystem::path& databasePath,
        std::filesystem::path webRoot)
        : service {databasePath},
          web_root {std::move(webRoot)}
    {
        if (!std::filesystem::is_regular_file(
                web_root / "index.html")) {
            throw std::runtime_error {
                "Dashboard index not found under web root: "
                + web_root.string()
            };
        }

        server.set_default_headers({
            {"X-Content-Type-Options", "nosniff"},
            {"X-Frame-Options", "DENY"},
            {"Referrer-Policy", "no-referrer"},
            {"Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"}
        });

        server.Get("/api/health", [this](
            const httplib::Request&,
            httplib::Response& response) {
            try {
                sendJson(service.health(), response);
            } catch (const std::exception& error) {
                sendError(response, 500, error.what());
            }
        });

        server.Get("/api/summary", [this](
            const httplib::Request&,
            httplib::Response& response) {
            try {
                sendJson(service.summary(), response);
            } catch (const std::exception& error) {
                sendError(response, 500, error.what());
            }
        });

        server.Get("/api/events", [this](
            const httplib::Request& request,
            httplib::Response& response) {
            std::string error;
            const auto limit = boundedQueryInteger(
                request,
                "limit",
                50,
                1,
                500,
                error
            );

            if (!limit.has_value()) {
                sendError(response, 400, error);
                return;
            }

            try {
                sendJson(
                    service.events(
                        static_cast<std::size_t>(*limit)
                    ),
                    response
                );
            } catch (const std::exception& exception) {
                sendError(response, 500, exception.what());
            }
        });

        server.Get("/api/alerts", [this](
            const httplib::Request& request,
            httplib::Response& response) {
            std::string error;
            const auto limit = boundedQueryInteger(
                request,
                "limit",
                25,
                1,
                500,
                error
            );

            if (!limit.has_value()) {
                sendError(response, 400, error);
                return;
            }

            const auto minimumScore = boundedQueryInteger(
                request,
                "min_score",
                0,
                0,
                100,
                error
            );

            if (!minimumScore.has_value()) {
                sendError(response, 400, error);
                return;
            }

            try {
                sendJson(
                    service.alerts(
                        static_cast<std::size_t>(*limit),
                        *minimumScore
                    ),
                    response
                );
            } catch (const std::exception& exception) {
                sendError(response, 500, exception.what());
            }
        });

        if (!server.set_mount_point("/", web_root.string())) {
            throw std::runtime_error {
                "Unable to mount dashboard web root: "
                + web_root.string()
            };
        }
    }

    ApiService service;
    std::filesystem::path web_root;
    httplib::Server server;
};

ApiServer::ApiServer(
    const std::filesystem::path& databasePath,
    const std::filesystem::path& webRoot)
    : impl_ {std::make_unique<Impl>(databasePath, webRoot)}
{
}

ApiServer::~ApiServer() = default;

bool ApiServer::listen(
    const std::string& address,
    const std::uint16_t port)
{
    return impl_->server.listen(address, static_cast<int>(port));
}

void ApiServer::stop()
{
    impl_->server.stop();
}

} // namespace netwatch

