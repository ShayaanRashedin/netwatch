#include "netwatch/persistence/EventWriter.hpp"

#include <exception>
#include <utility>

namespace netwatch {

EventWriter::EventWriter(
    const std::filesystem::path& databasePath,
    const std::size_t queueCapacity)
    : queue_ {queueCapacity},
      repository_ {databasePath},
      worker_ {&EventWriter::run, this}
{
}

EventWriter::~EventWriter()
{
    stop();
}

bool EventWriter::submit(
    SocketEvent event,
    std::vector<Alert> alerts)
{
    return queue_.push(PendingWrite {
        std::move(event),
        std::move(alerts)
    });
}

void EventWriter::stop()
{
    queue_.close();

    if (worker_.joinable()) {
        worker_.join();
    }
}

std::size_t EventWriter::persistedCount() const noexcept
{
    return persisted_count_.load();
}

std::size_t EventWriter::persistedAlertCount() const noexcept
{
    return persisted_alert_count_.load();
}

std::optional<std::string> EventWriter::failure() const
{
    std::lock_guard lock {failure_mutex_};
    return failure_;
}

void EventWriter::run() noexcept
{
    try {
        while (auto pending = queue_.pop()) {
            repository_.persist(
                pending->event,
                pending->alerts
            );
            ++persisted_count_;
            persisted_alert_count_ += pending->alerts.size();
        }
    } catch (const std::exception& error) {
        {
            std::lock_guard lock {failure_mutex_};
            failure_ = error.what();
        }

        queue_.close();
    } catch (...) {
        {
            std::lock_guard lock {failure_mutex_};
            failure_ = "unknown persistence failure";
        }

        queue_.close();
    }
}

} // namespace netwatch

