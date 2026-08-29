#include "netwatch/concurrency/BoundedQueue.hpp"

#include <catch2/catch_test_macros.hpp>

#include <future>
#include <stdexcept>
#include <thread>

TEST_CASE("Bounded queue rejects zero capacity")
{
    CHECK_THROWS_AS(
        netwatch::BoundedQueue<int> {0U},
        std::invalid_argument
    );
}

TEST_CASE("Bounded queue preserves FIFO order and drains after close")
{
    netwatch::BoundedQueue<int> queue {2U};

    REQUIRE(queue.push(10));
    REQUIRE(queue.push(20));
    CHECK(queue.size() == 2U);

    queue.close();

    REQUIRE(queue.pop() == 10);
    REQUIRE(queue.pop() == 20);
    CHECK_FALSE(queue.pop().has_value());
    CHECK_FALSE(queue.push(30));
    CHECK(queue.closed());
}

TEST_CASE("Bounded queue applies backpressure until space is available")
{
    netwatch::BoundedQueue<int> queue {1U};
    REQUIRE(queue.push(1));

    std::promise<void> started;
    auto startedFuture = started.get_future();
    bool secondPushSucceeded {};

    std::thread producer {[&] {
        started.set_value();
        secondPushSucceeded = queue.push(2);
    }};

    startedFuture.wait();
    REQUIRE(queue.pop() == 1);
    producer.join();

    CHECK(secondPushSucceeded);
    REQUIRE(queue.pop() == 2);

    queue.close();
}

