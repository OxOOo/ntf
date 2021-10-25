#include "main/common/thread_manager.h"

#include <atomic>

#include "absl/strings/str_format.h"
#include "gtest/gtest.h"
#include "utils/testing.h"

namespace common {
namespace {

using ::testing::ElementsAre;
using ::utils::testing::IsOkAndHolds;
using ::utils::testing::StatusIs;

std::atomic_int step_setup(0);

void test_thread(uint64_t id, ThreadManager* manager, int name_id,
                 int sleep_ms) {
    ASSERT_OK(manager->SetThreadName(id, absl::StrFormat("thread%d", name_id)));
    step_setup.fetch_add(1);

    std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
}

TEST(ThreadManager, ThreadManager) {
    using namespace std::chrono_literals;
    using namespace std::placeholders;

    ThreadManager manager;
    std::thread t([&manager]() { manager.Start(); });

    manager.Launch(std::bind(test_thread, _1, _2, 1, 1000));
    manager.Launch(std::bind(test_thread, _1, _2, 2, 1500));
    manager.Launch(std::bind(test_thread, _1, _2, 3, 1500));
    manager.Launch(std::bind(test_thread, _1, _2, 4, 2000));

    // setup
    while (step_setup.load() != 4) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10ms));
    }
    EXPECT_THAT(manager.GetAliveThreadNames(),
                ElementsAre("thread1", "thread2", "thread3", "thread4"));

    std::this_thread::sleep_for(std::chrono::milliseconds(1100ms));
    EXPECT_THAT(manager.GetAliveThreadNames(),
                ElementsAre("thread2", "thread3", "thread4"));

    EXPECT_OK(manager.WaitOnlyThreadsAlive({"thread4"}));
    EXPECT_THAT(manager.GetAliveThreadNames(), ElementsAre("thread4"));

    std::this_thread::sleep_for(std::chrono::milliseconds(600ms));
    EXPECT_THAT(manager.GetAliveThreadNames(), ElementsAre());

    EXPECT_OK(manager.Stop());
    t.join();
}

}  // namespace
}  // namespace common
