#ifndef MAIN_COMMON_THREAD_MANAGER_H_
#define MAIN_COMMON_THREAD_MANAGER_H_

#include <condition_variable>
#include <functional>
#include <list>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <thread>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace common {

class ThreadManager {
    struct Thread {
        uint64_t id;
        std::string name;
        std::thread t;
    };

   public:
    ThreadManager() { stopped_ = false; }

    void Start();
    absl::Status Stop();

    // Launch a new thread to run `func`.
    // The argument for `func` is id and thread manager pointer.
    void Launch(std::function<void(uint64_t, ThreadManager*)> func);

    absl::Status SetThreadName(uint64_t id, absl::string_view name);

    // Wait for only the threads in `alive_threads` are alive.
    absl::Status WaitOnlyThreadsAlive(
        const std::set<std::string>& alive_threads);

    std::vector<std::string> GetAliveThreadNames();

   private:
    // Any read/write to member vars should be protected by the mutex.
    std::mutex mtx_;
    std::condition_variable cv_;

    bool stopped_;
    std::list<Thread> threads_;
    std::queue<uint64_t> end_ids_;
};

}  // namespace common

#endif  // MAIN_COMMON_THREAD_MANAGER_H_
