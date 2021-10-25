#include "main/common/thread_manager.h"

#include <chrono>

#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "glog/logging.h"

namespace common {

constexpr absl::string_view kDefaultThreadName = "unnamed";

void ThreadManager::Start() {
    using namespace std::chrono_literals;

    while (true) {
        std::unique_lock<std::mutex> lock(mtx_);
        if (stopped_) {
            break;
        }

        cv_.wait_for(lock, 5000ms, [this] { return !end_ids_.empty(); });

        // removes ended threads
        while (!end_ids_.empty()) {
            uint64_t end_id = end_ids_.front();
            end_ids_.pop();

            auto it = threads_.begin();
            while (it != threads_.end()) {
                if (it->id == end_id) {
                    it->t.join();
                    it = threads_.erase(it);
                } else {
                    it++;
                }
            }
        }

        // logs running threads
        std::vector<std::string> running_threads;
        for (const auto& thread : threads_) {
            running_threads.push_back(thread.name);
        }
        LOG(INFO) << "Running threads : "
                  << absl::StrJoin(running_threads, ", ");

        // in this loop, some threads may end, thus we need to notify
        lock.unlock();
        cv_.notify_all();
    }
}

absl::Status ThreadManager::Stop() {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!threads_.empty()) {
            return absl::InternalError(
                "Cannot stop a ThreadManager which still has running threads");
        }
        stopped_ = true;
    }
    cv_.notify_all();
    return absl::OkStatus();
}

void ThreadManager::Launch(std::function<void(uint64_t, ThreadManager*)> func) {
    std::lock_guard<std::mutex> lock(mtx_);

    // alloc an new id
    uint64_t id = 0;
    while (true) {
        bool exists = false;
        for (const auto& thread : threads_) {
            if (thread.id == id) {
                exists = true;
            }
        }
        if (exists) {
            id++;
        } else {
            break;
        }
    }

    // run thread
    std::thread t = std::thread([func = std::move(func), id, this]() {
        try {
            func(id, this);
        } catch (...) {
            LOG(ERROR) << "ThreadManager has catched an error";
        }
        // Remove thread
        {
            std::lock_guard<std::mutex> lock(mtx_);
            end_ids_.push(id);
        }
        cv_.notify_all();
    });

    // add to list
    threads_.push_back(
        {.id = id, .name = std::string(kDefaultThreadName), .t = std::move(t)});
}

absl::Status ThreadManager::SetThreadName(uint64_t id, absl::string_view name) {
    std::lock_guard<std::mutex> lock(mtx_);

    for (auto& thread : threads_) {
        if (thread.id == id) {
            thread.name = std::string(name);
            return absl::OkStatus();
        }
    }

    return absl::InvalidArgumentError(
        absl::StrFormat("Cannot find a thread with id = `%d`", id));
}

absl::Status ThreadManager::WaitOnlyThreadsAlive(
    const std::set<std::string>& alive_threads) {
    std::unique_lock<std::mutex> lock(mtx_);

    cv_.wait(lock, [this, &alive_threads]() {
        for (const auto& thread : threads_) {
            if (alive_threads.find(thread.name) == alive_threads.end()) {
                return false;
            }
        }
        return true;
    });

    for (const auto& alive_thread : alive_threads) {
        bool exists = false;
        for (const auto& thread : threads_) {
            if (thread.name == alive_thread) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            return absl::InternalError(absl::StrFormat(
                "No alive thread which has name = `%s`", alive_thread));
        }
    }

    return absl::OkStatus();
}

std::vector<std::string> ThreadManager::GetAliveThreadNames() {
    std::lock_guard<std::mutex> lock(mtx_);

    std::vector<std::string> names;
    for (const auto& it : threads_) {
        names.push_back(it.name);
    }

    return names;
}

}  // namespace common
