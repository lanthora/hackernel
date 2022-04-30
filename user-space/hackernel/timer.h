/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_TIMER_H
#define HACKERNEL_TIMER_H

#include "hackernel/util.h"
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <vector>

namespace hackernel {

namespace timer {

struct element {
    std::chrono::time_point<std::chrono::system_clock> time_point;
    std::function<void()> func;
};

struct compare {
    bool operator()(element a, element b) {
        return a.time_point > b.time_point;
    }
};

class timer {

public:
    int insert(const element &element);
    int start();
    int stop();

private:
    std::priority_queue<element, std::vector<element>, compare> queue_;
    std::mutex queue_mutex_;
    std::mutex sync_mutex_;
    std::condition_variable cv_;
    bool running_;

public:
    static timer &global();
};

} // namespace timer

int start_timer();
void stop_timer();

}; // namespace hackernel

#endif
