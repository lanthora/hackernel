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

struct Element {
    std::chrono::time_point<std::chrono::system_clock> time_point;
    std::function<void()> func;
};

struct Compare {
    bool operator()(Element a, Element b) {
        return a.time_point > b.time_point;
    }
};

class Timer {

public:
    int Insert(const Element &element);
    int RunWait();
    int Exit();

private:
    std::priority_queue<Element, std::vector<Element>, Compare> queue_;
    std::mutex queue_mutex_;
    std::mutex sync_mutex_;
    std::condition_variable signal_;
    bool running_;

public:
    static Timer &GetInstance();

private:
    Timer() {}
};

} // namespace timer

int TimerWait();
void TimerExit();

}; // namespace hackernel

#endif
