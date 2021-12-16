#include "hackernel/ipc.h"

namespace hackernel {

SessionCache::SessionCache() {}

SessionCache &SessionCache::GetInstance() {
    static SessionCache cache;
    return cache;
}

int SessionCache::SetCapacity(size_t capacity) {
    lru_capacity_ = capacity;
    return 0;
}

size_t SessionCache::GenSessionID() {
    static std::atomic<size_t> id(0);
    return id++;
}

int SessionCache::Get(session_t key, conn_t &val) {
    lru_map::iterator lru_map_it = lru_map_.find(key);
    if (lru_map_it == lru_map_.end())
        return -1;

    std::pair<session_t, conn_t> lru_element = *(lru_map_it->second);
    lru_list_.erase(lru_map_it->second);
    lru_list_.push_front(move(lru_element));
    lru_map_[key] = lru_list_.begin();
    val = lru_element.second;
    return 0;
}

int SessionCache::Put(session_t key, conn_t value) {
    lru_map::iterator lru_map_it = lru_map_.find(key);

    if (lru_map_it != lru_map_.end()) {
        lru_list_.erase(lru_map_it->second);
    }

    std::pair<session_t, conn_t> lru_element(key, value);
    lru_list_.push_front(move(lru_element));

    lru_map_[key] = lru_list_.begin();

    while (lru_list_.size() > lru_capacity_) {
        lru_map_.erase(lru_list_.back().first);
        lru_list_.pop_back();
    }
    return 0;
}

}; // namespace hackernel
