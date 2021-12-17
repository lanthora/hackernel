#include "hackernel/ipc.h"

namespace hackernel {

ConnCache::ConnCache() {}

ConnCache &ConnCache::GetInstance() {
    static ConnCache cache;
    return cache;
}

int ConnCache::SetCapacity(size_t capacity) {
    lru_capacity_ = capacity;
    return 0;
}

int ConnCache::Get(const Session &key, UserConn &value) {
    lru_map::iterator lru_map_it = lru_map_.find(key);
    if (lru_map_it == lru_map_.end())
        return -1;

    std::pair<Session, UserConn> lru_element = *(lru_map_it->second);
    lru_list_.erase(lru_map_it->second);
    lru_list_.push_front(move(lru_element));
    lru_map_[key] = lru_list_.begin();
    value = lru_element.second;
    return 0;
}

int ConnCache::Put(const Session &key, const UserConn &value) {
    lru_map::iterator lru_map_it = lru_map_.find(key);

    if (lru_map_it != lru_map_.end()) {
        lru_list_.erase(lru_map_it->second);
    }

    std::pair<Session, UserConn> lru_element(key, value);
    lru_list_.push_front(move(lru_element));

    lru_map_[key] = lru_list_.begin();

    while (lru_list_.size() > lru_capacity_) {
        lru_map_.erase(lru_list_.back().first);
        lru_list_.pop_back();
    }
    return 0;
}

}; // namespace hackernel
