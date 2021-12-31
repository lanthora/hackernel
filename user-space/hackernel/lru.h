#ifndef HACKERNEL_LRU_H
#define HACKERNEL_LRU_H

#include <list>
#include <mutex>
#include <unordered_map>

namespace hackernel {

template <typename Key, typename Value> class LRUCache {
    typedef std::list<std::pair<Key, Value>> lru_list;
    typedef std::unordered_map<Key, typename lru_list::iterator> lru_map;

private:
    lru_list lru_list_;
    lru_map lru_map_;
    size_t lru_capacity_ = 1;
    std::mutex lru_lock_;

public:
    int Get(const Key &key, Value &value) {
        std::lock_guard<std::mutex> lock(lru_lock_);

        typename lru_map::iterator lru_map_it = lru_map_.find(key);
        if (lru_map_it == lru_map_.end())
            return -ESRCH;

        std::pair<Key, Value> lru_element = *(lru_map_it->second);
        value = lru_element.second;
        lru_list_.erase(lru_map_it->second);
        lru_list_.push_front(move(lru_element));
        lru_map_[key] = lru_list_.begin();
        return 0;
    }
    int Put(const Key &key, const Value &value) {
        std::lock_guard<std::mutex> lock(lru_lock_);

        typename lru_map::iterator lru_map_it = lru_map_.find(key);

        if (lru_map_it != lru_map_.end()) {
            lru_list_.erase(lru_map_it->second);
        }

        std::pair<Key, Value> lru_element(key, value);
        lru_list_.push_front(move(lru_element));

        lru_map_[key] = lru_list_.begin();

        while (lru_list_.size() > lru_capacity_) {
            lru_map_.erase(lru_list_.back().first);
            lru_list_.pop_back();
        }
        return 0;
    }
    int SetCapacity(size_t capacity) {
        lru_capacity_ = capacity;
        return 0;
    }
};

}; // namespace hackernel

#endif
