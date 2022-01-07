/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_LRU_H
#define HACKERNEL_LRU_H

#include <functional>
#include <list>
#include <mutex>
#include <unordered_map>

namespace hackernel {

template <typename Key, typename Value> class LRUData {
    typedef std::list<std::pair<Key, Value>> lru_list;

public:
    lru_list raw;
    size_t capacity;
};

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

private:
    int UnlockedPut(const Key &key, const Value &value) {
        typename lru_map::iterator lru_map_it = lru_map_.find(key);

        if (lru_map_it != lru_map_.end()) {
            lru_list_.erase(lru_map_it->second);
        }

        std::pair<Key, Value> lru_element(key, value);
        lru_list_.push_front(move(lru_element));

        lru_map_[key] = lru_list_.begin();

        while (lru_list_.size() > lru_capacity_) {
            if (on_earse_)
                on_earse_(lru_list_.back());
            lru_map_.erase(lru_list_.back().first);
            lru_list_.pop_back();
        }
        return 0;
    }

public:
    int Put(const Key &key, const Value &value) {
        std::lock_guard<std::mutex> lock(lru_lock_);
        return UnlockedPut(key, value);
    }

    int SetCapacity(size_t capacity) {
        std::lock_guard<std::mutex> lock(lru_lock_);

        lru_capacity_ = capacity;
        return 0;
    }

    int GetCapacity(size_t &capacity) {
        std::lock_guard<std::mutex> lock(lru_lock_);

        capacity = lru_capacity_;
        return 0;
    }

    int Export(LRUData<Key, Value> &data) {
        std::lock_guard<std::mutex> lock(lru_lock_);

        data.raw = lru_list_;
        data.capacity = lru_capacity_;
        return 0;
    }

    int Import(const LRUData<Key, Value> &data) {
        std::lock_guard<std::mutex> lock(lru_lock_);

        lru_capacity_ = data.capacity;
        for (typename lru_list::const_reverse_iterator it = data.raw.rbegin(); it != data.raw.rend(); ++it) {
            UnlockedPut(it->first, it->second);
        }
        return 0;
    }

private:
    std::function<void(const std::pair<Key, Value> &)> on_earse_ = nullptr;

public:
    int SetOnEarseHandler(std::function<void(const std::pair<Key, Value> &item)> on_earse) {
        on_earse_ = on_earse;
        return 0;
    }
};

}; // namespace hackernel

#endif
