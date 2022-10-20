#include "hackernel/osinfo.h"
#include "hackernel/ipc.h"
#include "hackernel/timer.h"
#include "hackernel/util.h"
#include <cstring>
#include <fstream>
#include <nlohmann/json.hpp>

namespace hackernel {

int osinfo_cpu::update() {
    std::ifstream ifs;
    ifs.open("/proc/stat", std::ios::in);

    if (ifs.rdstate() & ifs.failbit) {
        ERR("open /proc/stat failed");
        return -ENOENT;
    }

    std::string name;
    ifs >> name >> user >> nice >> system >> idle >> iowait >> irq >> softirq;
    ifs.close();

    if (ifs.rdstate() & ifs.failbit) {
        ERR("close /proc/stat failed");
        return -ENOENT;
    }
    return 0;
}

long long osinfo_cpu::sum() const {
    return user + nice + system + idle + iowait + irq + softirq;
}

double osinfo_cpu::usage(const osinfo_cpu &previous) {
    return 1 - ((idle - previous.idle) * 1.0 / (sum() - previous.sum()));
}

int osinfo_mem::update() {
    total = 0ULL;
    available = 0ULL;

    static const unsigned int BUFFER_SIZE = 64;
    std::string line;
    line.resize(BUFFER_SIZE);

    std::ifstream ifs;
    ifs.open("/proc/meminfo");
    if (ifs.rdstate() & ifs.failbit) {
        ERR("open /proc/meminfo failed");
        return -ENOENT;
    }

    while (ifs.getline(line.data(), BUFFER_SIZE - 1)) {
        if (!total && line.starts_with("MemTotal:"))
            total = atoll(line.data() + strlen("MemTotal:"));

        if (!available && line.starts_with("MemAvailable:"))
            available = atoll(line.data() + strlen("MemAvailable:"));

        if (total && available)
            break;
    }
    ifs.close();
    if (ifs.rdstate() & ifs.failbit) {
        ERR("close /proc/meminfo failed");
        return -ENOENT;
    }
    return 0;
}

double osinfo_mem::usage() {
    return 1 - (1.0 * available / total);
}

int osinfo::update() {
    current_mem_usage_.update();
    current_cpu_usage_.update();

    mem_usage_ = current_mem_usage_.usage();
    cpu_usage_ = current_cpu_usage_.usage(previous_cpu_usage_);

    previous_cpu_usage_ = current_cpu_usage_;
    return 0;
}

double osinfo::get_mem_usage() {
    return mem_usage_;
}

double osinfo::get_cpu_usage() {
    return cpu_usage_;
}

void register_osinfo_timer() {
    timer::event event;
    event.time_point = std::chrono::system_clock::now() + std::chrono::seconds(5);
    event.func = register_osinfo_timer;

    static osinfo info;
    info.update();

    nlohmann::json doc;
    doc["type"] = "osinfo::report";
    doc["cpu"] = info.get_cpu_usage();
    doc["mem"] = info.get_mem_usage();
    std::string msg = generate_system_broadcast_msg(doc);
    broadcaster::global().broadcast(msg);

    timer::timer::global().insert(event);
}

}; // namespace hackernel
