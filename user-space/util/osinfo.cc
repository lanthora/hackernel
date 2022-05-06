#include "hackernel/osinfo.h"
#include "hackernel/util.h"
#include <cstring>
#include <fstream>

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

double osinfo_cpu::percentage(const osinfo_cpu &previous) {
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

double osinfo_mem::percentage() {
    return 1 - (1.0 * available / total);
}

int osinfo::update() {
    current_mem_status_.update();
    current_cpu_status_.update();
    mem_usage_percentage_ = current_mem_status_.percentage();
    cpu_usage_percentage_ = current_cpu_status_.percentage(previous_cpu_status_);
    previous_cpu_status_ = current_cpu_status_;
    return 0;
}

double osinfo::get_mem_usage_percentage() {
    return mem_usage_percentage_;
}

double osinfo::get_cpu_usage_percentage() {
    return cpu_usage_percentage_;
}

}; // namespace hackernel