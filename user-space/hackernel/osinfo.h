#ifndef HACKERNEL_OSINFO_H
#define HACKERNEL_OSINFO_H

namespace hackernel {

struct osinfo_cpu {
    long long user = 0;
    long long nice = 0;
    long long system = 0;
    long long idle = 0;
    long long iowait = 0;
    long long irq = 0;
    long long softirq = 0;

    long long sum() const;
    int update();
    double percentage(const osinfo_cpu &previous);
};

struct osinfo_mem {
    unsigned long total;
    unsigned long available;

    int update();
    double percentage();
};

class osinfo {
public:
    int update();
    double get_mem_usage_percentage();
    double get_cpu_usage_percentage();

private:
    double mem_usage_percentage_;
    double cpu_usage_percentage_;

    osinfo_cpu current_cpu_status_;
    osinfo_cpu previous_cpu_status_;
    osinfo_mem current_mem_status_;
};

} // namespace hackernel

#endif
