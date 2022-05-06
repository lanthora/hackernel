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
    double usage(const osinfo_cpu &previous);
};

struct osinfo_mem {
    unsigned long total;
    unsigned long available;

    int update();
    double usage();
};

class osinfo {
public:
    int update();
    double get_mem_usage();
    double get_cpu_usage();

private:
    double mem_usage_;
    double cpu_usage_;

    osinfo_cpu current_cpu_usage_;
    osinfo_cpu previous_cpu_usage_;
    osinfo_mem current_mem_usage_;
};

void register_osinfo_timer();

} // namespace hackernel

#endif
