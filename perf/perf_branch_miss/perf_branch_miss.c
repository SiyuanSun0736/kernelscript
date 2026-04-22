#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <fcntl.h>
#include <net/if.h>
#include <setjmp.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#include <pthread.h>

/* TCX attachment constants - defined inline to ensure availability */
#ifndef BPF_TCX_INGRESS
#define BPF_TCX_INGRESS  44
#endif
#ifndef BPF_TCX_EGRESS
#define BPF_TCX_EGRESS   45
#endif

/* Generated from KernelScript IR */
#include "perf_branch_miss.skel.h"

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <dirent.h>

/* KernelScript perf_event types */
typedef enum {
    cpu_cycles = 0,
    instructions = 1,
    cache_references = 2,
    cache_misses = 3,
    branch_instructions = 4,
    branch_misses = 5,
    page_faults = 6,
    context_switches = 7,
    cpu_migrations = 8
} perf_counter;

typedef struct {
    int32_t counter;
    int32_t pid;
    int32_t cpu;
    uint64_t period;
    uint32_t wakeup;
    bool inherit;
    bool exclude_kernel;
    bool exclude_user;
} ks_perf_event_attr;














/* eBPF skeleton instance */
struct perf_branch_miss_ebpf *obj = NULL;













/* BPF Helper Functions (generated only when used) */


int get_bpf_program_handle(const char *program_name) {
    if (!obj) {
        fprintf(stderr, "eBPF skeleton not loaded - this should not happen with implicit loading\n");
        return -1;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj->obj, program_name);
    if (!prog) {
        fprintf(stderr, "Failed to find program '%s' in BPF object\n", program_name);
        return -1;
    }
    
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for program '%s'\n", program_name);
        return -1;
    }
    

    return prog_fd;
}

int attach_perf_by_attr(int prog_fd, ks_perf_event_attr ks_attr) {
    if (prog_fd < 0) {
        fprintf(stderr, "attach_perf: invalid program fd %d\n", prog_fd);
        return -1;
    }
    
    /* Map KernelScript perf_counter enum to PERF_TYPE_* and PERF_COUNT_* */
    __u32 perf_type;
    __u64 perf_config;
    switch (ks_attr.counter) {
        case 0: /* cpu_cycles */
            perf_type = PERF_TYPE_HARDWARE;
            perf_config = PERF_COUNT_HW_CPU_CYCLES;
            break;
        case 1: /* instructions */
            perf_type = PERF_TYPE_HARDWARE;
            perf_config = PERF_COUNT_HW_INSTRUCTIONS;
            break;
        case 2: /* cache_references */
            perf_type = PERF_TYPE_HARDWARE;
            perf_config = PERF_COUNT_HW_CACHE_REFERENCES;
            break;
        case 3: /* cache_misses */
            perf_type = PERF_TYPE_HARDWARE;
            perf_config = PERF_COUNT_HW_CACHE_MISSES;
            break;
        case 4: /* branch_instructions */
            perf_type = PERF_TYPE_HARDWARE;
            perf_config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
            break;
        case 5: /* branch_misses */
            perf_type = PERF_TYPE_HARDWARE;
            perf_config = PERF_COUNT_HW_BRANCH_MISSES;
            break;
        case 6: /* page_faults */
            perf_type = PERF_TYPE_SOFTWARE;
            perf_config = PERF_COUNT_SW_PAGE_FAULTS;
            break;
        case 7: /* context_switches */
            perf_type = PERF_TYPE_SOFTWARE;
            perf_config = PERF_COUNT_SW_CONTEXT_SWITCHES;
            break;
        case 8: /* cpu_migrations */
            perf_type = PERF_TYPE_SOFTWARE;
            perf_config = PERF_COUNT_SW_CPU_MIGRATIONS;
            break;
        default:
            fprintf(stderr, "attach_perf: unknown counter value %d\n", ks_attr.counter);
            return -1;
    }
    
    /* Build struct perf_event_attr */
    struct perf_event_attr attr = {};
    attr.type = perf_type;
    attr.size = sizeof(struct perf_event_attr);
    attr.config = perf_config;
    attr.sample_period = ks_attr.period > 0 ? ks_attr.period : 1000000;
    attr.wakeup_events = ks_attr.wakeup > 0 ? ks_attr.wakeup : 1;
    attr.inherit = ks_attr.inherit ? 1 : 0;
    attr.exclude_kernel = ks_attr.exclude_kernel ? 1 : 0;
    attr.exclude_user = ks_attr.exclude_user ? 1 : 0;
    attr.disabled = 1;
    
    int cpu = ks_attr.cpu >= 0 ? ks_attr.cpu : 0;
    int pid = ks_attr.pid;  /* -1 = all threads on cpu */
    
    /* Open perf event */
    int perf_fd = (int)syscall(SYS_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd < 0) {
        fprintf(stderr, "attach_perf: perf_event_open failed: %s\n", strerror(errno));
        return -1;
    }
    
    /* Find bpf_program from skeleton and attach */
    if (!obj) {
        fprintf(stderr, "attach_perf: BPF skeleton not loaded\n");
        close(perf_fd);
        return -1;
    }
    
    struct bpf_program *prog = NULL;
    bpf_object__for_each_program(prog, obj->obj) {
        if (bpf_program__fd(prog) == prog_fd) {
            break;
        }
    }
    if (!prog) {
        fprintf(stderr, "attach_perf: bpf_program not found for fd %d\n", prog_fd);
        close(perf_fd);
        return -1;
    }
    
    struct bpf_link *link = bpf_program__attach_perf_event(prog, perf_fd);
    if (!link) {
        fprintf(stderr, "attach_perf: bpf_program__attach_perf_event failed: %s\n", strerror(errno));
        close(perf_fd);
        return -1;
    }
    
    /* ioctl to enable the perf event */
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    
    printf("perf event attached (counter=%d, pid=%d, cpu=%d)\n", ks_attr.counter, pid, cpu);
    return 0;
}



int main(int argc, char **argv) {
    int32_t __func_call_2;
    // Parse command line arguments
    struct Args args = parse_arguments(argc, argv);
    // Implicit eBPF skeleton loading - makes global variables immediately accessible
    if (!obj) {
        obj = perf_branch_miss_ebpf__open_and_load();
        if (!obj) {
            fprintf(stderr, "Failed to open and load eBPF skeleton\n");
            return 1;
        }
    }
    // Note: Skeleton loaded implicitly above, load() now gets program handles
    
    uint32_t __unop_1 = -1;
    ks_perf_event_attr __struct_literal_0 = {.counter = branch_misses, .pid = __unop_1, .cpu = 0, .period = 1000000, .wakeup = 1, .inherit = false, .exclude_kernel = false, .exclude_user = false};
    ks_perf_event_attr var_attr = __struct_literal_0;
    int32_t var_prog;
    var_prog = get_bpf_program_handle("on_branch_miss");
    if (var_prog < 0) {
        fprintf(stderr, "Failed to get BPF program handle\n");
        return 1;
    }
    __func_call_2 = attach_perf_by_attr(var_prog, var_attr);
    return 0;
}
