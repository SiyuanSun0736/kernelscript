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
#include <sys/ioctl.h>
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


// Global attachment storage for tracking active program attachments
struct attachment_entry {
    int prog_fd;
    char target[128];
    uint32_t flags;
    struct bpf_link *link;    // For kprobe/tracepoint programs (NULL for XDP)
    int ifindex;              // For XDP programs (0 for kprobe/tracepoint)
  int perf_fd;              // For perf_event programs (-1 otherwise)
    enum bpf_prog_type type;
    struct attachment_entry *next;
};

static struct attachment_entry *attached_programs = NULL;
static pthread_mutex_t attachment_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper function to find attachment entry
static struct attachment_entry *find_attachment(int prog_fd) {
    pthread_mutex_lock(&attachment_mutex);
    struct attachment_entry *current = attached_programs;
    while (current) {
        if (current->prog_fd == prog_fd) {
            pthread_mutex_unlock(&attachment_mutex);
            return current;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&attachment_mutex);
    return NULL;
}

// Helper function to remove attachment entry
static void remove_attachment(int prog_fd) {
    pthread_mutex_lock(&attachment_mutex);
    struct attachment_entry **current = &attached_programs;
    while (*current) {
        if ((*current)->prog_fd == prog_fd) {
            struct attachment_entry *to_remove = *current;
            *current = (*current)->next;
            free(to_remove);
            break;
        }
        current = &(*current)->next;
    }
    pthread_mutex_unlock(&attachment_mutex);
}

// Helper function to add attachment entry
static int add_attachment(int prog_fd, const char *target, uint32_t flags, 
             struct bpf_link *link, int ifindex, int perf_fd,
             enum bpf_prog_type type) {
    struct attachment_entry *entry = malloc(sizeof(struct attachment_entry));
    if (!entry) {
        fprintf(stderr, "Failed to allocate memory for attachment entry\n");
        return -1;
    }
    
    entry->prog_fd = prog_fd;
    strncpy(entry->target, target, sizeof(entry->target) - 1);
    entry->target[sizeof(entry->target) - 1] = '\0';
    entry->flags = flags;
    entry->link = link;
    entry->ifindex = ifindex;
    entry->perf_fd = perf_fd;
    entry->type = type;
    
    pthread_mutex_lock(&attachment_mutex);
    entry->next = attached_programs;
    attached_programs = entry;
    pthread_mutex_unlock(&attachment_mutex);
    
    return 0;
}


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

int attach_bpf_program_by_fd(int prog_fd, const char *target, int flags) {
    if (prog_fd < 0) {
        fprintf(stderr, "Invalid program file descriptor: %d\n", prog_fd);
        return -1;
    }
    
    // Check if program is already attached
    if (find_attachment(prog_fd)) {
        fprintf(stderr, "Program with fd %d is already attached. Use detach() first.\n", prog_fd);
        return -1;
    }
    
    // Get program type from file descriptor  
    struct bpf_prog_info info = {};
    uint32_t info_len = sizeof(info);
    int ret = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (ret) {
        fprintf(stderr, "Failed to get program info: %s\n", strerror(errno));
        return -1;
    }
    
    switch (info.type) {
        case BPF_PROG_TYPE_XDP: {
            int ifindex = if_nametoindex(target);
            if (ifindex == 0) {
                fprintf(stderr, "Failed to get interface index for '%s'\n", target);
                return -1;
            }
            
            // Use modern libbpf API for XDP attachment
            ret = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
            if (ret) {
                fprintf(stderr, "Failed to attach XDP program to interface '%s': %s\n", target, strerror(errno));
                return -1;
            }
            
            // Store XDP attachment (no bpf_link for XDP)
            if (add_attachment(prog_fd, target, flags, NULL, ifindex, -1, BPF_PROG_TYPE_XDP) != 0) {
                // If storage fails, detach and return error
                bpf_xdp_detach(ifindex, flags, NULL);
                return -1;
            }
            
            printf("XDP attached to interface: %s\n", target);
            return 0;
        }
        case BPF_PROG_TYPE_KPROBE: {
            // For probe programs, target should be the kernel function name (e.g., "sys_read")
            // Use libbpf high-level API for probe attachment
            
            // Get the bpf_program struct from the object and file descriptor
            struct bpf_program *prog = NULL;

            // Find the program object corresponding to this fd
            // We need to get the program from the skeleton object
            if (!obj) {
                fprintf(stderr, "eBPF skeleton not loaded for probe attachment\n");
                return -1;
            }

            bpf_object__for_each_program(prog, obj->obj) {
                if (bpf_program__fd(prog) == prog_fd) {
                    break;
                }
            }

            if (!prog) {
                fprintf(stderr, "Failed to find bpf_program for fd %d\n", prog_fd);
                return -1;
            }

            // BPF_PROG_TYPE_KPROBE programs always use kprobe attachment
            // (these are generated from @probe("target+offset"))
            struct bpf_link *link = bpf_program__attach_kprobe(prog, false, target);
            long link_err = libbpf_get_error(link);
            if (link_err) {
              fprintf(stderr, "Failed to attach kprobe to function '%s': %s\n", target, strerror((int)-link_err));
                return -1;
            }
            printf("Kprobe attached to function: %s\n", target);
            
            // Store probe attachment for later cleanup
            if (add_attachment(prog_fd, target, flags, link, 0, -1, BPF_PROG_TYPE_KPROBE) != 0) {
                // If storage fails, destroy link and return error
                bpf_link__destroy(link);
                return -1;
            }
            
            return 0;
        }
        case BPF_PROG_TYPE_TRACING: {
            // For fentry/fexit programs (BPF_PROG_TYPE_TRACING)
            // These are loaded with SEC("fentry/target") or SEC("fexit/target")
            
            // Get the bpf_program struct from the object and file descriptor
            struct bpf_program *prog = NULL;

            // Find the program object corresponding to this fd
            if (!obj) {
                fprintf(stderr, "eBPF skeleton not loaded for tracing program attachment\n");
                return -1;
            }

            bpf_object__for_each_program(prog, obj->obj) {
                if (bpf_program__fd(prog) == prog_fd) {
                    break;
                }
            }

            if (!prog) {
                fprintf(stderr, "Failed to find bpf_program for fd %d\n", prog_fd);
                return -1;
            }

            // For fentry/fexit programs, use bpf_program__attach_trace
            struct bpf_link *link = bpf_program__attach_trace(prog);
            long link_err = libbpf_get_error(link);
            if (link_err) {
              fprintf(stderr, "Failed to attach fentry/fexit program to function '%s': %s\n", target, strerror((int)-link_err));
                return -1;
            }
            
            printf("Fentry/fexit program attached to function: %s\n", target);
            
            // Store tracing attachment for later cleanup
            if (add_attachment(prog_fd, target, flags, link, 0, -1, BPF_PROG_TYPE_TRACING) != 0) {
                // If storage fails, destroy link and return error
                bpf_link__destroy(link);
                return -1;
            }
            
            return 0;
        }
        case BPF_PROG_TYPE_TRACEPOINT: {
            // For regular tracepoint programs, target should be in "category:event" format (e.g., "sched:sched_switch")
            // Split into category and event name for attachment
            
            // Make a copy of target since we need to modify it
            char target_copy[256];
            strncpy(target_copy, target, sizeof(target_copy) - 1);
            target_copy[sizeof(target_copy) - 1] = '\0';
            
            char *category = target_copy;
            char *event_name = NULL;
            char *colon_pos = strchr(target_copy, ':');
            if (colon_pos) {
                // Null-terminate category and get event name
                *colon_pos = '\0';
                event_name = colon_pos + 1;
            } else {
                fprintf(stderr, "Invalid tracepoint target format: '%s'. Expected 'category:event'\n", target);
                return -1;
            }
            
            // Get the bpf_program struct from the object and file descriptor
            struct bpf_program *prog = NULL;

            // Find the program object corresponding to this fd
            // We need to get the program from the skeleton object
            if (!obj) {
                fprintf(stderr, "eBPF skeleton not loaded for tracepoint attachment\n");
                return -1;
            }

            bpf_object__for_each_program(prog, obj->obj) {
                if (bpf_program__fd(prog) == prog_fd) {
                    break;
                }
            }

            if (!prog) {
                fprintf(stderr, "Failed to find bpf_program for fd %d\n", prog_fd);
                return -1;
            }

            // Use libbpf's high-level tracepoint attachment API with category and event name
            struct bpf_link *link = bpf_program__attach_tracepoint(prog, category, event_name);
            long link_err = libbpf_get_error(link);
            if (link_err) {
              fprintf(stderr, "Failed to attach tracepoint to '%s:%s': %s\n", category, event_name, strerror((int)-link_err));
                return -1;
            }
            
            // Store tracepoint attachment for later cleanup
            if (add_attachment(prog_fd, target, flags, link, 0, -1, BPF_PROG_TYPE_TRACEPOINT) != 0) {
                // If storage fails, destroy link and return error
                bpf_link__destroy(link);
                return -1;
            }
            
            printf("Tracepoint attached to: %s:%s\n", category, event_name);
            
            return 0;
        }
        case BPF_PROG_TYPE_SCHED_CLS: {
            // For TC (Traffic Control) programs, target should be the interface name (e.g., "eth0")
            
            int ifindex = if_nametoindex(target);
            if (ifindex == 0) {
                fprintf(stderr, "Failed to get interface index for '%s'\n", target);
                return -1;
            }
            
            // Get the bpf_program struct from the object and file descriptor
            struct bpf_program *prog = NULL;

            // Find the program object corresponding to this fd
            if (!obj) {
                fprintf(stderr, "eBPF skeleton not loaded for TC attachment\n");
                return -1;
            }

            bpf_object__for_each_program(prog, obj->obj) {
                if (bpf_program__fd(prog) == prog_fd) {
                    break;
                }
            }

            if (!prog) {
                fprintf(stderr, "Failed to find bpf_program for fd %d\n", prog_fd);
                return -1;
            }

            // Set up TCX options using LIBBPF_OPTS macro
            LIBBPF_OPTS(bpf_tcx_opts, tcx_opts);

            // Use libbpf's TC attachment API
            struct bpf_link *link = bpf_program__attach_tcx(prog, ifindex, &tcx_opts);
            long link_err = libbpf_get_error(link);
            if (link_err) {
              fprintf(stderr, "Failed to attach TC program to interface '%s': %s\n", target, strerror((int)-link_err));
                return -1;
            }
            
            // Store TC attachment for later cleanup (flags no longer needed for direction)
            if (add_attachment(prog_fd, target, 0, link, ifindex, -1, BPF_PROG_TYPE_SCHED_CLS) != 0) {
                // If storage fails, destroy link and return error
                bpf_link__destroy(link);
                return -1;
            }
            
            printf("TC program attached to interface: %s\n", target);
            
            return 0;
        }
        case BPF_PROG_TYPE_PERF_EVENT: {
            // For perf_event programs, target should be a perf_fd as a decimal string
            // (the perf_fd is obtained via perf_event_open by the caller or attach_perf_by_attr)
            char *endptr = NULL;
            long perf_fd_long = strtol(target, &endptr, 10);
            if (endptr == target || *endptr != '\0' || perf_fd_long < 0) {
                fprintf(stderr, "BPF_PROG_TYPE_PERF_EVENT: invalid perf_fd target '%s'. "
                        "For perf event programs, pass an already-opened perf_fd as a decimal string, "
                        "or use attach_perf_by_attr() instead.\n", target);
                return -1;
            }
            int perf_fd_val = (int)perf_fd_long;

            if (!obj) {
                fprintf(stderr, "eBPF skeleton not loaded for perf_event attachment\n");
                return -1;
            }

            struct bpf_program *prog = NULL;
            bpf_object__for_each_program(prog, obj->obj) {
                if (bpf_program__fd(prog) == prog_fd) {
                    break;
                }
            }
            if (!prog) {
                fprintf(stderr, "Failed to find bpf_program for fd %d\n", prog_fd);
                return -1;
            }

            if (ioctl(perf_fd_val, PERF_EVENT_IOC_RESET, 0) != 0) {
                fprintf(stderr, "Failed to reset perf event fd %d: %s\n", perf_fd_val, strerror(errno));
                return -1;
            }

            struct bpf_link *link = bpf_program__attach_perf_event(prog, perf_fd_val);
            long link_err = libbpf_get_error(link);
            if (link_err) {
                fprintf(stderr, "Failed to attach perf_event program to perf_fd %d: %s\n", perf_fd_val, strerror((int)-link_err));
                return -1;
            }

            if (ioctl(perf_fd_val, PERF_EVENT_IOC_ENABLE, 0) != 0) {
                fprintf(stderr, "Failed to enable perf event fd %d: %s\n", perf_fd_val, strerror(errno));
                bpf_link__destroy(link);
                return -1;
            }

            if (add_attachment(prog_fd, target, flags, link, 0, perf_fd_val, BPF_PROG_TYPE_PERF_EVENT) != 0) {
                ioctl(perf_fd_val, PERF_EVENT_IOC_DISABLE, 0);
                bpf_link__destroy(link);
                return -1;
            }

            printf("Perf event program attached to perf_fd: %d\n", perf_fd_val);
            return 0;
        }
        default:
            fprintf(stderr, "Unsupported program type for attachment: %d\n", info.type);
            return -1;
    }
}

void detach_bpf_program_by_fd(int prog_fd) {
    if (prog_fd < 0) {
        fprintf(stderr, "Invalid program file descriptor: %d\n", prog_fd);
        return;
    }
    
    // Find the attachment entry
    struct attachment_entry *entry = find_attachment(prog_fd);
    if (!entry) {
        fprintf(stderr, "No active attachment found for program fd %d\n", prog_fd);
        return;
    }
    
    // Detach based on program type
    switch (entry->type) {
        case BPF_PROG_TYPE_XDP: {
            int ret = bpf_xdp_detach(entry->ifindex, entry->flags, NULL);
            if (ret) {
                fprintf(stderr, "Failed to detach XDP program from interface: %s\n", strerror(errno));
            } else {
                printf("XDP detached from interface index: %d\n", entry->ifindex);
            }
            break;
        }
        case BPF_PROG_TYPE_KPROBE: {
            if (entry->link) {
                bpf_link__destroy(entry->link);
                printf("Kprobe detached from: %s\n", entry->target);
            } else {
                fprintf(stderr, "Invalid kprobe link for program fd %d\n", prog_fd);
            }
            break;
        }
        case BPF_PROG_TYPE_TRACING: {
            if (entry->link) {
                bpf_link__destroy(entry->link);
                printf("Fentry/fexit program detached from: %s\n", entry->target);
            } else {
                fprintf(stderr, "Invalid tracing program link for program fd %d\n", prog_fd);
            }
            break;
        }
        case BPF_PROG_TYPE_TRACEPOINT: {
            if (entry->link) {
                bpf_link__destroy(entry->link);
                printf("Tracepoint detached from: %s\n", entry->target);
            } else {
                fprintf(stderr, "Invalid tracepoint link for program fd %d\n", prog_fd);
            }
            break;
        }
        case BPF_PROG_TYPE_SCHED_CLS: {
            if (entry->link) {
                bpf_link__destroy(entry->link);
                printf("TC program detached from interface: %s\n", entry->target);
            } else {
                fprintf(stderr, "Invalid TC program link for program fd %d\n", prog_fd);
            }
            break;
        }
        case BPF_PROG_TYPE_PERF_EVENT: {
          if (entry->perf_fd >= 0 && ioctl(entry->perf_fd, PERF_EVENT_IOC_DISABLE, 0) != 0) {
            fprintf(stderr, "Failed to disable perf event: %s\n", strerror(errno));
          }
            if (entry->link) {
                bpf_link__destroy(entry->link);
            } else {
                fprintf(stderr, "Invalid perf event link for program fd %d\n", prog_fd);
            }
          if (entry->perf_fd >= 0) {
            close(entry->perf_fd);
          }
          printf("Perf event program detached\n");
            break;
        }
        default:
            fprintf(stderr, "Unsupported program type for detachment: %d\n", entry->type);
            break;
    }
    
    // Remove from tracking
    remove_attachment(prog_fd);
}

int ks_open_perf_event(ks_perf_event_attr ks_attr) {
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
            fprintf(stderr, "ks_open_perf_event: unknown counter value %d\n", ks_attr.counter);
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

    int cpu = ks_attr.cpu;
    int pid = ks_attr.pid;

    if (pid < -1) {
        fprintf(stderr, "ks_open_perf_event: invalid pid %d (expected >= -1)\n", pid);
        return -1;
    }
    if (cpu < -1) {
        fprintf(stderr, "ks_open_perf_event: invalid cpu %d (expected >= -1)\n", cpu);
        return -1;
    }
    if (pid == -1 && cpu == -1) {
        fprintf(stderr, "ks_open_perf_event: system-wide perf events require an explicit cpu >= 0\n");
        return -1;
    }

    int perf_fd = (int)syscall(SYS_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd < 0) {
        fprintf(stderr, "ks_open_perf_event: perf_event_open failed: %s\n", strerror(errno));
        return -1;
    }
    return perf_fd;
}



int main(void) {
    // No arguments to parse
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
    int __ks_pfd_1 = ks_open_perf_event(var_attr);
    char __ks_pstr_2[32];
    snprintf(__ks_pstr_2, sizeof(__ks_pstr_2), "%d", __ks_pfd_1);
    attach_bpf_program_by_fd(var_prog, __ks_pstr_2, 0);
    detach_bpf_program_by_fd(var_prog);
    return 0;
}
