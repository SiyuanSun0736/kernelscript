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
#include "struct_ops_simple.skel.h"













/* eBPF skeleton instance */
struct struct_ops_simple_ebpf *obj = NULL;













/* BPF Helper Functions (generated only when used) */


// Global attachment storage for tracking active program attachments
struct attachment_entry {
    int prog_fd;
    char target[128];
    uint32_t flags;
    struct bpf_link *link;    // For kprobe/tracepoint programs (NULL for XDP)
    int ifindex;              // For XDP programs (0 for kprobe/tracepoint)
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
                         struct bpf_link *link, int ifindex, enum bpf_prog_type type) {
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
    entry->type = type;
    
    pthread_mutex_lock(&attachment_mutex);
    entry->next = attached_programs;
    attached_programs = entry;
    pthread_mutex_unlock(&attachment_mutex);
    
    return 0;
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
            if (add_attachment(prog_fd, target, flags, NULL, ifindex, BPF_PROG_TYPE_XDP) != 0) {
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
            struct bpf_object *obj_iter;

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
            if (!link) {
                fprintf(stderr, "Failed to attach kprobe to function '%s': %s\n", target, strerror(errno));
                return -1;
            }
            printf("Kprobe attached to function: %s\n", target);
            
            // Store probe attachment for later cleanup
            if (add_attachment(prog_fd, target, flags, link, 0, BPF_PROG_TYPE_KPROBE) != 0) {
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
            if (!link) {
                fprintf(stderr, "Failed to attach fentry/fexit program to function '%s': %s\n", target, strerror(errno));
                return -1;
            }
            
            printf("Fentry/fexit program attached to function: %s\n", target);
            
            // Store tracing attachment for later cleanup
            if (add_attachment(prog_fd, target, flags, link, 0, BPF_PROG_TYPE_TRACING) != 0) {
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
            if (!link) {
                fprintf(stderr, "Failed to attach tracepoint to '%s:%s': %s\n", category, event_name, strerror(errno));
                return -1;
            }
            
            // Store tracepoint attachment for later cleanup
            if (add_attachment(prog_fd, target, flags, link, 0, BPF_PROG_TYPE_TRACEPOINT) != 0) {
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
            if (!link) {
                fprintf(stderr, "Failed to attach TC program to interface '%s': %s\n", target, strerror(errno));
                return -1;
            }
            
            // Store TC attachment for later cleanup (flags no longer needed for direction)
            if (add_attachment(prog_fd, target, 0, link, ifindex, BPF_PROG_TYPE_SCHED_CLS) != 0) {
                // If storage fails, destroy link and return error
                bpf_link__destroy(link);
                return -1;
            }
            
            printf("TC program attached to interface: %s\n", target);
            
            return 0;
        }
        default:
            fprintf(stderr, "Unsupported program type for attachment: %d\n", info.type);
            return -1;
    }
}

int attach_struct_ops_minimal_congestion_control(void) { return 0; }
int detach_struct_ops_minimal_congestion_control(void) { return 0; }

int main(void) {
    uint32_t var_result;
    uint32_t __struct_ops_reg_0;
    // No arguments to parse
    // Implicit eBPF skeleton loading - makes global variables immediately accessible
    if (!obj) {
        obj = struct_ops_simple_ebpf__open_and_load();
        if (!obj) {
            fprintf(stderr, "Failed to open and load eBPF skeleton\n");
            return 1;
        }
    }
    
    ({
    if (!obj) {
        fprintf(stderr, "eBPF skeleton not loaded for struct_ops registration\n");
        __struct_ops_reg_0 = -1;
    } else {
        struct bpf_map *map = bpf_object__find_map_by_name(obj->obj, "minimal_congestion_control");
        if (!map) {
            fprintf(stderr, "Failed to find struct_ops map 'minimal_congestion_control'\n");
            __struct_ops_reg_0 = -1;
        } else {
            struct bpf_link *link = bpf_map__attach_struct_ops(map);
            __struct_ops_reg_0 = (link != NULL) ? 0 : -1;
            if (link) bpf_link__destroy(link);
        }
    }
    __struct_ops_reg_0;
});
    return var_result;
}
