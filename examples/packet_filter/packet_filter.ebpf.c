#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* eBPF Dynptr API integration for enhanced pointer safety */
/* Using system-provided bpf_dynptr_* helper functions from bpf_helpers.h */

/* Enhanced dynptr safety macros */
#define DYNPTR_SAFE_ACCESS(dynptr, offset, size, type) \
    ({ \
        type *__ptr = (type*)bpf_dynptr_data(dynptr, offset, sizeof(type)); \
        __ptr ? *__ptr : (type){0}; \
    })

#define DYNPTR_SAFE_WRITE(dynptr, offset, value, type) \
    ({ \
        type __tmp = (value); \
        bpf_dynptr_write(dynptr, offset, &__tmp, sizeof(type), 0); \
    })

#define DYNPTR_SAFE_READ(dst, dynptr, offset, type) \
    bpf_dynptr_read(dst, sizeof(type), dynptr, offset, 0)

/* Fallback macros for regular pointer operations */
#define SAFE_DEREF(ptr) \
    ({ \
        typeof(*ptr) __val = {0}; \
        if (ptr) { \
            __builtin_memcpy(&__val, ptr, sizeof(__val)); \
        } \
        __val; \
    })

#define SAFE_PTR_ACCESS(ptr, field) \
    ({ \
        typeof((ptr)->field) __val = {0}; \
        if (ptr) { \
            __val = (ptr)->field; \
        } \
        __val; \
    })

SEC("xdp")
enum xdp_action packet_filter(struct xdp_md* ctx) {
    __u8 __binop_3;
    __u64 __binop_2;
    __u8* __arrow_access_1;
    __u8* __arrow_access_0;
    __arrow_access_0 = (void*)(long)ctx->data_end;
    __arrow_access_1 = (void*)(long)ctx->data;
    __binop_2 = (((__u64)__arrow_access_0) - ((__u64)__arrow_access_1));
    __u64 packet_size = __binop_2;
    __binop_3 = (packet_size > 1500);
    if (__binop_3) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";