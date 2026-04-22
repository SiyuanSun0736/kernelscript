#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} branch_misses SEC(".maps");

SEC("perf_event")
int on_branch_miss(struct bpf_perf_event_data *ctx)
{
    (void)ctx;

    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&branch_misses, &key);

    if (count)
        *count += 1;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";