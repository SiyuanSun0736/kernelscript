// perf_branch_miss.ks
// Demonstrates @perf_event program type in KernelScript.
// The eBPF program runs on every hardware branch-miss event.
// The userspace side opens the perf event and attaches the BPF program.

@perf_event
fn on_branch_miss(ctx: *bpf_perf_event_data) -> i32 {
    return 0
}

fn main(args: Args) -> i32 {
    var attr = perf_event_attr {
        counter: branch_misses,
        pid: -1,
        cpu: 0,
        period: 1000000,
        wakeup: 1,
        inherit: false,
        exclude_kernel: false,
        exclude_user: false
    }

    var prog = load(on_branch_miss)
    attach_perf(prog, attr)

    return 0
}
