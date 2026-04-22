#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static volatile sig_atomic_t exiting;

struct perf_target {
    int *pfds;
    struct bpf_link **links;
    size_t count;
    size_t capacity;
};

static void on_signal(int signo)
{
    (void)signo;
    exiting = 1;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim) == 0)
        return 0;

    if (errno == EPERM)
        return 0;

    perror("setrlimit(RLIMIT_MEMLOCK)");
    return -1;
}

static int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, -1, 0);
}

static int read_perf_event_paranoid(void)
{
    FILE *f;
    int paranoid = -2; /* unknown */

    f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    if (f) {
        if (fscanf(f, "%d", &paranoid) != 1)
            paranoid = -2;
        fclose(f);
    }
    return paranoid;
}

static void diagnose_perf_event_open_error(int saved_errno, pid_t pid, int cpu)
{
    if (saved_errno == ENOSYS) {
        fprintf(stderr, "perf_event_open: kernel does not support perf events "
                        "(CONFIG_PERF_EVENTS not compiled in)\n");
    } else if (saved_errno == ENOENT) {
        fprintf(stderr, "perf_event_open: hardware event not available on this "
                        "CPU or architecture (common in VMs without PMU passthrough)\n");
    } else if (saved_errno == EOPNOTSUPP) {
        fprintf(stderr, "perf_event_open: event attribute not supported on this platform\n"
                        "  hint: hardware counters often require bare-metal or explicit "
                        "VMX/KVM perf passthrough\n");
    } else if (saved_errno == EACCES || saved_errno == EPERM) {
        int paranoid = read_perf_event_paranoid();
        if (paranoid >= 0)
            fprintf(stderr, "perf_event_open: permission denied "
                            "(perf_event_paranoid=%d)\n"
                            "  hint: run as root, use CAP_PERFMON, or:\n"
                            "        echo 0 > /proc/sys/kernel/perf_event_paranoid\n",
                    paranoid);
        else
            fprintf(stderr, "perf_event_open(pid=%d, cpu=%d): permission denied\n",
                    pid, cpu);
    } else {
        fprintf(stderr, "perf_event_open(pid=%d, cpu=%d) failed: %s\n",
                pid, cpu, strerror(saved_errno));
    }
}

static int parse_long_arg(const char *text, const char *name, long min_value, long *value)
{
    char *end = NULL;
    long parsed;

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < min_value) {
        fprintf(stderr, "invalid %s: %s\n", name, text);
        return -1;
    }

    *value = parsed;
    return 0;
}

static int perf_target_grow(struct perf_target *target)
{
    struct bpf_link **new_links;
    int *new_pfds;
    size_t index;
    size_t new_capacity;

    new_capacity = target->capacity ? target->capacity * 2 : 4;

    new_pfds = malloc(new_capacity * sizeof(*new_pfds));
    new_links = calloc(new_capacity, sizeof(*new_links));
    if (!new_pfds || !new_links) {
        free(new_pfds);
        free(new_links);
        return -1;
    }

    for (index = 0; index < new_capacity; index++)
        new_pfds[index] = -1;

    for (index = 0; index < target->count; index++) {
        new_pfds[index] = target->pfds[index];
        new_links[index] = target->links[index];
    }

    free(target->pfds);
    free(target->links);

    target->pfds = new_pfds;
    target->links = new_links;
    target->capacity = new_capacity;
    return 0;
}

static int perf_target_append(struct perf_target *target, int pfd, struct bpf_link *link)
{
    if (target->count == target->capacity) {
        if (perf_target_grow(target) != 0)
            return -1;
    }

    target->pfds[target->count] = pfd;
    target->links[target->count] = link;
    target->count += 1;
    return 0;
}

static int resolve_bpf_object_path(char *path, size_t path_size)
{
    char exe_path[PATH_MAX];
    char *slash;
    int written;
    ssize_t length;

    length = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (length < 0) {
        written = snprintf(path, path_size, "perf.bpf.o");
        return (written >= 0 && (size_t)written < path_size) ? 0 : -1;
    }

    exe_path[length] = '\0';
    slash = strrchr(exe_path, '/');
    if (!slash) {
        written = snprintf(path, path_size, "perf.bpf.o");
        return (written >= 0 && (size_t)written < path_size) ? 0 : -1;
    }

    *slash = '\0';
    written = snprintf(path, path_size, "%s/perf.bpf.o", exe_path);
    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

static void perf_target_cleanup(struct perf_target *target)
{
    size_t index;

    for (index = 0; index < target->count; index++) {
        if (target->links[index])
            bpf_link__destroy(target->links[index]);
        if (target->pfds[index] >= 0)
            close(target->pfds[index]);
    }

    free(target->pfds);
    free(target->links);
    memset(target, 0, sizeof(*target));
}

static int open_and_attach_one(struct bpf_program *prog,
                               struct perf_event_attr *attr,
                               struct perf_target *target,
                               pid_t pid,
                               int cpu)
{
    long link_err;
    int pfd;
    struct bpf_link *link;

    pfd = sys_perf_event_open(attr, pid, cpu);
    if (pfd < 0) {
        diagnose_perf_event_open_error(errno, pid, cpu);
        return -1;
    }

    link = bpf_program__attach_perf_event(prog, pfd);
    link_err = libbpf_get_error(link);
    if (link_err != 0) {
        fprintf(stderr, "bpf_program__attach_perf_event failed: %s\n", strerror((int)-link_err));
        close(pfd);
        return -1;
    }

    if (perf_target_append(target, pfd, link) != 0) {
        fprintf(stderr, "failed to grow perf target arrays\n");
        bpf_link__destroy(link);
        close(pfd);
        return -1;
    }

    return 0;
}

static int attach_all_threads_of_pid(struct bpf_program *prog,
                                     struct perf_event_attr *attr,
                                     struct perf_target *target,
                                     pid_t pid)
{
    char task_dir[64];
    DIR *dir;
    struct dirent *entry;
    int attached = 0;

    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);
    dir = opendir(task_dir);
    if (!dir) {
        fprintf(stderr, "opendir(%s) failed: %s\n", task_dir, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        pid_t tid;

        if (entry->d_name[0] == '.')
            continue;

        tid = (pid_t)strtol(entry->d_name, NULL, 10);
        if (tid <= 0)
            continue;

        if (open_and_attach_one(prog, attr, target, tid, -1) != 0) {
            closedir(dir);
            return -1;
        }

        attached += 1;
    }

    closedir(dir);

    if (attached == 0) {
        fprintf(stderr, "no thread found under /proc/%d/task\n", pid);
        return -1;
    }

    return 0;
}

static int enable_all(struct perf_target *target)
{
    size_t index;

    for (index = 0; index < target->count; index++) {
        if (ioctl(target->pfds[index], PERF_EVENT_IOC_RESET, 0) != 0) {
            fprintf(stderr, "PERF_EVENT_IOC_RESET failed: %s\n", strerror(errno));
            return -1;
        }

        if (ioctl(target->pfds[index], PERF_EVENT_IOC_ENABLE, 0) != 0) {
            fprintf(stderr, "PERF_EVENT_IOC_ENABLE failed: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}

static void disable_all(struct perf_target *target)
{
    size_t index;

    for (index = 0; index < target->count; index++)
        ioctl(target->pfds[index], PERF_EVENT_IOC_DISABLE, 0);
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s -p PID\n"
            "  %s -C CPU\n\n"
            "Modes:\n"
            "  -p PID   attach to all current threads of PID, aggregate all CPU data\n"
            "  -C CPU   no PID mode, collect only the specified CPU\n",
            prog, prog);
}

static int read_counts(int map_fd, __u64 *values, int ncpus)
{
    __u32 key = 0;

    memset(values, 0, ncpus * sizeof(*values));
    if (bpf_map_lookup_elem(map_fd, &key, values) != 0) {
        fprintf(stderr, "bpf_map_lookup_elem failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(struct perf_event_attr),
        .config = PERF_COUNT_HW_BRANCH_MISSES,
        .sample_period = 1,
        .wakeup_events = 1,
        .disabled = 1,
    };
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct perf_target target = {};
    __u64 *values = NULL;
    char bpf_object_path[PATH_MAX];
    int map_fd;
    int ncpus;
    int cpu = -1;
    pid_t pid = -1;
    int opt;
    int err = 1;
    int online_cpus;

    while ((opt = getopt(argc, argv, "p:C:h")) != -1) {
        switch (opt) {
        case 'p':
            {
                long parsed_pid;

                if (parse_long_arg(optarg, "pid", 1, &parsed_pid) != 0)
                    return 1;
                pid = (pid_t)parsed_pid;
            }
            break;
        case 'C':
            {
                long parsed_cpu;

                if (parse_long_arg(optarg, "cpu", 0, &parsed_cpu) != 0)
                    return 1;
                cpu = (int)parsed_cpu;
            }
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (pid > 0 && cpu >= 0) {
        fprintf(stderr, "-p and -C cannot be used together\n");
        return 1;
    }

    if (pid <= 0 && cpu < 0) {
        fprintf(stderr, "without -p you must provide -C\n");
        return 1;
    }

    if (signal(SIGINT, on_signal) == SIG_ERR || signal(SIGTERM, on_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    if (bump_memlock_rlimit() != 0)
        return 1;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (resolve_bpf_object_path(bpf_object_path, sizeof(bpf_object_path)) != 0) {
        fprintf(stderr, "failed to resolve perf.bpf.o path: %s\n", strerror(errno));
        goto out;
    }

    obj = bpf_object__open_file(bpf_object_path, NULL);
    {
        long open_err = libbpf_get_error(obj);

        if (open_err != 0) {
            fprintf(stderr, "bpf_object__open_file(%s) failed: %s\n",
                    bpf_object_path, strerror((int)-open_err));
            obj = NULL;
            goto out;
        }
    }

    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "bpf_object__load failed: %s\n", strerror(errno));
        goto out;
    }

    prog = bpf_object__find_program_by_name(obj, "on_branch_miss");
    if (!prog) {
        fprintf(stderr, "cannot find BPF program on_branch_miss\n");
        goto out;
    }

    map = bpf_object__find_map_by_name(obj, "branch_misses");
    if (!map) {
        fprintf(stderr, "cannot find BPF map branch_misses\n");
        goto out;
    }

    map_fd = bpf_map__fd(map);
    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        fprintf(stderr, "libbpf_num_possible_cpus failed: %d\n", ncpus);
        goto out;
    }

    values = calloc(ncpus, sizeof(*values));
    if (!values) {
        fprintf(stderr, "calloc failed\n");
        goto out;
    }

    if (pid > 0) {
        if (attach_all_threads_of_pid(prog, &attr, &target, pid) != 0)
            goto out;
        printf("attached to pid %d across %zu thread(s), collecting all CPU data\n",
               pid, target.count);
    } else {
        if (open_and_attach_one(prog, &attr, &target, -1, cpu) != 0)
            goto out;
        printf("attached to cpu %d only\n", cpu);
    }

    if (enable_all(&target) != 0)
        goto out;

    online_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (online_cpus <= 0)
        online_cpus = ncpus;

    while (!exiting) {
        int index;

        sleep(1);

        if (read_counts(map_fd, values, ncpus) != 0)
            goto out;

        if (pid > 0) {
            unsigned long long total = 0;

            printf("branch_miss per cpu:");
            for (index = 0; index < online_cpus && index < ncpus; index++) {
                unsigned long long count = values[index];

                total += count;
                printf(" cpu%d=%llu", index, count);
            }
            printf(" total=%llu\n", total);
        } else {
            if (cpu >= ncpus) {
                fprintf(stderr, "cpu %d exceeds possible cpu count %d\n", cpu, ncpus);
                goto out;
            }
            printf("cpu%d branch_miss=%llu\n", cpu, (unsigned long long)values[cpu]);
        }
    }

    err = 0;

out:
    disable_all(&target);
    perf_target_cleanup(&target);
    free(values);
    if (obj)
        bpf_object__close(obj);
    return err;
}