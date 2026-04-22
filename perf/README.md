# perf branch_miss 示例

这个目录包含一个最小的 `SEC("perf_event")` eBPF 示例：

- `perf.bpf.c`：内核态 perf_event 程序，使用 per-CPU map 统计 branch miss 次数。
- `perf_user.c`：用户态加载器，负责 `perf_event_open + bpf_program__attach_perf_event`。
- `Makefile`：独立构建脚本。

## 构建

```bash
cd /home/ssy/kernelscript/perf
make
```

## 运行

按 PID 模式运行时，会遍历 `/proc/PID/task` 下当前所有线程，并对每个线程用 `cpu = -1` 打开 perf event。这样线程在哪个 CPU 上运行，就会落到对应 CPU 的 per-CPU 统计槽位里。

```bash
cd /home/ssy/kernelscript/perf
sudo ./perf_user -p 1234
```

不指定 PID 时，必须显式给 CPU，此时程序只会采集指定 CPU 上的系统级 branch miss 数据。

```bash
cd /home/ssy/kernelscript/perf
sudo ./perf_user -C 2
```

## 当前实现边界

- PID 模式只会附着到启动时刻已经存在的线程，不会自动追踪后续新建线程。
- `sample_period = 1` 适合做最小验证，不适合高负载长期运行。
- 用户态现在会优先从可执行文件所在目录查找 `perf.bpf.o`，因此不要求必须在当前目录运行。