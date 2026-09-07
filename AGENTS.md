# AGENTS.md — mimic 性能工作与测试手册

本文档沉淀历次性能优化与 Podman 实测中验证过的知识。修改 BPF 数据面代码前必读。

## 构建（macOS 经 Podman）

```bash
# 默认构建（kfunc，需内核模块，仅生产机可加载验证）
podman run --rm -v /Users/eric/WorkSpace/mimic-master:/work \
  localhost/mimic-build-base bash -c 'cd /work && make build-cli -j$(nproc)'
# 容器内功能/性能测试必须用 kprobe 版（无模块也可跑，checksum hack 自动降级）：
podman run --rm -v /Users/eric/WorkSpace/mimic-master:/work \
  localhost/mimic-build-base bash -c 'cd /work && make build-cli -j$(nproc) CHECKSUM_HACK=kprobe'
```

注意：宿主目录是 git worktree，容器内 `git stash` 不可用（`.git` 指向宿主绝对路径）。
基线对照做法：宿主机 `git stash push bpf/` → 容器构建 `*_before` → 宿主机 `git stash pop` → 容器构建 `*_after`。

## 测试（全部进特权容器跑）

```bash
# 单元测试全量（bats，8 个，含 v4/v6 握手缓冲与抓包校验和）
podman run --rm --privileged -v /Users/eric/WorkSpace/mimic-master:/work \
  localhost/mimic-build-base bash -c 'cd /work && bats tests'
# 冒烟：握手正确性（含建连/重传/计数）
bash .perf-baseline/handshake-test.sh /path/to/mimic
# 端到端打流：bench-run.sh <bin> <dur_s> <rate_pps> <tag> <streams>
bash .perf-baseline/bench-run.sh out/mimic 8 100000 tag1 2
# BPF 单包 CPU（最可信的优化指标，需先开统计）：
sysctl -w kernel.bpf_stats_enabled=1
# 打流前后各取一次 bpftool prog show id <EID|XID> 的 run_time_ns/run_cnt，差值相除
```

- `bench-run.sh` 的 `CPU_TICKS` 只统计 userspace 进程（数据面全在内核，恒为 ~0），看 `AGG ... mbps/loss_pct`。
- 吞吐对照必须 **ABAB 交错**：AABB 顺序会被宿主虚拟机时间漂移污染（曾观测到 ±3% 系统性偏移）。
- 单流（1400B）是 sender-bound（Python sender 上限 ~115kpps），测的是 sender 不是数据面；饱和多流看相对丢包率。

## 数据面红线（血泪：两次被 bats 抓包）

1. **`egress.c` 里有两个 `for (i < 8)`，含义完全不同**：IPv6 扩展头链（遍历，可砍到 4）vs
   IPv6 伪首部地址求和（定长 128 位 = 8 个 u16，砍一半则 v6 全部校验和错误）。
   缩减循环上界前必须确认是"遍历链"还是"定长地址"。
2. **`mangle_data`/`restore_data` 的栈 `buf` 去零初始化时**，奇长对齐修正
   `bpf_csum_diff(buf+1, l, buf, l+4)` 会读到 copy 没写过的 `buf[0]` 与尾部对齐字节。
   正确做法：热路径不定初值 + 仅奇长罕见分支入口 `__builtin_memset` 清零。
   偶包基准测不出此 bug，必须跑随机长度测试（`tests/general.bats` 的 random UDP 用例）。
3. **无锁快车道 entropy 必须用 wire seq**：`conn_padding` 的随机数由 `(seq, ack)` 推导，
   对端用**线上** seq/ack 重算 padding 长度。若用"读提示值"算 padding 而 fetch-add 后
   seq 被并发推进，padding 长度两端分歧 → 对端 strip 错位 → 全包损坏。
   当前实现 padding=0/固定值不受影响；若启用 `padding=random`，多 TX CPU 并发是已知风险。
4. **生产必须 kfunc**：kprobe 版每包多 2 个系统级 kretprobe + ~80 条指令，
   仅用于无模块的容器测试。

## iperf3 使用限制

iperf3 的 TCP 控制连接与数据共用 `-p` 端口，而 mimic 会把该端口的裸 TCP
全部按自己的握手状态机消费（SYN 被 `XDP_DROP` + 假 SYN-ACK，ACK 被 RST）。
**任何 iperf3 会话都无法跑在 mimic 管理的端口上**（已实证：客户端永久挂起）。
正确姿势（二选一）：

- iperf3 跑在隧道（WireGuard）**里面**，隧道外层 UDP 端口由 mimic 接管（README 基准即此结构）；
- mimic 管理端口的吞吐用裸 UDP 打流（`udp_node.py` / `bench-run.sh`），iperf3 只定直连天花板。

## 当前性能基线（2026-09，Podman，kprobe 版，60kpps×1400B 双向）

- BPF 单包：egress 193.6→177.3ns（-8.4%），ingress 174.0→168.5ns（-3%），合计约 -6%。
  手段：双向无锁快车道（spinlock→XADD）、settings 单次拷贝、去零初始化、ext 循环 8→4、
  ingress `log_tcp` 移到 conn 确认后。
- 代价：verifier 静态指令 tc 800→915、xdp 1204→1317（快车道复制逻辑）。
- 端到端吞吐持平（veth/bridge 瓶颈）；直连天花板：UDP 单流 2.49Gbps，TCP 4 流 232Gbps。
