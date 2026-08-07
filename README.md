# AgentCore Runtime EFS 共享存储与隔离访问

## 核心目标

AgentCore Runtime session 能访问业务 Pod 提供的文件数据，同时确保租户间的访问隔离：
**租户只能访问自己的目录，不能访问其他租户目录、EFS 根目录或宿主文件系统的任何位置，
读写权限严格限制在自己目录内。**

## 架构设计

```
┌──────────────────┐          ┌──────────────────────────────────────────┐
│   业务 Pod        │          │   AgentCore Runtime                       │
│                    │          │   (EFS 挂载 → /mnt/shared)                │
│  EFS 挂载根目录    │          │                                          │
│  /mnt/efs/         │          │  Session X (microVM, tenant=A):          │
│  └─ tenants/       │    ←──→  │    mount namespace + pivot_root           │
│     ├─ A/          │  同一 EFS │    jail 内可见路径：                       │
│     │  ├─ input/   │          │      /workspace  = tenants/A (可写)       │
│     │  └─ output/  │          │      /usr /lib /bin ... (只读)            │
│     ├─ B/          │          │    /mnt/shared 与 tenants/B 不存在         │
│     │  ├─ input/   │          │                                          │
│     │  └─ output/  │          │  Session Y (microVM, tenant=B):          │
│     └─ ...         │          │    同上，/workspace = tenants/B           │
└──────────────────┘          └──────────────────────────────────────────┘
                                          │
                              ┌────────────┴──────────────────┐
                              │  EFS (单 AP，root=/tenants)     │
                              └───────────────────────────────┘
```

### 设计要点

| 问题 | 解法 |
|------|------|
| session 间隔离 | AgentCore 原生：每个 session 独立 microVM |
| 租户身份可信 | HMAC 签名 tenant_token（或已验签 JWT claim），调用方无法自证 |
| 租户代码的文件视图 | mount namespace + pivot_root：jail 内只有自己的目录 |
| 受守卫 API 的路径 | 拒绝绝对路径、`..` 遍历、symlink 逃逸 |
| 共享数据 | 业务 Pod 和 Runtime 挂载同一 EFS，写入即可见 |
| 不用多 AP | 1 个 EFS + 1 个 Access Point（root 限定到 /tenants）+ 1 个 Runtime |
| 扩展性 | 租户数不受 AP 上限（1万）限制 |

## 隔离机制

四层，每层独立成立：

**1. microVM 物理隔离**（AgentCore 原生）

每个 session 独立 Firecracker microVM，session 之间物理隔离，session 结束即销毁。

> **session 隔离的是"计算"，不是"存储"。** 同一租户开两个不同的 session id，
> `/workspace` 看到的是**同一份** EFS 数据 —— 这是刻意的，不是漏洞。
> 隔离边界是**租户**，不是 session；`--session-id` 换了但 `--tenant` 没换，
> 就还是同一个人。详见 [同一租户的两个 session 为什么看到同样的文件](#同一租户的两个-session-为什么看到同样的文件)。

**2. 可信租户身份**（`runtime/tenant_identity.py`）

`tenant_id` 来自 HMAC-SHA256 签名的短期 token（Runtime 侧验签），或来自 AgentCore
inbound JWT authorizer 已验签的 claim。**请求体里的 `tenant_id` 字段不被信任** ——
否则任何能调用 `InvokeAgentRuntime` 的主体都可以声明任意租户身份。
session 首次调用时绑定租户，之后该 session 不接受其他租户身份。

绑定按 `session_id` 分别记录，因此容器被复用来服务多个 session 时不会误拒。

**3. mount namespace jail**（`runtime/jail.py`）

`run_command` / `run_code` 在独立 mount namespace 中执行：

- `pivot_root` 到 tmpfs 上现搭的 rootfs，旧 root 随后 `MNT_DETACH` 移除
- jail 内只存在：只读系统目录、合成的最小 `/etc`（不含宿主账号）、
  基础 `/dev` 节点、受限 tmpfs `/tmp`、`/proc`，以及可写的 `/workspace`（= 租户目录）
- `/mnt/shared`、`/app`、其他租户目录在这个视图里**根本不存在**
- 全部 capability 丢弃 + `no_new_privs` → 无法重新 mount / chroot 逃逸
- 独立 PID / IPC / UTS namespace → 看不到、杀不到宿主进程
- 环境变量白名单重建 → AWS 凭证与签名密钥不进入 jail
- rlimit 限制 CPU / 文件大小 / 进程数 / 内存
- **jail 建立失败时拒绝执行**（exit 126），绝不退化为无隔离执行

保持 uid 0 而非降权：EFS Access Point 是 `Uid=0/Gid=0`，租户文件属主为 root，
降权后租户无法写自己的目录。丢弃所有 capability 后的 uid 0 仍受 pivot_root 约束
（逃逸所需的 `CAP_SYS_ADMIN` / `CAP_SYS_CHROOT` 已不存在）。

**4. 路径守卫**（`runtime/workspace_guard.py`）

`read_file` / `write_file` / `list_files` 的路径必须落在租户目录内：

- 绝对路径**直接拒绝**，不做静默改写
- `..` 遍历拒绝
- symlink 逃逸经 `realpath` 校验拒绝（含写路径的父目录 symlink）
- NUL 字节、空路径拒绝

### 为什么单靠 bind mount 到 /workspace 不成立

早期版本只用 `mount --bind /mnt/shared/tenants/{id} /workspace` 做隔离，
这是不成立的：bind mount 把租户目录**映射**到 `/workspace`，但没有**隐藏**
`/mnt/shared`。租户代码用绝对路径 `/mnt/shared/tenants/<其他租户>` 可以直接读写，
`cwd=/workspace` 只是起始目录，不是边界。

关键区别在于 mount namespace + `pivot_root`：新 rootfs 是现搭的，旧 root 随后
`MNT_DETACH`，所以 `/mnt/shared` 这个挂载点**在这个 namespace 里根本不存在**。
线上 `/proc/mounts` 印证了这一点 —— jail 内只剩 `/workspace` 一条 EFS 挂载
（挂载源是 AP 子路径 `:/tenant-a`，不是 `/mnt/shared` 的 bind）。

隔离必须来自"其他路径不存在"，而不是"其他路径不方便访问"。

### `ls /` 有输出，是不是没隔离住？

不是。`pivot_root` 不是"禁止访问 `/`"，而是**换掉 `/` 的含义** —— 任何进程都有根
目录可以列，问题在于那个根是谁的。jail 里的 `/` 是每次执行现搭的 16MB tmpfs：

```
$ cat /proc/mounts | head -1
tmpfs / tmpfs rw,nosuid,nodev,relatime,size=16384k,mode=755 0 0
```

宿主容器里真实存在的 `/app`（Runtime 源码）、`/mnt`（EFS 挂载点）、
`/root` `/home` `/var` `/run` `/srv` `/sys`、`/etc/shadow` 在 jail 内全部
`No such file`；`/etc/passwd` 只有一行合成内容
（`root:x:0:0:root:/workspace:/bin/bash`），没有宿主账号表。
挂载进来的 `/usr` `/opt` `/etc/ssl` 等都是 `ro,nosuid,nodev` —— 不给 libc
则 bash 和 python 都起不来，所以这些必须在，但只读。

**根 tmpfs 和 `/etc` 可写，但那是那次执行私有的。** 线上实测：写入 `/PWN`、
往 `/etc/passwd` 追加一行 `attacker:x:0:0::/:/bin/sh` 都会成功，而同一 session
的下一次调用里标记不存在、`/etc/passwd` 仍是一行。改动随 namespace 一起消失，
影响不到任何人（包括他自己的下一条命令），也换不来提权：所有挂载 `nosuid`、
capability 全零、`no_new_privs` 已置位 —— 没有会去读那个伪造 passwd 的
setuid 程序。唯一的持久写入面是 `/workspace`，那本来就是他自己的 EFS 目录。

这几条都在 section 11.5 里做了**正向断言**（`/` 必须是 tmpfs、宿主路径必须消失、
污染必须蒸发），而不是只检查"`ls /` 的输出里没有机密串" —— 后者会空过：
`bin dev etc …` 这种输出本身不含机密，就算真是宿主根也扫不出问题。

### 同一租户的两个 session 为什么看到同样的文件

```
$ ./tools/tenant_shell.py --tenant tenant-a --session-id $S1 -c 'echo S1-WROTE-THIS > /workspace/xsess.txt'
$ ./tools/tenant_shell.py --tenant tenant-a --session-id $S2 -c 'cat /workspace/xsess.txt'
S1-WROTE-THIS          ← 换了 session id，还是读到了
```

**这是正确行为。** 隔离边界是**租户**，不是 session。`--session-id` 换了但
`--tenant` 还是 `tenant-a`，那就还是同一个人 —— 同一个人当然应该看到自己的文件，
否则这个共享文件系统就没有意义了（关掉 shell 再打开，产物就没了）。

session 隔离的是**计算**，租户隔离的是**存储**。两个 session 是两台 microVM、
两个 mount namespace、两个 rootfs，但它们的 `/workspace` 绑到同一个 EFS 子目录：

| | 同租户 / 不同 session | 不同租户 |
|---|---|---|
| `/workspace` 挂载源 | `127.0.0.1:/tenant-a` **相同** | `:/tenant-a` vs `:/tenant-b` |
| `/workspace` 的 inode | 同一个（`5493027947850942901`） | `5741213667953168919` vs `13111088590686751993` |
| 读对方写的 `/workspace/x` | 读到 | `No such file or directory` |
| `/tmp`、`/etc`、`/` 的写入 | 互不可见（各自 tmpfs） | 互不可见 |

inode 相同是"同一份数据"的硬证据 —— 不是内容恰好一样，而是同一个文件。

所以哪些东西**不**跨 session 共享：`/workspace` 之外的一切。上例中 session 1
写的 `/tmp/eph.txt` 和 `/etc/eph.txt`，在 session 2 里都是
`No such file or directory`（每次执行都重搭 rootfs，见上一节）。

**想让两个 session 互相看不到文件，就得是两个租户** —— 换 `--tenant`（交互式用
`:su`，它会自动开新 session，因为 session 一旦绑定就不许换租户）。

### 配额

单次读写大小、workspace 总量、目录条目数、stdout/stderr 长度、执行超时均有上限
（见 `runtime/main.py` 顶部，可用环境变量覆盖），防止单租户写满共享 EFS 或耗尽资源。

## 验证结果

`tests/test_isolation.py` — 49 项，本地全部通过（jail 相关 24 项需 root，
非 root 运行会 skip 掉这些，输出 `OK (skipped=24)` —— 那不等于隔离已验证）：

```
$ sudo python3 -m unittest discover -s tests -v
Ran 49 tests in 0.894s
OK
```

| 测试类 | 项数 | 覆盖 |
|--------|------|------|
| `TestJailIsolation` | 22 | pivot_root 视图、capability、凭证不透传、fail-closed（需 root）|
| `TestPathGuard` | 12 | 绝对路径、`..`、NUL、symlink 逃逸（读/写/目录）|
| `TestTenantIdentity` | 10 | 伪造签名、过期、换租户名、错密钥、短密钥 |
| `TestSessionBinding` | 3 | 同 session 不许换租户、不同 session 各自绑定 |
| `TestJailCrossTenant` | 2 | 各租户只见自己数据、jail 拆除后宿主完好（需 root）|

对抗性验证覆盖的攻击面。修复前每一项都可以成功越权：

| 攻击 | 修复前 | 修复后 |
|------|--------|--------|
| `run_command` 绝对路径读其他租户 | 读到明文 | No such file or directory |
| `run_command` 绝对路径写其他租户 | **写入成功** | 写入失败，目标不存在 |
| `run_command` `ls /mnt/shared/tenants/` | 列出所有租户 | 路径不存在 |
| `run_command` 相对路径 `../<租户>/` | 读到明文 | 路径不存在 |
| `run_command` 读 `/etc/passwd`、`ls /` | 完整宿主 rootfs | 仅 jail 内合成视图 |
| `run_command` 读 `/app`（Runtime 源码）| 可读 | 路径不存在 |
| `run_code` 同上各项 | 均成功 | 均被阻止 |
| 环境变量中的 AWS 凭证 / 签名密钥 | 完整透传 | 白名单重建，不可见 |
| jail 内 `mount --bind` 逃逸 | — | permission denied（无 capability）|
| `tenant_id` 自证 | 无认证 | UNAUTHENTICATED |
| 伪造 / 过期 / 换租户名的 token | — | UNAUTHENTICATED |
| 同一 session 切换租户 | 拒绝 | 拒绝 |
| 受守卫 API 的 `..` 遍历 | 拒绝 | 拒绝 |
| 受守卫 API 绝对路径 | 静默改写为 workspace 内路径 | 明确拒绝 |
| 受守卫 API symlink 逃逸 | 部分可绕过 | 拒绝 |
| bind mount 失败时 rmtree 摧毁他人数据 | 数据被删除 | 该代码路径已移除 |

同时验证隔离没有破坏功能：租户读写自己目录、`run_command`/`run_code` 在
`/workspace` 内正常工作、业务 Pod ↔ jail 双向文件流转仍然成立。

### 线上（真实 AgentCore Runtime）验证

```bash
export RUNTIME_ID=... AWS_REGION=us-east-1
python3 tests/test_agentcore_live.py
# Key from: secretsmanager:agentcore/tenant-signing-key
# 91 passed, 0 failed, 91 total
```

签名密钥不需要手动导出：脚本先看 `TENANT_SIGNING_KEY`，没有就从
`TENANT_SIGNING_KEY_SECRET_ID`（默认 `agentcore/tenant-signing-key`，
与 Runtime 读的是同一个 secret）拉，banner 里会打印实际来源。
**拿不到密钥就直接退出**，不会带着"跳过身份测试"往下跑 —— hmac 模式下每次调用
都要带签名 token，缺密钥会在 section 1 撞出一片 `UNAUTHENTICATED`，
把人误导去查 Runtime 和 EFS。

14 个 section:1 连通/沙箱状态、2 正常读写、3 受守卫 API 越权、
4 `run_command` 越权、5 `run_code` 越权、6 凭证泄漏、7 沙箱逃逸、
8 身份与 session 绑定、9 双向文件流转、10 活体对照 + 内核挂载表 + 深度逃逸探测、
11 宿主侧 symlink 逃逸、11.5 `/` 是 jail 私有 tmpfs、
11.6 隔离边界是租户而非 session（同租户跨 session 共享 `/workspace`，
换租户则不共享 —— 两个方向都断言）、12 破坏性尝试后受害租户数据完好。

判定原则是**机密内容有没有出现在响应里**，而不是有没有返回错误信息 ——
一个 "Path not allowed" 只说明那一个 API 挡住了，不代表沙箱成立。
相应地，报错里回显被攻击的路径（`cat: /mnt/shared/tenants/tenant-b/x: No such file`）
不算泄漏，那恰恰是路径不存在的证据；`no_leak()` 会先剔除攻击输入里的路径 token，
再扫描机密标记，因此目录真被列出或文件真被读到仍会判失败。

线上实测确认的关键事实：

- `status.sandbox` = `mount-namespace-jail`，执行接口不返回 126
  → microVM 内确实具备 `CAP_SYS_ADMIN`，`unshare` + `pivot_root` 成立
- jail 内 `/proc/mounts` 只有一条 EFS 挂载：`127.0.0.1:/tenant-a → /workspace`，
  **没有 `/mnt/shared` 条目** —— 隔离由内核挂载表本身保证，不依赖路径过滤
- jail 内 `CapEff` / `CapBnd` 均为 `0000000000000000`
- `nsenter -t 1 -m` / 二次 `unshare` / `mknod` / `mount -t nfs4` 全部
  `Operation not permitted`；`/.oldroot` 已不存在；`/proc/1/root` 下无 `/mnt`
- 对照实验：在 B 的 canary **确实存在于 EFS** 的同时，A 的所有越权尝试
  均返回 ENOENT；A 执行 `rm -rf /mnt/shared` 后 B 的数据完好
- A 在自己 EFS 目录里种下指向 `/`、`/etc/passwd`、B 目录的 symlink 后，
  受守卫 API 的 11 项读/写/列目录尝试全部被 `realpath` 校验拒绝
  （宿主侧 `/mnt/shared` 真实存在，这才是有效的 symlink 逃逸测试）
- fail-closed 可达性：剥夺 `CAP_SYS_ADMIN` 运行同一镜像，jail 退出码 126
  且被执行的命令从未运行（无法从线上测 —— microVM 里确实有该能力，
  所以单独用 `docker run --cap-drop=SYS_ADMIN` 验证，命令见测试文件 docstring）

上面除最后一条外，每一项都在 `tests/test_agentcore_live.py` 里，不是一次性脚本。

### 手动验证：交互式租户 shell

想自己动手戳，用 `tools/tenant_shell.py` —— 每敲一条命令就是一次
`InvokeAgentRuntime` → 一次 jail 内执行，你看到的文件系统就是那个租户
在 jail 里看到的全部内容。

依赖只有 boto3（`tests/test_agentcore_live.py` 同样）。注意 Amazon Linux 2023 的
`/usr/bin/python3` **连 pip 都没装**，所以别照 `pip install boto3` 敲：

```bash
sudo dnf install -y python3-boto3     # AL2023 / RHEL 系
sudo apt install -y python3-boto3     # Debian / Ubuntu
# 或者不碰系统 python：
python3 -m venv ~/.venv/agentcore && ~/.venv/agentcore/bin/pip install boto3
```

```bash
export RUNTIME_ID=sandboxIsolationDemo-xxxx AWS_REGION=us-east-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

./tools/tenant_shell.py --tenant tenant-a           # 交互式
./tools/tenant_shell.py --tenant tenant-a --probe   # 一键隔离探测（13 项）
./tools/tenant_shell.py --tenant tenant-b -c 'ls /' # 单条命令后退出
```

还需要一份能 `bedrock-agentcore:InvokeAgentRuntime` 的 AWS 凭证，以及签名密钥
（未设 `TENANT_SIGNING_KEY` 时会自动从 Secrets Manager 取，见下）。

指定 runtime 与 session：

| 参数 | 环境变量 | 说明 |
|------|---------|------|
| `--runtime-arn` | `RUNTIME_ARN` | 完整 ARN，给了就忽略下面两项 |
| `--runtime-id` | `RUNTIME_ID` | 与 `--account`/`--region` 拼成 ARN |
| `--account` / `--region` | `ACCOUNT_ID` / `AWS_REGION` | |
| `--session-id` | `RUNTIME_SESSION_ID` | 复用已有 session；不足 33 字符自动补齐 |
| `--secret-id` | `TENANT_SIGNING_KEY_SECRET_ID` | 签名密钥的 secret |
| `--tenant` `--timeout` `-c` `--probe` `--no-sign` `--keep-session` | | |

`--session-id` 配 `--keep-session` 可以跨两次进程观察同一个 session ——
这是验证「session 绑定」和「rootfs 每次执行重建」的手段：

```
$ S=demo-session-$(uuidgen)
$ ./tools/tenant_shell.py --session-id $S --keep-session -c 'touch /etc/x; ls /etc/x'
[session] demo-session-9d13f74d-482c-4e9a-87a1-b5481605a23d
/etc/x                              ← 同一次调用里存在
  ⓘ 写入 /etc/x 只在本次调用内有效（jail 的 rootfs 每次执行重建）。要持久化请写 /workspace。

$ ./tools/tenant_shell.py --session-id $S -c 'ls /etc/x'
[session] demo-session-9d13f74d-482c-4e9a-87a1-b5481605a23d   ← 同一个 session
ls: cannot access '/etc/x': No such file or directory
[exit 2]
```

两次进程打出同一个 session id，说明 session 确实被复用了 —— 而 `/etc/x`
仍然消失，可见"每次执行重建 rootfs"与 session 是否复用无关。

密钥解析方式与线上测试一致：`TENANT_SIGNING_KEY` 优先，否则从
`--secret-id`（默认 `agentcore/tenant-signing-key`）拉。拿不到就退出并说明两条路。
`:session` 会显示密钥的实际来源。`--probe` 先确认调用能打通 ——
认证不过时直接说"探测未执行"，而不是打一屏 ❌ 冒充隔离结论。

```
[tenant-a] /workspace $ ls /
bin dev etc lib opt proc sbin tmp usr workspace
[tenant-a] /workspace $ cat /mnt/shared/tenants/tenant-b/output/b.txt
cat: /mnt/shared/tenants/tenant-b/output/b.txt: No such file or directory
[tenant-a] /workspace $ cd /mnt/shared
/bin/bash: line 1: cd: /mnt/shared: No such file or directory
[tenant-a] /workspace $ :switch-attack
session 已绑定 tenant-a，现在在同一 session 内用 tenant-b 的 token 调用 status …
✅ 被拒绝: Session already bound to a different tenant; cannot switch to 'tenant-b'
（换租户需要新 session —— 用 :su）
```

内置命令：`:probe` 一键探测、`:status`、`:session`、`:su <tenant>` 换租户、
`:switch-attack` 演示同 session 内换租户被拒、`:read`/`:write`/`:ls` 走受守卫 API
（便于和 jail 内的 `cat` 对比）、`:py` 走 `run_code`。`:help` 看全部。

`cd` 由 shell 侧维护当前目录（每次 invoke 都是新进程），但目标是否可进入由
jail 内的 `pwd` 回读决定 —— 所以 `cd /mnt/shared` 会如实失败，不是被客户端拦掉的。

**每条命令都是一个全新 jail**，所以 `/workspace` 之外的写入不跨命令存活：

```
[tenant-a] /workspace $ touch /etc/a.txt
  ⓘ 写入 /etc/a.txt 只在本次调用内有效（jail 的 rootfs 每次执行重建）。要持久化请写 /workspace。
[tenant-a] /workspace $ ls /etc/a.txt
ls: cannot access '/etc/a.txt': No such file or directory
```

`touch` 返回的是 exit 0，**它真的成功了** —— 同一条命令里 `touch x && ls x` 也
看得到。消失是因为下一条命令换了一个 jail，rootfs 是新搭的。这不是权限错误，
所以没有报错信息可打；shell 因此对非 `/workspace` 的写入主动加一行 ⓘ 提示。
`/tmp` 同样易失，但那是通用语义，不提示。

**这个 shell 不是 ssh，没有租户侧的账号密码可登。** 它需要
`TENANT_SIGNING_KEY` —— 扮演的是**业务 Pod（可信签发方）**，不是租户本人。
这正是设计意图：如果靠"我声明我是 tenant-a"就能进去，`tenant_id` 就又变成
自证的了。`--no-sign` 会发明文 `tenant_id`，正常部署下被 Runtime 直接拒掉
（`UNAUTHENTICATED`）—— 那本身也是一次有效验证。

### 完整交互示例（每一行都是线上真实输出）

```
$ ./tools/tenant_shell.py --tenant tenant-a

  AgentCore 租户 shell  (:help 查看命令, :probe 一键探测)
  tenant  = tenant-a
  session = shell-tenant-a-7a35926ec3b3487cb1eacffd4673cb05
  key     = secretsmanager:agentcore/tenant-signing-key
```

session id 完整打印，不截断 —— 它就是要复制去传 `--session-id` 复用这个
session 的值，也是去 CloudWatch 对日志用的关键字。`-c` 模式把它打到
**stderr**（`[session] <id>`），这样 stdout 仍可直接进管道。

**身份与状态** —— `:session` 是客户端视角，`:status` 是 Runtime 回报的视角
（两边的 `tenant_id` 必须一致，否则说明签发与验签对不上）：

```
[tenant-a] /workspace $ :session
  tenant_id                tenant-a
  session_id               shell-tenant-a-7a35926ec3b3487cb1eacffd4673cb05
  auth                     hmac signed token
  key source               secretsmanager:agentcore/tenant-signing-key
  timeout                  60s

[tenant-a] /workspace $ :status
  tenant_id                tenant-a
  workspace                /workspace
  auth_mode                hmac
  sandbox                  mount-namespace-jail      ← 不是这个值就说明 jail 没生效
  used_bytes               0
  quota_bytes              5368709120
```

**受守卫 API vs jail 内命令** —— 同一个文件两条路径都能到，可以互相对照：

```
[tenant-a] /workspace $ :write notes/hello.txt 你好，这是通过受守卫 API 写入的
已写入 44 字节 → /workspace/notes/hello.txt
[tenant-a] /workspace $ :ls notes
  -         44  hello.txt
[tenant-a] /workspace $ :read notes/hello.txt
你好，这是通过受守卫 API 写入的
[tenant-a] /workspace $ cat /workspace/notes/hello.txt      ← 走 jail 内的 cat
你好，这是通过受守卫 API 写入的
[tenant-a] /workspace $ :py import os; print(sorted(os.listdir("/workspace")))
['input', 'notes', 'output']
```

**`cd` 的边界由 jail 决定，不是客户端过滤的**：

```
[tenant-a] /workspace $ cd /workspace/notes
[tenant-a] /workspace/notes $ pwd
/workspace/notes
[tenant-a] /workspace/notes $ cd /mnt/shared
/bin/bash: line 1: cd: /mnt/shared: No such file or directory
[tenant-a] /workspace/notes $ cd /etc                        ← 这个能进，它在 jail 里
[tenant-a] /etc $ touch a.txt
  ⓘ 写入 /etc/a.txt 只在本次调用内有效（jail 的 rootfs 每次执行重建）。要持久化请写 /workspace。
```

**受守卫 API 的越权被明确拒绝**（注意是拒绝，不是静默改写）：

```
[tenant-a] /workspace $ :read ../tenant-b/output/report.txt
[guard] Parent directory traversal is not allowed
[tenant-a] /workspace $ :read /etc/passwd
[guard] Absolute paths are not allowed; use a workspace-relative path
```

**换租户**：同 session 内换会被拒，`:su` 自动开新 session：

```
[tenant-a] /workspace $ :switch-attack
session 已绑定 tenant-a，现在在同一 session 内用 tenant-b 的 token 调用 status …
✅ 被拒绝: Session already bound to a different tenant; cannot switch to 'tenant-b'
（换租户需要新 session —— 用 :su）

[tenant-a] /workspace $ :su tenant-b
已切换到 tenant-b
  新 session: shell-tenant-b-fc3a3f4f91694e9b84ae3a0fcf4b8edb
[tenant-b] /workspace $ cat /workspace/output/b.txt
SECRET-OF-B-0dfe2abefe9244999ab8cd93f16d7283     ← 现在读到的是 B 自己的数据
```

非交互式（脚本里用）：

```bash
./tools/tenant_shell.py --tenant tenant-a --probe          # 13 项隔离探测
./tools/tenant_shell.py --tenant tenant-a -c 'cat /proc/mounts'
./tools/tenant_shell.py --tenant tenant-a --no-sign -c 'ls /'   # 看未认证的样子
```

**退出码可以直接用在脚本和 CI 里**：`-c` 透传 jail 内命令的退出码
（`-c 'exit 42'` → 42），受守卫 API 被拒、认证失败、传输失败都记为 1；
`--probe` 有任一项未通过则返回 1 —— 包括"调用没打通、探测根本没跑"的情况，
那同样不算通过。所以 `shell -c 'build.sh' && deploy` 这种写法是安全的。

### 两个租户并行的完整例子

下面全部是线上真实输出。开两个 session，各自绑一个租户：

```bash
SA=demo-a-$(uuidgen)   # tenant-a 的 session（uuidgen 给出 43 字符，满足 >= 33）
SB=demo-b-$(uuidgen)   # tenant-b 的 session
sh() { ./tools/tenant_shell.py --session-id "$1" --tenant "$2" --keep-session -c "$3"; }
```

**1. 各写一份同名产物** `/workspace/output/report.txt`：

```
$ sh $SA tenant-a 'echo "A 的营收报表 Q3=1200万" > /workspace/output/report.txt'
[session] demo-a-b1587c64-21a2-46bf-82d5-d843baca325b
$ sh $SB tenant-b 'echo "B 的营收报表 Q3=980万"  > /workspace/output/report.txt'
[session] demo-b-1f74b602-002c-4092-85fa-65e226af209a
```

`[session]` 那行走 **stderr**（stdout 留给命令自己的输出，可以直接进管道）。
下面几步为省篇幅省掉了这行。

**2. 同一个绝对路径，各读到自己的内容** —— 不是同一个文件：

```
$ sh $SA tenant-a 'cat /workspace/output/report.txt'
A 的营收报表 Q3=1200万
$ sh $SB tenant-b 'cat /workspace/output/report.txt'
B 的营收报表 Q3=980万
```

**3. 内核挂载表给出原因**：两个 session 的 `/workspace` 挂载源不同，
`/workspace` 在各自 namespace 里指向 EFS Access Point 下不同的子路径。

```
$ sh $SA tenant-a 'grep " /workspace " /proc/mounts | cut -d" " -f1-3'
127.0.0.1:/tenant-a /workspace nfs4
$ sh $SB tenant-b 'grep " /workspace " /proc/mounts | cut -d" " -f1-3'
127.0.0.1:/tenant-b /workspace nfs4
```

**4. A 试图读 B 的同一份报表** —— 路径不存在，不是权限不足：

```
$ sh $SA tenant-a 'cat /mnt/shared/tenants/tenant-b/output/report.txt'
cat: /mnt/shared/tenants/tenant-b/output/report.txt: No such file or directory
```

**5. A 在自己 session 里冒充 tenant-b**。注意用的是**签名完全合法**的
tenant-b token（业务 Pod 真能签出来），依然被拒 —— session 一旦绑定，
换身份就不再取决于 token 是否有效：

```
-> PERMISSION_DENIED | Session already bound to a different tenant; cannot switch to 'tenant-b'
原绑定是否受影响: tenant-a          # 被拒的尝试没有破坏 A 自己的绑定
```

命令行形式同理 —— 换 `--tenant` 但复用 A 的 session：

```
$ ./tools/tenant_shell.py --tenant tenant-b --session-id $SA -c 'echo hi'
[PERMISSION_DENIED] Session already bound to a different tenant; cannot switch to 'tenant-b'
```

**换租户必须开新 session**（交互式里就是 `:su <tenant>`，它会自动新建 session）。
这条规则挡住的是"拿到一个 session 后横向切换身份"，与签名验证互补：
签名管"你是谁"，session 绑定管"这个 session 已经是谁了"。

## 项目结构

```
.
├── README.md
├── runtime/                    # AgentCore Runtime 容器
│   ├── Dockerfile              # ARM64, Python 3.12 + bedrock-agentcore SDK
│   ├── requirements.txt
│   ├── main.py                 # /invocation 入口 + 配额
│   ├── jail.py                 # mount namespace + pivot_root 沙箱
│   ├── tenant_identity.py      # tenant token 签发/验签 + session 绑定
│   └── workspace_guard.py      # 租户目录解析 + 路径守卫
├── control-plane/              # 业务 Pod 侧调用封装
│   ├── requirements.txt
│   └── sandbox_client.py       # SandboxClient (签发 tenant_token)
├── infra/                      # 部署脚本
│   ├── setup-efs.sh            # EFS + AP (root=/tenants)
│   ├── setup-iam.sh            # 执行角色 + Secrets Manager 权限
│   ├── build-and-push.sh
│   ├── create-runtime.sh
│   └── update_runtime_efs.py
├── tools/
│   └── tenant_shell.py         # 交互式租户 shell（手动验证隔离）
└── tests/
    ├── test_isolation.py       # 本地对抗性隔离测试 (49 项)
    └── test_agentcore_live.py  # AWS 线上验证 (91 项, 14 section)
```

## 部署步骤

### 前置条件

- AWS 账号，EFS 文件系统 + Mount Targets（至少覆盖 2 个 AZ）
- ECR 仓库
- 安全组：Runtime SG 允许 outbound TCP 2049 到 Mount Target SG

### 1. 创建 EFS 与签名密钥

```bash
export VPC_ID=vpc-xxx SUBNET_IDS="subnet-a,subnet-b" SECURITY_GROUP_ID=sg-xxx
./infra/setup-efs.sh

# 生成租户 token 签名密钥（业务 Pod 与 Runtime 共享，绝不下发给租户）
aws secretsmanager create-secret --name agentcore/tenant-signing-key \
  --secret-string "$(openssl rand -base64 48)"
```

### 2. 创建 IAM 角色

```bash
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export EFS_FILE_SYSTEM_ID=fs-xxx
export EFS_ACCESS_POINT_ARN=arn:aws:elasticfilesystem:...
export TENANT_SIGNING_KEY_SECRET_ARN=arn:aws:secretsmanager:...
./infra/setup-iam.sh
```

角色权限：`elasticfilesystem:ClientMount`/`ClientWrite`（限定到单个 AP）、
`secretsmanager:GetSecretValue`（限定到签名密钥）、ECR 拉取、CloudWatch Logs。

### 3. 构建镜像

```bash
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION=us-east-1
./infra/build-and-push.sh          # 建仓库、登录、arm64 构建、推送
# 末尾会打印下一步要用的：export ECR_IMAGE_URI=...sandbox-isolation-runtime:jail
```

tag 默认 `jail`（带 mount namespace 沙箱那一版），仓库名默认
`sandbox-isolation-runtime`，可用 `IMAGE_TAG` / `ECR_REPO` 覆盖。这两个默认值必须和
第 4 步部署的镜像一致 —— 对不上时 Runtime 照样 READY，只是跑的是旧镜像，很难发现。

### 4. 创建 Runtime

新建用 `create-runtime.sh`；给已存在的 Runtime 补挂 EFS / 换镜像用
`update_runtime_efs.py`（先 `--dry-run` 看一遍要提交什么）：

```bash
# 新建
export ROLE_ARN=... EFS_ACCESS_POINT_ARN=... SUBNET_IDS=subnet-a,subnet-b \
       SECURITY_GROUP_ID=sg-xxx ECR_IMAGE_URI=<account>.dkr.ecr.<region>.amazonaws.com/sandbox-isolation-runtime:jail
./infra/create-runtime.sh

# 或：更新已有 Runtime
export ACCOUNT_ID=... RUNTIME_ID=... EFS_ACCESS_POINT_ID=fsap-xxx \
       SUBNET_IDS=subnet-a,subnet-b SECURITY_GROUP_IDS=sg-xxx IMAGE_TAG=jail
python3 infra/update_runtime_efs.py --dry-run    # 先看
python3 infra/update_runtime_efs.py              # 再提交
```

> 更新走的是 `PUT /runtimes/{id}`，**整体替换而非合并** —— 不带上
> `environmentVariables` 会把 `TENANT_AUTH_MODE` /
> `TENANT_SIGNING_KEY_SECRET_ID` 一起抹掉，Runtime 随即拒绝所有调用，
> 且不会有任何提示。脚本每次都把这几项完整带上，别手写裁剪版。

关键配置：

```json
{
  "networkMode": "VPC",
  "subnets": ["与 EFS mount target 同 AZ 的子网"],
  "securityGroups": ["允许 outbound NFS 2049 的 SG"],
  "filesystemConfigurations": [{
    "efsAccessPoint": {
      "accessPointArn": "arn:aws:elasticfilesystem:...:access-point/fsap-xxx",
      "mountPath": "/mnt/shared"
    }
  }],
  "environmentVariables": {
    "TENANT_AUTH_MODE": "hmac",
    "TENANT_SIGNING_KEY_SECRET_ID": "agentcore/tenant-signing-key",
    "TENANTS_DIR": "/mnt/shared"
  }
}
```

`TENANTS_DIR=/mnt/shared`：因为 AP 的 root directory 已经是 `/tenants`，
挂载点本身就是租户目录的父目录。若 AP root 为 `/`，则不设此变量（默认
`/mnt/shared/tenants`）。

### 配置项

| 环境变量 | 默认 | 说明 |
|---------|------|------|
| `TENANT_AUTH_MODE` | `hmac` | `hmac` / `jwt` / `insecure_payload` |
| `TENANT_SIGNING_KEY` | — | HMAC 密钥（>= 32 字节），或用下一项 |
| `TENANT_SIGNING_KEY_SECRET_ID` | — | Secrets Manager secret id |
| `TENANT_JWT_CLAIM` | `custom:tenant_id` | jwt 模式下取哪个 claim |
| `EFS_MOUNT` | `/mnt/shared` | EFS 挂载点 |
| `TENANTS_DIR` | `$EFS_MOUNT/tenants` | 租户目录的父目录 |
| `MAX_WORKSPACE_BYTES` | 5 GiB | 单租户 workspace 配额 |
| `MAX_WRITE_BYTES` / `MAX_READ_BYTES` | 32 MiB | 单次读写上限 |
| `MAX_TIMEOUT` | 300 | 执行超时上限（秒）|
| `JAIL_TMP_MB` | 64 | jail 内 /tmp 容量 |
| `JAIL_MAX_MEMORY_MB` | 0（不限）| jail 内存上限 |

> `TENANT_AUTH_MODE=insecure_payload` 会回退到读取请求体里的 `tenant_id`，
> 任何调用方都能冒充任意租户。仅供本地开发，启动时会打 CRITICAL 日志。

## 使用方式（业务 Pod 侧）

```python
import sys
sys.path.insert(0, "control-plane")    # 目录名带连字符，不是合法包名
from sandbox_client import SandboxClient

client = SandboxClient(
    runtime_arn="arn:aws:bedrock-agentcore:us-east-1:...:runtime/...",
    region="us-east-1",                # 默认 us-west-2，要与 Runtime 同 region
    signing_key=SIGNING_KEY,           # 与 Runtime 共享，绝不下发给租户
)

# 1. 业务 Pod 写入数据到 EFS: /mnt/efs/tenants/tenant-A/input/data.csv

# 2. 创建 session（客户端为每次调用签发短期 tenant_token）
session = client.create_session(tenant_id="tenant-A")

# 3. session 内执行，jail 内只存在 /workspace (= tenants/tenant-A/)
session.run_command("cat /workspace/input/data.csv")
session.run_code("import pandas as pd; df = pd.read_csv('/workspace/input/data.csv')")

# 4. session 内写入产物
session.write_file("output/result.json", '{"status": "done"}')

# 5. 业务 Pod 消费产物: /mnt/efs/tenants/tenant-A/output/result.json
```

路径一律用 `/workspace` 相对路径。绝对路径会被守卫拒绝（不再静默改写）。

## 运维注意

- **jail 需要 `CAP_SYS_ADMIN`** 才能 `unshare(CLONE_NEWNS)` + `pivot_root`。
  AgentCore microVM 内容器以 root 运行 —— 已在真实 Runtime 上实测通过
  （`sandbox=mount-namespace-jail`，不返回 126）。若运行环境剥夺了该能力，
  执行接口会返回 exit 126 并拒绝执行 —— 这是有意的 fail-closed 行为，
  不要为了"能跑"而放宽。
- **签名密钥的分发范围**决定了信任边界。密钥只应存在于业务 Pod 与 Runtime，
  任何持有密钥的组件都能冒充任意租户。
- **`tenant_id` 大小写敏感**：`Tenant-A` 与 `tenant-a` 是两个目录。
  若上游身份系统大小写不敏感，应在签发 token 前统一规范化。
- **EFS 424 挂载错误**排查：Runtime 子网与 EFS mount target 同 AZ；
  Runtime SG 允许 outbound TCP 2049；IAM 角色含 `DescribeAccessPoints`
  + `DescribeMountTargets`。
