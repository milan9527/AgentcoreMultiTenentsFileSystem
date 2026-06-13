# AgentCore Runtime EFS 共享存储与隔离访问

## 核心目标

AgentCore Runtime session 能访问业务 Pod 提供的文件数据，同时确保租户间的访问隔离。

**已在 AWS AgentCore 真实环境验证通过。**

## 架构设计

```
┌──────────────────┐          ┌─────────────────────────────────────┐
│   业务 Pod        │          │   AgentCore Runtime                  │
│                    │          │   (EFS 挂载 → /mnt/shared)           │
│  EFS 挂载根目录    │          │                                     │
│  /mnt/efs/         │          │  Session X (microVM, tenant=A):     │
│  └─ tenants/       │    ←──→  │    bind mount /mnt/shared/tenants/A │
│     ├─ A/          │  同一 EFS │         → /workspace                │
│     │  ├─ input/   │          │    agent 只看到 /workspace           │
│     │  └─ output/  │          │                                     │
│     ├─ B/          │          │  Session Y (microVM, tenant=B):     │
│     │  ├─ input/   │          │    bind mount /mnt/shared/tenants/B │
│     │  └─ output/  │          │         → /workspace                │
│     └─ ...         │          │    agent 只看到 /workspace           │
└──────────────────┘          └─────────────────────────────────────┘
                                          │
                              ┌────────────┴────────────┐
                              │    EFS (单 Access Point)  │
                              └─────────────────────────┘
```

### 设计要点

| 问题 | 解法 |
|------|------|
| session 间隔离 | AgentCore 原生：每个 session 独立 microVM，天然物理隔离 |
| 租户数据隔离 | `/invocation` 入口 bind mount 租户子目录到 /workspace |
| 共享数据 | 业务 Pod 和 Runtime 挂载同一 EFS，写入即可见 |
| 不用多 AP | 1 个 EFS + 1 个 Access Point + 1 个 Runtime |
| 扩展性 | 租户数不受 AP 上限（1万）限制 |

## 验证结果（AWS 真实环境）

Runtime: `sandboxIsolationDemo-COIZYqEK2d` (us-east-1)

| 测试项 | 结果 |
|--------|------|
| EFS 挂载到 session `/mnt/shared` | ✅ 内容可见 |
| Bind mount 到 `/workspace` | ✅ `isolated: true` |
| 租户 A 写入文件 | ✅ |
| 租户 A 路径遍历访问 B (`../tenant-B/...`) | ✅ 阻止: "Path not allowed" |
| 租户 B 独立 session 写入 | ✅ |
| 租户 B 路径遍历访问 A | ✅ 阻止: "Path not allowed" |
| 同一 session 切换租户 | ✅ 拒绝: "Session bound to 'tenant-A', cannot switch" |
| Session 间物理隔离 | ✅ 独立 microVM |

## 项目结构

```
.
├── README.md
├── runtime/                    # AgentCore Runtime 容器
│   ├── Dockerfile              # ARM64, Python 3.12 + bedrock-agentcore SDK
│   ├── requirements.txt
│   ├── main.py                 # /invocation 入口 (bind mount + 路径守卫)
│   └── workspace_guard.py      # 租户目录隔离逻辑
├── control-plane/              # 业务 Pod 侧调用封装
│   ├── requirements.txt
│   └── sandbox_client.py       # SandboxClient (封装 InvokeAgentRuntime)
├── infra/                      # 部署脚本
│   ├── setup-efs.sh
│   ├── setup-iam.sh
│   ├── build-and-push.sh
│   ├── create-runtime.sh
│   └── update_runtime_efs.py   # 添加 EFS 到 Runtime (raw API)
└── tests/
    ├── test_e2e.py             # 本地单元测试
    └── test_agentcore_live.py  # AWS 线上验证测试 (17 项)
```

## 部署步骤

### 前置条件

- AWS 账号，us-east-1 region
- EFS 文件系统 + Mount Targets（至少覆盖 2 个 AZ）
- EFS Access Point（UID/GID 按需设置）
- ECR 仓库
- 安全组：Runtime SG 允许 outbound TCP 2049 到 Mount Target SG

### 1. 构建镜像

```bash
cd runtime
docker build --platform linux/arm64 -t sandbox-isolation-runtime:latest .

# Push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker tag sandbox-isolation-runtime:latest <account>.dkr.ecr.us-east-1.amazonaws.com/sandbox-isolation-runtime:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/sandbox-isolation-runtime:latest
```

### 2. 创建 IAM 角色

```bash
# 信任策略: bedrock-agentcore.amazonaws.com
# 权限: elasticfilesystem:ClientMount, ClientWrite, DescribeAccessPoints, DescribeMountTargets
# + ecr:GetDownloadUrlForLayer, ecr:BatchGetImage, ecr:GetAuthorizationToken
# + logs:CreateLogGroup, CreateLogStream, PutLogEvents
./infra/setup-iam.sh
```

### 3. 创建 AgentCore Runtime

```bash
# 先创建 Runtime (PUBLIC 模式验证容器可用)
# 再通过 raw API 添加 EFS 配置 (VPC 模式)
python3 infra/update_runtime_efs.py
```

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
  }]
}
```

### 4. 运行验证测试

```bash
python3 tests/test_agentcore_live.py
```

测试覆盖 17 项场景，全部通过：

```
━━━ Test 1: EFS 挂载验证 ━━━
  ✅ PASS: EFS /mnt/shared 可访问
━━━ Test 2: Workspace bind mount 隔离 ━━━
  ✅ PASS: /workspace 存在且有内容
  ✅ PASS: isolated = true (bind mount 生效)
━━━ Test 3: Tenant-A 写入文件 ━━━
  ✅ PASS: 写入成功
━━━ Test 4: Tenant-A 读取自己的文件 ━━━
  ✅ PASS: 读取内容正确
━━━ Test 5: Tenant-A 路径遍历攻击 (../tenant-B/) ━━━
  ✅ PASS: 阻止: ../tenant-B/output/secret_B.txt
  ✅ PASS: 阻止: ../../tenants/tenant-B/output/secret_B.txt
  ✅ PASS: 阻止: output/../../../etc/passwd
━━━ Test 6: Tenant-B 独立 session 写入 ━━━
  ✅ PASS: Tenant-B 写入成功
━━━ Test 7: Tenant-B 路径遍历访问 Tenant-A ━━━
  ✅ PASS: Tenant-B 无法访问 Tenant-A
━━━ Test 8: Tenant-B 读取自己的文件 ━━━
  ✅ PASS: Tenant-B 读取自己文件成功
━━━ Test 9: 同一 Session 切换租户 (应被拒绝) ━━━
  ✅ PASS: 切换租户被拒绝 (PERMISSION_DENIED)
━━━ Test 10: Python 代码执行验证 ━━━
  ✅ PASS: 代码执行成功
  ✅ PASS: 运行在 /workspace (bind mount)
  ✅ PASS: workspace 包含 input/output
━━━ Test 11: 列目录验证 ━━━
  ✅ PASS: list_files 返回文件列表
━━━ Test 12: list_files 路径遍历防护 ━━━
  ✅ PASS: list_files 路径遍历被阻止

============================================================
  结果: 17 passed, 0 failed, 17 total
============================================================
```

## 使用方式（业务 Pod 侧）

```python
from control_plane.sandbox_client import SandboxClient

client = SandboxClient(runtime_arn="arn:aws:bedrock-agentcore:us-east-1:...:runtime/...")

# 1. 业务 Pod 写入数据到 EFS
#    /mnt/efs/tenants/tenant-A/input/data.csv

# 2. 创建 session
session = client.create_session(tenant_id="tenant-A")

# 3. session 内执行，只能看到 /workspace (= tenants/tenant-A/)
result = session.run_command("cat /workspace/input/data.csv")
result = session.run_code("import pandas as pd; df = pd.read_csv('/workspace/input/data.csv')")

# 4. session 内写入产物
session.write_file("output/result.json", '{"status": "done"}')

# 5. 业务 Pod 消费产物
#    /mnt/efs/tenants/tenant-A/output/result.json
```

## 隔离机制详解

### 三层防护

1. **microVM 物理隔离**（AgentCore 原生）
   - 每个 session 独立 Firecracker microVM
   - 独立内核、内存、文件系统
   - session 结束后 microVM 销毁

2. **Bind mount 目录限制**（/invocation 入口）
   - `mount --bind /mnt/shared/tenants/{id} /workspace`
   - session 内所有操作在 /workspace 范围
   - AgentCore microVM 支持 bind mount（已验证）

3. **路径守卫**（workspace_guard.py）
   - `resolve_path()` 校验所有路径不逃逸 workspace
   - `../` 遍历攻击被阻止
   - tenant_id 注入攻击被过滤

### Session 绑定

同一 session 首次调用时绑定 tenant_id，后续调用如果传入不同 tenant_id 直接拒绝。防止通过复用 session 越权。

## 关键发现

1. **AgentCore microVM 内支持 bind mount** — 容器以 root 运行时可以执行 `mount --bind`
2. **EFS mount 424 错误排查** — 必须确保：
   - Runtime 子网与 EFS mount target 在同一 AZ
   - Runtime SG 允许 outbound TCP 2049 到 mount target SG
   - IAM 角色包含 `DescribeAccessPoints` + `DescribeMountTargets`
