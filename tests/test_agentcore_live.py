#!/usr/bin/env python3
"""
AgentCore Runtime 多租户隔离 - 线上验证测试

每一项断言都对应一个曾经可以越权成功的攻击面：
- run_command / run_code 用绝对路径读写其他租户
- run_command / run_code 读宿主根目录与 Runtime 源码
- 宿主环境变量（含 AWS 凭证、签名密钥）泄漏给租户代码
- tenant_id 自证
- 受守卫 API 的路径遍历、绝对路径、symlink 逃逸

14 个 section，91 项断言：
  1  连通与沙箱状态         7  沙箱逃逸（mount / chroot / capability）
  2  正常读写不被破坏       8  身份与 session 绑定
  3  受守卫 API 越权        9  业务 Pod ↔ jail 双向文件流转
  4  run_command 越权      10  活体对照 + 内核挂载表 + 深度逃逸探测
  5  run_code 越权         11  宿主侧 symlink 逃逸（受守卫 API 穿越）
  6  凭证与密钥泄漏      11.5  / 是 jail 私有 tmpfs（正向断言，非"没搜到机密"）
                        11.6  隔离边界是租户而非 session（共享/不共享两侧都断言）
                          12  破坏性尝试后受害租户数据完好

三条让结论站得住的原则：

1. 判定看机密内容，不看错误信息。一个 "Path not allowed" 只说明那一个 API
   挡住了，不代表沙箱成立 —— 旧版每个 API 都返回得很得体，而 run_command
   根本没调用那个 API。

2. 活体对照（section 10）。攻击返回 ENOENT 可能只是因为目标文件压根不存在。
   所以先证明 canary 此刻真的在 EFS 上，再让攻击方去读。

3. 拿内核挂载表当事实来源（section 10），而不是相信应用层的自我报告。
   /proc/mounts 里没有 /mnt/shared，比任何 "No such file" 都硬。

使用方法:
    export RUNTIME_ID=sandboxIsolationDemo-xxxx
    export AWS_REGION=us-east-1
    python3 tests/test_agentcore_live.py

签名密钥（hmac 模式下每一次调用都需要，不是只有身份那几项）二者取一：
    TENANT_SIGNING_KEY            直接给密钥
    TENANT_SIGNING_KEY_SECRET_ID  从 Secrets Manager 取（默认
                                  agentcore/tenant-signing-key，与 Runtime 同一个）
密钥拿不到就直接退出，不会带着"跳过身份测试"继续跑 —— 那只会在 section 1
撞上一堆 UNAUTHENTICATED，误导人去查 Runtime 和 EFS。

fail-closed 的可达性无法从线上测（microVM 里有 CAP_SYS_ADMIN），单独验证：
    docker run --rm --cap-drop=SYS_ADMIN --entrypoint python <image> \
      /app/jail.py --tenant-root /mnt/shared/tenants --workspace /workspace \
      -- /bin/echo SHOULD-NOT-RUN
    # 期望 exit 126，且 SHOULD-NOT-RUN 从未打印
"""

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid

# 这是独立运行的线上验证脚本，不是 unittest。但文件名匹配 test_*.py，会被
# `unittest discover` 导入 —— 本地没装 boto3 时不能让它把整个 discover 弄崩。
try:
    import boto3
except ImportError:  # pragma: no cover - 仅影响本地 discover
    boto3 = None

REGION = os.environ.get("AWS_REGION", "us-east-1")
RUNTIME_ID = os.environ.get("RUNTIME_ID", "sandboxIsolationDemo-COIZYqEK2d")
ACCOUNT = os.environ.get("ACCOUNT_ID", "123456789012")
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{RUNTIME_ID}"

SECRET_ID = os.environ.get("TENANT_SIGNING_KEY_SECRET_ID", "agentcore/tenant-signing-key")


def load_signing_key():
    """
    取签名密钥。优先 TENANT_SIGNING_KEY，否则从 Secrets Manager 拉
    （和 Runtime 的 tenant_identity.py 读同一个 secret，避免两边不一致）。

    密钥只在内存里用于签 token，不会被打印。
    """
    raw = os.environ.get("TENANT_SIGNING_KEY")
    if raw:
        return raw.encode(), "env TENANT_SIGNING_KEY"
    if boto3 is None:
        return None, None
    try:
        sm = boto3.client("secretsmanager", region_name=REGION)
        val = sm.get_secret_value(SecretId=SECRET_ID)
        val = val.get("SecretString") or val.get("SecretBinary")
        if isinstance(val, bytes):
            return val, f"secretsmanager:{SECRET_ID}"
        # 允许 {"signing_key": "..."} 或裸字符串，与 Runtime 侧解析规则一致
        try:
            parsed = json.loads(val)
            if isinstance(parsed, dict):
                for k in ("signing_key", "TENANT_SIGNING_KEY", "key"):
                    if k in parsed:
                        return str(parsed[k]).encode(), f"secretsmanager:{SECRET_ID}[{k}]"
        except (json.JSONDecodeError, TypeError):
            pass
        return str(val).encode(), f"secretsmanager:{SECRET_ID}"
    except Exception as e:
        print(f"  (无法从 Secrets Manager 读取 {SECRET_ID}: {type(e).__name__})")
        return None, None


SIGNING_KEY, KEY_SOURCE = (None, None)

TENANT_A = "tenant-a"
TENANT_B = "tenant-b"


def _session_id(tag):
    sid = f"iso-{tag}-{uuid.uuid4().hex}"
    return sid + "0" * max(0, 33 - len(sid))


SESSION_A = _session_id("a")
SESSION_B = _session_id("b")

# 机密内容标记：只要出现在任何响应里，就是泄漏
SECRET_A = f"SECRET-OF-A-{uuid.uuid4().hex}"
SECRET_B = f"SECRET-OF-B-{uuid.uuid4().hex}"
# 活体对照用的 canary（section 10-12）。前缀固定，便于用 grep 反向搜索验证。
CANARY = f"DEEP-CANARY-{uuid.uuid4().hex}"

client = boto3.client("bedrock-agentcore", region_name=REGION) if boto3 else None


def sign(tenant_id, ttl=900):
    expiry = int(time.time()) + ttl
    sig = hmac.new(SIGNING_KEY, f"{tenant_id}.{expiry}".encode(), hashlib.sha256).digest()
    return f"{tenant_id}.{expiry}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


def call(session_id, tenant_id, action, params=None, token=True, raw_token=None):
    body = {"action": action, "params": params or {}}
    if raw_token is not None:
        body["tenant_token"] = raw_token
    elif token and SIGNING_KEY:
        body["tenant_token"] = sign(tenant_id)
    else:
        body["tenant_id"] = tenant_id

    try:
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=RUNTIME_ARN,
            runtimeSessionId=session_id,
            payload=json.dumps(body).encode(),
        )
        chunks = []
        for chunk in resp.get("response", []):
            chunks.append(chunk if isinstance(chunk, bytes) else chunk["chunk"]["bytes"])
        return json.loads(b"".join(chunks)) if chunks else {"error": "empty response"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:300]}"}


class Results:
    def __init__(self):
        self.passed = self.failed = 0
        self.failures = []

    def check(self, name, ok, detail=""):
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}: {name}")
        if detail:
            print(f"         {detail}")
        if ok:
            self.passed += 1
        else:
            self.failed += 1
            self.failures.append(name)

    def no_leak(self, name, resp, *markers, echoed=""):
        """
        核心断言：机密内容不得出现在响应的任何位置。

        echoed: 攻击输入本身（命令 / 代码）。shell 与 Python 的报错会把被攻击的
        路径原样回显 —— `cat: /mnt/shared/tenants/tenant-b/x: No such file`。
        那是"路径不存在"的证据，恰恰说明隔离成立，不是泄漏。

        因此扫描前先把**攻击输入里出现过的路径 token**从响应中删掉。删的只有
        我们自己送进去的字符串，所以真正的泄漏仍然会被抓到：
          - 目录真被列出 → 响应里出现裸的 `tenant-b`（不是完整路径 token）→ 判失败
          - 文件真被读到 → 响应里出现 SECRET_B（从不出现在攻击输入里）→ 判失败
        """
        blob = json.dumps(resp)
        # 攻击输入中的路径样 token（含 / 或 . 的连续片段），长度足够才算
        for token in sorted(re.findall(r"[\w./\-]+", echoed or ""), key=len, reverse=True):
            if len(token) >= 8 and ("/" in token or "." in token):
                blob = blob.replace(token, "")
        leaked = [m for m in markers if m in blob]
        self.check(name, not leaked,
                   f"LEAKED {leaked}" if leaked else f"resp: {blob[:130]}")

    def summary(self):
        print(f"\n{'='*64}")
        print(f"  {self.passed} passed, {self.failed} failed, {self.passed + self.failed} total")
        if self.failures:
            print("\n  FAILED:")
            for f in self.failures:
                print(f"    - {f}")
        print(f"{'='*64}")
        return self.failed == 0


def data_of(resp):
    return resp.get("data", resp) if isinstance(resp, dict) else {}


def run_tests():
    print("=" * 64)
    print("  AgentCore 多租户隔离 - 线上验证")
    print("=" * 64)
    print(f"  Runtime : {RUNTIME_ID}  ({REGION})")
    print(f"  Auth    : hmac (signed tenant_token)")
    print(f"  Key from: {KEY_SOURCE}")
    print("=" * 64)

    t = Results()

    print("\n━━━ 1. 基本连通与沙箱状态 ━━━")
    r = call(SESSION_A, TENANT_A, "status")
    d = data_of(r)
    if "error" in r and not d.get("tenant_id"):
        print(f"  调用失败: {r}")
        code = r.get("code")
        if code == "UNAUTHENTICATED":
            # 到这里说明密钥存在但 Runtime 不认 —— 两边密钥不一致，
            # 或 Runtime 的 TENANT_AUTH_MODE 不是 hmac。
            print(f"\n  本脚本的密钥来自: {KEY_SOURCE}")
            print("  Runtime 拒绝了这个 token，说明两边密钥不一致。核对：")
            print(f"    aws bedrock-agentcore-control get-agent-runtime \\")
            print(f"      --agent-runtime-id {RUNTIME_ID} --region {REGION} \\")
            print("      --query 'environmentVariables'")
            print("  确认 TENANT_AUTH_MODE=hmac，且 TENANT_SIGNING_KEY_SECRET_ID")
            print(f"  指向的 secret 与本脚本读的 {SECRET_ID} 是同一个。")
        else:
            print("  确认 Runtime READY、EFS 已挂载（424 排查见 README 运维注意）")
        return False
    t.check("身份解析为 tenant-a", d.get("tenant_id") == TENANT_A, f"status: {d}")
    t.check("沙箱模式为 mount-namespace-jail",
            d.get("sandbox") == "mount-namespace-jail", f"sandbox: {d.get('sandbox')}")

    print("\n━━━ 2. 正常读写（隔离不得破坏功能）━━━")
    r = call(SESSION_A, TENANT_A, "write_file",
             {"path": "output/a.txt", "content": SECRET_A})
    t.check("A 写入自己的文件",
            data_of(r).get("written") == len(SECRET_A.encode()), f"{data_of(r)}")

    r = call(SESSION_A, TENANT_A, "read_file", {"path": "output/a.txt"})
    t.check("A 读回自己的文件", data_of(r).get("content") == SECRET_A)

    # 非 ASCII：written 必须是字节数（配额与 MAX_WRITE_BYTES 都按字节算）。
    # 全 ASCII 的内容里字符数 == 字节数，测不出这个差别。
    CJK = "你好，多租户隔离"          # 8 字符 / 22 字节
    r = call(SESSION_A, TENANT_A, "write_file",
             {"path": "output/cjk.txt", "content": CJK})
    t.check("非 ASCII 写入返回字节数（非字符数）",
            data_of(r).get("written") == len(CJK.encode()) != len(CJK),
            f"written={data_of(r).get('written')} 期望={len(CJK.encode())}")
    d = data_of(call(SESSION_A, TENANT_A, "run_command",
                     {"command": "stat -c %s /workspace/output/cjk.txt"}))
    t.check("written 与磁盘上的实际大小一致",
            d.get("stdout", "").strip() == str(len(CJK.encode())),
            f"stat={d.get('stdout', '').strip()}")

    r = call(SESSION_B, TENANT_B, "write_file",
             {"path": "output/b.txt", "content": SECRET_B})
    t.check("B 写入自己的文件",
            data_of(r).get("written") == len(SECRET_B.encode()), f"{data_of(r)}")

    r = call(SESSION_A, TENANT_A, "run_command", {"command": "cat /workspace/output/a.txt"})
    t.check("A 的 run_command 能读自己 workspace",
            SECRET_A in data_of(r).get("stdout", ""), f"rc={data_of(r).get('exit_code')}")

    r = call(SESSION_A, TENANT_A, "run_code",
             {"code": "print(open('/workspace/output/a.txt').read())"})
    t.check("A 的 run_code 能读自己 workspace",
            SECRET_A in data_of(r).get("stdout", ""), f"rc={data_of(r).get('exit_code')}")

    print("\n━━━ 3. 受守卫 API 的越权尝试 ━━━")
    for path in (f"../{TENANT_B}/output/b.txt",
                 f"../../tenants/{TENANT_B}/output/b.txt",
                 "output/../../../etc/passwd",
                 "/etc/passwd",
                 f"/mnt/shared/tenants/{TENANT_B}/output/b.txt"):
        t.no_leak(f"read_file 阻止 {path}",
                  call(SESSION_A, TENANT_A, "read_file", {"path": path}), SECRET_B, "root:x:")

    t.no_leak("list_files 阻止 ../",
              call(SESSION_A, TENANT_A, "list_files", {"path": "../"}), TENANT_B)

    r = call(SESSION_A, TENANT_A, "write_file",
             {"path": f"../{TENANT_B}/output/pwned.txt", "content": "PWNED"})
    t.check("write_file 阻止跨租户写入", "error" in data_of(r), f"{data_of(r)}")

    print("\n━━━ 4. run_command 越权尝试（旧版全部成功）━━━")
    for label, cmd in (
        ("绝对路径读 B", f"cat /mnt/shared/tenants/{TENANT_B}/output/b.txt"),
        ("列出所有租户", "ls /mnt/shared/tenants/"),
        ("查看 EFS 挂载点", "ls -la /mnt/shared 2>&1; ls /mnt 2>&1"),
        ("相对路径逃逸", f"cat ../{TENANT_B}/output/b.txt 2>&1"),
        ("读宿主 passwd", "cat /etc/passwd"),
        ("读 Runtime 源码", "ls /app 2>&1; cat /app/tenant_identity.py 2>&1"),
        ("列出根目录", "ls /"),
        ("查找其他租户数据", "find / -name 'b.txt' 2>/dev/null | head -5"),
    ):
        t.no_leak(f"run_command 阻止: {label}",
                  call(SESSION_A, TENANT_A, "run_command", {"command": cmd}),
                  SECRET_B, TENANT_B, "sign_tenant_token", "/root:",
                  echoed=cmd)

    r = call(SESSION_A, TENANT_A, "run_command",
             {"command": f"echo PWNED > /mnt/shared/tenants/{TENANT_B}/output/pwned.txt && echo wrote"})
    t.check("run_command 无法写入 B 的目录",
            "wrote" not in data_of(r).get("stdout", ""), f"{data_of(r)}")
    r = call(SESSION_B, TENANT_B, "read_file", {"path": "output/pwned.txt"})
    t.check("B 目录未被写入 pwned.txt", "error" in data_of(r), f"{data_of(r)}")
    r = call(SESSION_B, TENANT_B, "read_file", {"path": "output/b.txt"})
    t.check("B 自己的数据完好", data_of(r).get("content") == SECRET_B)

    print("\n━━━ 5. run_code 越权尝试 ━━━")
    for label, code in (
        ("python 读 B", f"print(open('/mnt/shared/tenants/{TENANT_B}/output/b.txt').read())"),
        ("python 列根目录", "import os; print(sorted(os.listdir('/')))"),
        ("python 遍历 EFS", "import os; print(os.listdir('/mnt/shared/tenants'))"),
        ("python 读 Runtime 源码", "print(open('/app/main.py').read()[:200])"),
    ):
        t.no_leak(f"run_code 阻止: {label}",
                  call(SESSION_A, TENANT_A, "run_code", {"code": code}),
                  SECRET_B, TENANT_B, "'mnt'", "BedrockAgentCoreApp",
                  echoed=code)

    print("\n━━━ 6. 凭证与密钥泄漏 ━━━")
    r = call(SESSION_A, TENANT_A, "run_command",
             {"command": "env; cat /proc/self/environ 2>&1"})
    blob = json.dumps(r)
    for marker in ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                   "TENANT_SIGNING_KEY", "AWS_CONTAINER_CREDENTIALS"):
        t.check(f"环境中无 {marker}", marker not in blob)

    r = call(SESSION_A, TENANT_A, "run_command",
             {"command": "curl -s -m 3 http://169.254.170.2/ 2>&1 | head -c 200; echo done"})
    t.check("容器凭证端点无有效响应",
            "AccessKeyId" not in json.dumps(r), f"{str(data_of(r))[:120]}")

    print("\n━━━ 7. 沙箱逃逸尝试 ━━━")
    for label, cmd in (
        ("重新 mount", "mkdir -p /tmp/e && mount --bind / /tmp/e 2>&1; ls /tmp/e 2>&1 | head -5"),
        ("chroot 逃逸", "chroot / /bin/sh -c 'ls /mnt' 2>&1"),
        ("查看宿主进程", "ps aux 2>&1 | head -5; ls /proc/1/root 2>&1"),
    ):
        t.no_leak(f"阻止: {label}",
                  call(SESSION_A, TENANT_A, "run_command", {"command": cmd}),
                  SECRET_B, TENANT_B, echoed=cmd)

    r = call(SESSION_A, TENANT_A, "run_command",
             {"command": "grep -E '^Cap(Eff|Bnd):' /proc/self/status"})
    caps = data_of(r).get("stdout", "")
    t.check("capability 已全部丢弃",
            bool(caps) and all(v.strip("0") == "" for v in
                               [l.split(":")[1].strip() for l in caps.strip().splitlines()]),
            f"caps: {caps.strip()}")

    print("\n━━━ 8. 身份与 session 绑定 ━━━")
    r = call(SESSION_A, TENANT_A, "status", token=False)
    t.check("自证 tenant_id 被拒绝",
            r.get("code") == "UNAUTHENTICATED", f"{str(r)[:120]}")

    expiry = int(time.time()) + 900
    r = call(SESSION_A, TENANT_A, "status",
             raw_token=f"{TENANT_B}.{expiry}.{'A' * 43}")
    t.check("伪造签名被拒绝", r.get("code") == "UNAUTHENTICATED", f"{str(r)[:120]}")

    r = call(SESSION_A, TENANT_A, "status",
             raw_token=sign(TENANT_A, ttl=-3600))
    t.check("过期 token 被拒绝", r.get("code") == "UNAUTHENTICATED", f"{str(r)[:120]}")

    r = call(SESSION_A, TENANT_B, "status")
    t.check("同一 session 切换租户被拒绝",
            r.get("code") == "PERMISSION_DENIED", f"{str(r)[:130]}")

    r = call(SESSION_A, TENANT_A, "read_file", {"path": "output/a.txt"})
    t.check("被拒绝的切换未影响原绑定",
            data_of(r).get("content") == SECRET_A)

    print("\n━━━ 9. 双向文件流转仍然成立 ━━━")
    marker = f"ROUNDTRIP-{uuid.uuid4().hex[:8]}"
    call(SESSION_A, TENANT_A, "write_file",
         {"path": "input/task.json", "content": json.dumps({"m": marker})})
    r = call(SESSION_A, TENANT_A, "run_code",
             {"code": "import json;print(json.load(open('/workspace/input/task.json'))['m'])"})
    t.check("input 写入后 jail 内可读", marker in data_of(r).get("stdout", ""))
    call(SESSION_A, TENANT_A, "run_command",
         {"command": f"echo {marker} > /workspace/output/result.txt"})
    r = call(SESSION_A, TENANT_A, "read_file", {"path": "output/result.txt"})
    t.check("jail 内写入后 API 可读", marker in data_of(r).get("content", ""))

    print("\n━━━ 10. 活体对照：B 的数据确实在，A 依然读不到 ━━━")
    # 最容易自欺的失败模式：攻击返回 ENOENT，其实是因为目标文件压根不存在。
    # 所以先证明 canary 此刻真的在 EFS 上（B 自己能读到、B 的 jail 里也能读到），
    # 再让 A 去攻击。这样 A 的 ENOENT 才能归因到隔离，而不是数据缺失。
    r = call(SESSION_B, TENANT_B, "write_file",
             {"path": "secret/canary.txt", "content": CANARY})
    t.check("[对照] B 写入 canary", data_of(r).get("written") == len(CANARY.encode()), f"{data_of(r)}")
    r = call(SESSION_B, TENANT_B, "read_file", {"path": "secret/canary.txt"})
    t.check("[对照] B 经 API 能读到 canary", data_of(r).get("content") == CANARY)
    r = call(SESSION_B, TENANT_B, "run_command",
             {"command": "cat /workspace/secret/canary.txt"})
    t.check("[对照] B 的 jail 内能读到 canary",
            CANARY in data_of(r).get("stdout", ""),
            f"rc={data_of(r).get('exit_code')}")

    # 内核挂载表是比任何错误信息都硬的证据：/mnt/shared 这个挂载点
    # 在这个 mount namespace 里根本不存在，不是"被过滤掉了"。
    r = call(SESSION_A, TENANT_A, "run_command", {"command": "cat /proc/mounts"})
    mounts = data_of(r).get("stdout", "")
    efs_lines = [l for l in mounts.splitlines() if " nfs4 " in l or " nfs " in l]
    t.check("jail 内挂载表无 /mnt/shared",
            bool(mounts) and " /mnt/shared " not in mounts and "/mnt/shared " not in mounts,
            f"mount 条目数={len(mounts.splitlines())}")
    t.check("jail 内只有一条 EFS 挂载且挂在 /workspace",
            len(efs_lines) == 1 and " /workspace " in efs_lines[0],
            f"{efs_lines[0][:100] if efs_lines else 'none'}")
    t.check("EFS 挂载源是 AP 子路径（非 /mnt/shared 的 bind）",
            bool(efs_lines) and f":/{TENANT_A}" in efs_lines[0].split()[0],
            f"source={efs_lines[0].split()[0] if efs_lines else 'none'}")

    for label, cmd in (
        ("/proc/self/root 无 mnt", "ls /proc/self/root/ 2>&1; ls /proc/self/root/mnt 2>&1"),
        ("/.oldroot 已移除", "ls -a /.oldroot 2>&1; ls -a / 2>&1"),
        ("/proc/1/root 无 mnt", "ls /proc/1/root/ 2>&1 | head -5; ls /proc/1/root/mnt 2>&1"),
        ("其他 pid 的 root 不可穿越", "ls -d /proc/[0-9]*/root 2>&1 | head -5; ls /proc/1/root/mnt 2>&1"),
        ("mknod 裸设备失败", "mknod /tmp/d b 0 1 2>&1; echo rc=$?"),
        ("直接 mount EFS 失败", "mkdir -p /tmp/m && mount -t nfs4 127.0.0.1:/ /tmp/m 2>&1; echo rc=$?"),
        ("workspace 之上 cd 不出去", "cd /workspace && cd ../../../.. && pwd && ls 2>&1"),
        ("/dev 穿越读不到宿主 etc", "cat /dev/../etc/passwd 2>&1 | head -2"),
        ("canary 不在可搜索范围内", "grep -rl 'DEEP-CANARY' /workspace /tmp /etc 2>/dev/null | head -5; echo scan-done"),
    ):
        t.no_leak(f"逃逸探测: {label}",
                  call(SESSION_A, TENANT_A, "run_command", {"command": cmd, "timeout": 25}),
                  CANARY, SECRET_B, TENANT_B, echoed=cmd)

    # nsenter / unshare 需要正向断言：这两个逃逸成功时输出可能只有 "shared"
    # （`ls /mnt` 的结果），不含任何机密标记 —— 光靠 no_leak 会**空过**。
    # 所以直接要求内核拒绝该操作。
    for label, cmd, must_fail_with in (
        ("nsenter 进宿主 mount ns", "nsenter -t 1 -m -- ls /mnt 2>&1", "not permitted"),
        ("二次 unshare(CLONE_NEWNS)", "unshare -m sh -c 'ls /mnt' 2>&1", "not permitted"),
    ):
        d = data_of(call(SESSION_A, TENANT_A, "run_command", {"command": cmd, "timeout": 25}))
        out = (d.get("stdout", "") + d.get("stderr", "")).lower()
        t.check(f"逃逸探测: {label} 被内核拒绝",
                d.get("exit_code") != 0 and must_fail_with in out
                and "shared" not in out,
                f"rc={d.get('exit_code')} out={out.replace(chr(10), ' ')[:90]}")

    print("\n━━━ 11. 宿主侧 symlink 逃逸（受守卫 API 穿越 symlink）━━━")
    # 注意：symlink 必须在宿主侧测。在 jail 里种 symlink 再在 jail 里读，必然失败，
    # 但那只是因为 jail 里没有 /mnt/shared —— 什么都没测到。
    # 有效做法：A 把 symlink 落盘到自己的 EFS 目录，然后用受守卫 API 去穿越 ——
    # 那些 API 跑在宿主进程里，/mnt/shared 真实存在，这才是真正的逃逸测试。
    r = call(SESSION_A, TENANT_A, "run_command", {"command":
        "ln -sfn /mnt/shared/tenants /workspace/esc_tenants; "
        f"ln -sfn /mnt/shared/tenants/{TENANT_B}/secret/canary.txt /workspace/esc_file; "
        "ln -sfn / /workspace/esc_root; "
        "ln -sfn /etc/passwd /workspace/esc_passwd; "
        f"mkdir -p /workspace/d && ln -sfn /mnt/shared/tenants/{TENANT_B} /workspace/d/b; "
        "ls -l /workspace | grep -c '^l'"})
    t.check("[前置] A 已在自己 EFS 目录种下 symlink",
            data_of(r).get("exit_code") == 0, f"symlink 数={data_of(r).get('stdout','').strip()}")

    for action, params in (
        ("read_file", {"path": "esc_file"}),
        ("read_file", {"path": f"esc_tenants/{TENANT_B}/secret/canary.txt"}),
        ("read_file", {"path": "esc_root/etc/passwd"}),
        ("read_file", {"path": "esc_passwd"}),
        ("read_file", {"path": "d/b/secret/canary.txt"}),
        ("list_files", {"path": "esc_tenants"}),
        ("list_files", {"path": "esc_root"}),
        ("list_files", {"path": "d/b"}),
        ("write_file", {"path": f"esc_tenants/{TENANT_B}/secret/canary.txt", "content": "PWNED"}),
        ("write_file", {"path": "d/b/secret/pwned.txt", "content": "PWNED"}),
        ("write_file", {"path": "esc_root/tmp/pwned.txt", "content": "PWNED"}),
    ):
        d = data_of(call(SESSION_A, TENANT_A, action, params))
        # 既要拒绝，也不能泄漏内容 —— 两个条件都得成立
        blob = json.dumps(d).replace(params["path"], "")
        leaked = [m for m in (CANARY, SECRET_B, "root:x:") if m in blob]
        t.check(f"symlink 穿越被拒: {action} {params['path']}",
                "error" in d and not leaked,
                f"LEAKED {leaked}" if leaked else f"{str(d)[:90]}")

    print("\n━━━ 11.5 `/` 是 jail 私有的 tmpfs，不是宿主根 ━━━")
    # `ls /` 在 jail 里当然有输出 —— pivot_root 不是"禁止访问 /"，是**换掉 / 的含义**。
    # 光看 `ls /` 没泄漏机密不足以证明这一点（输出就是 bin/dev/etc…，本身不含机密），
    # 所以这里全部用正向断言：/ 必须是 tmpfs、宿主上真实存在的路径必须消失、
    # 往 / 和 /etc 的写入必须在下次调用蒸发。
    d = data_of(call(SESSION_A, TENANT_A, "run_command", {"command":
        'stat -f -c %T /; echo "---"; '
        'for p in /app /mnt /root /home /var /sys /run /srv /etc/shadow; do '
        '  [ -e "$p" ] && echo "EXISTS $p"; done; echo "---"; '
        'wc -l < /etc/passwd'}))
    out = d.get("stdout", "")
    parts = [s.strip() for s in out.split("---")]
    t.check("jail 的 / 是 tmpfs（不是宿主 rootfs）",
            len(parts) == 3 and parts[0] == "tmpfs", f"fstype={parts[0] if parts else out[:40]}")
    t.check("宿主上真实存在的目录在 jail 内全部不存在",
            len(parts) == 3 and parts[1] == "",
            f"泄漏: {parts[1]}" if len(parts) > 1 and parts[1] else "/app /mnt /root /var … 均无")
    t.check("/etc/passwd 是合成的单行（无宿主账号表）",
            len(parts) == 3 and parts[2] == "1", f"行数={parts[2] if len(parts) > 2 else '?'}")

    # 根 tmpfs 可写，但写入是那次执行私有的：同 session 的下一次调用也看不到。
    # 这才是"可写但无害"的证据 —— 不能只靠推断。
    MARK = f"/PWN-{CANARY[-8:]}"
    d = data_of(call(SESSION_A, TENANT_A, "run_command", {"command":
        f'echo x > {MARK} && echo wrote-root; '
        'echo "attacker:x:0:0::/:/bin/sh" >> /etc/passwd && echo wrote-passwd'}))
    t.check("[前置] 根 tmpfs 与 /etc 确实可写（污染已写入）",
            "wrote-root" in d.get("stdout", "") and "wrote-passwd" in d.get("stdout", ""),
            d.get("stdout", "").replace("\n", " ")[:60])
    d = data_of(call(SESSION_A, TENANT_A, "run_command", {"command":
        f'[ -e {MARK} ] && echo MARK-SURVIVED; wc -l < /etc/passwd'}))
    out = d.get("stdout", "")
    t.check("对 / 的写入下次调用即消失（每次执行重建 rootfs）",
            "MARK-SURVIVED" not in out, f"stdout={out.replace(chr(10), ' ')[:60]}")
    t.check("对 /etc/passwd 的污染不残留",
            out.strip().splitlines()[-1].strip() == "1" if out.strip() else False,
            f"行数={out.strip().splitlines()[-1].strip() if out.strip() else '?'}")

    print("\n━━━ 11.6 隔离边界是租户，不是 session ━━━")
    # 同一租户的第二个 session：/workspace 必须是**同一份**数据（这是共享文件
    # 系统的意义所在），而 /workspace 之外必须互不可见。两个方向都要断言 ——
    # 只测"能读到"会漏掉易失层泄漏，只测"读不到"则会把正确行为当成 bug。
    SESSION_A2 = _session_id("a2")
    XFILE = f"/workspace/xsess-{CANARY[-8:]}.txt"
    EPH = f"/tmp/eph-{CANARY[-8:]}.txt"
    d = data_of(call(SESSION_A, TENANT_A, "run_command", {"command":
        f'echo {CANARY} > {XFILE} && echo S1 > {EPH} && '
        f'stat -c %i {XFILE}; grep " /workspace " /proc/mounts | cut -d" " -f1'}))
    lines = [l for l in d.get("stdout", "").splitlines() if l.strip()]
    t.check("[前置] session1 写入成功并取到 inode/挂载源",
            len(lines) == 2 and lines[0].isdigit(), f"{lines}")
    inode_1, src_1 = (lines + ["", ""])[:2]

    d2 = data_of(call(SESSION_A2, TENANT_A, "run_command", {"command":
        f'cat {XFILE}; stat -c %i {XFILE}; '
        f'grep " /workspace " /proc/mounts | cut -d" " -f1; '
        f'cat {EPH} 2>/dev/null || echo EPH-ABSENT'}))
    l2 = [l for l in d2.get("stdout", "").splitlines() if l.strip()]
    t.check("同租户的另一个 session 读到自己的 /workspace 文件（预期行为）",
            len(l2) == 4 and l2[0] == CANARY, f"{l2[:1]}")
    t.check("两个 session 的 /workspace 是同一个 inode（同一份数据，非内容巧合）",
            len(l2) == 4 and l2[1] == inode_1 and inode_1,
            f"{inode_1} vs {l2[1] if len(l2) > 1 else '?'}")
    t.check("两个 session 的 /workspace 挂载源相同",
            len(l2) == 4 and l2[2] == src_1 and src_1, f"{src_1} vs {l2[2] if len(l2) > 2 else '?'}")
    t.check("/workspace 之外的写入不跨 session（/tmp 是各自的 tmpfs）",
            len(l2) == 4 and l2[3] == "EPH-ABSENT", f"{l2[3] if len(l2) > 3 else '?'}")

    # 反向对照：换租户才真正换存储。没有这一条，上面四条就只证明了"共享"，
    # 没证明"共享仅限同租户"。
    # cat 的报错留在 stderr（不做 2>&1），否则它会顶进 stdout 把下面的行号错开
    d3 = data_of(call(SESSION_B, TENANT_B, "run_command", {"command":
        f'cat {XFILE}; stat -c %i /workspace; '
        f'grep " /workspace " /proc/mounts | cut -d" " -f1'}))
    out3 = d3.get("stdout", "") + d3.get("stderr", "")
    t.check("换租户后同一路径读不到（存储边界在租户）",
            CANARY not in out3 and "No such file" in out3,
            out3.replace("\n", " ")[:70])
    l3 = [l for l in d3.get("stdout", "").splitlines() if l.strip()]
    t.check("另一租户的 /workspace 挂载源不同",
            len(l3) == 2 and l3[1] != src_1, f"{src_1} vs {l3[1] if len(l3) > 1 else '?'}")
    call(SESSION_A, TENANT_A, "run_command", {"command": f'rm -f {XFILE}'})

    print("\n━━━ 12. 破坏性尝试后 B 的数据完好 ━━━")
    call(SESSION_A, TENANT_A, "run_command",
         {"command": "rm -rf /mnt/shared /workspace/../* /.oldroot 2>&1; echo tried",
          "timeout": 25})
    r = call(SESSION_B, TENANT_B, "read_file", {"path": "secret/canary.txt"})
    t.check("A 的 rm -rf 未影响 B 的 canary", data_of(r).get("content") == CANARY,
            f"{str(data_of(r))[:90]}")
    r = call(SESSION_B, TENANT_B, "read_file", {"path": "output/b.txt"})
    t.check("A 的 rm -rf 未影响 B 的其他文件", data_of(r).get("content") == SECRET_B)

    print("\n━━━ 清理 ━━━")
    call(SESSION_A, TENANT_A, "run_command",
         {"command": "rm -f /workspace/esc_* ; rm -rf /workspace/d ; echo cleaned"})
    for sid in (SESSION_A, SESSION_B):
        try:
            client.stop_runtime_session(agentRuntimeArn=RUNTIME_ARN, runtimeSessionId=sid)
        except Exception as e:
            print(f"  stop {sid[:20]}: {type(e).__name__}")
    print("  done")

    return t.summary()


KEY_HELP = f"""\
拿不到签名密钥，无法验证 —— Runtime 处于 hmac 模式，每一次调用都要带
签名 token，不只是身份测试那几项。

按下面任一种方式提供（与 Runtime 的密钥必须一致）：

  # 1. 从 Secrets Manager 导出（Runtime 读的就是这个 secret）
  export TENANT_SIGNING_KEY="$(aws secretsmanager get-secret-value \\
    --secret-id {SECRET_ID} --region {REGION} \\
    --query SecretString --output text)"

  # 2. 或让本脚本自己去拉（需要当前身份有 secretsmanager:GetSecretValue）
  export TENANT_SIGNING_KEY_SECRET_ID={SECRET_ID}

密钥只应存在于业务 Pod 与 Runtime 两侧，不要下发给租户。"""


if __name__ == "__main__":
    if boto3 is None:
        sys.exit("boto3 required: pip install boto3")

    SIGNING_KEY, KEY_SOURCE = load_signing_key()
    if not SIGNING_KEY:
        sys.exit(KEY_HELP)
    if len(SIGNING_KEY) < 32:
        sys.exit(f"签名密钥太短（{len(SIGNING_KEY)} 字节，需 >= 32）")

    sys.exit(0 if run_tests() else 1)
