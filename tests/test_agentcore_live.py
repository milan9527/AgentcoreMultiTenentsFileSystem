#!/usr/bin/env python3
"""
AgentCore Runtime EFS 共享存储隔离 - 线上验证测试

直接调用 AWS AgentCore Runtime，验证：
1. EFS 挂载
2. Bind mount 隔离
3. 文件读写
4. 路径遍历防护
5. 多租户隔离
6. Session 绑定
7. 代码执行隔离

使用方法:
    python3 tests/test_agentcore_live.py

环境要求:
    - AWS credentials 已配置
    - AgentCore Runtime 已部署且 READY
    - pip install boto3
"""

import json
import time
import sys
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import urllib3

# ─── 配置 ─────────────────────────────────────────────────────────

REGION = "us-east-1"
RUNTIME_ID = "sandboxIsolationDemo-COIZYqEK2d"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{REGION}:632930644527:runtime/{RUNTIME_ID}"

SESSION_A = "test-isolation-tenantA-session001"
SESSION_B = "test-isolation-tenantB-session001"

# ─── 调用封装 ─────────────────────────────────────────────────────

http = urllib3.PoolManager()
session = boto3.Session(region_name=REGION)


def invoke(session_id: str, tenant_id: str, action: str, params: dict = None) -> dict:
    """调用 AgentCore Runtime"""
    creds = session.get_credentials().get_frozen_credentials()
    url = f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/{RUNTIME_ID}/sessions/{session_id}/invocations"

    payload = json.dumps({
        "tenant_id": tenant_id,
        "action": action,
        "params": params or {},
    })

    headers = {
        "Content-Type": "application/json",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
    }

    req = AWSRequest(method="POST", url=url, data=payload, headers=headers)
    SigV4Auth(creds, "bedrock-agentcore", REGION).add_auth(req)

    resp = http.request("POST", url, body=payload, headers=dict(req.headers))

    if resp.status != 200:
        # 尝试解析响应
        try:
            body = json.loads(resp.data.decode())
            return body
        except Exception:
            return {"error": f"HTTP {resp.status}: {resp.data.decode()[:200]}"}

    return json.loads(resp.data.decode())


def invoke_via_sdk(session_id: str, tenant_id: str, action: str, params: dict = None) -> dict:
    """通过 boto3 SDK 调用 (使用正确的 API)"""
    client = boto3.client("bedrock-agentcore", region_name=REGION)

    payload = json.dumps({
        "tenant_id": tenant_id,
        "action": action,
        "params": params or {},
    })

    try:
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=RUNTIME_ARN,
            runtimeSessionId=session_id,
            payload=payload.encode(),
        )
        body = b"".join(resp.get("response", []))
        return json.loads(body)
    except client.exceptions.ClientError as e:
        return {"error": str(e)}
    except Exception as e:
        # 如果 SDK 不支持此 API，回退到 raw 请求
        return invoke_raw(session_id, tenant_id, action, params)


def invoke_raw(session_id: str, tenant_id: str, action: str, params: dict = None) -> dict:
    """Raw SigV4 请求"""
    creds = session.get_credentials().get_frozen_credentials()
    # 使用 data-plane endpoint
    url = f"https://bedrock-agentcore.{REGION}.amazonaws.com/agentRuntimes/{RUNTIME_ID}/invocations"

    payload = json.dumps({
        "tenant_id": tenant_id,
        "action": action,
        "params": params or {},
    })

    headers = {
        "Content-Type": "application/json",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
    }

    req = AWSRequest(method="POST", url=url, data=payload, headers=headers)
    SigV4Auth(creds, "bedrock-agentcore", REGION).add_auth(req)

    resp = http.request("POST", url, body=payload, headers=dict(req.headers))
    try:
        data = json.loads(resp.data.decode())
        # 如果响应包含 response body
        if "response" in data:
            return json.loads(data["response"]) if isinstance(data["response"], str) else data["response"]
        return data
    except Exception:
        return {"error": f"HTTP {resp.status}"}


def call(session_id: str, tenant_id: str, action: str, params: dict = None) -> dict:
    """统一调用入口 - 尝试 SDK 再回退 raw"""
    try:
        client = boto3.client("bedrock-agentcore", region_name=REGION)
        payload_bytes = json.dumps({
            "tenant_id": tenant_id,
            "action": action,
            "params": params or {},
        }).encode()

        resp = client.invoke_agent_runtime(
            agentRuntimeArn=RUNTIME_ARN,
            runtimeSessionId=session_id,
            payload=payload_bytes,
        )
        # 读取流式响应
        body_parts = []
        for chunk in resp.get("response", resp.get("body", [])):
            if isinstance(chunk, dict) and "chunk" in chunk:
                body_parts.append(chunk["chunk"]["bytes"])
            elif isinstance(chunk, bytes):
                body_parts.append(chunk)

        if body_parts:
            full_body = b"".join(body_parts)
            return json.loads(full_body)

        # 有些版本直接返回
        if "body" in resp:
            return json.loads(resp["body"].read())

        return {"error": "empty response"}
    except Exception as e:
        error_msg = str(e)
        if "424" in error_msg or "502" in error_msg:
            return {"error": f"Runtime error: {error_msg[:200]}"}
        if "ParamValidation" in error_msg:
            return {"error": error_msg}
        # 可能 API 格式不同
        return {"error": error_msg[:300]}


# ─── 测试框架 ─────────────────────────────────────────────────────

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def check(self, name: str, condition: bool, detail: str = ""):
        status = "✅ PASS" if condition else "❌ FAIL"
        self.results.append((name, status, detail))
        if condition:
            self.passed += 1
        else:
            self.failed += 1
        print(f"  {status}: {name}")
        if detail:
            print(f"         {detail}")

    def summary(self):
        print(f"\n{'='*60}")
        print(f"  结果: {self.passed} passed, {self.failed} failed, {self.passed+self.failed} total")
        print(f"{'='*60}")
        return self.failed == 0


# ─── 测试用例 ─────────────────────────────────────────────────────

def run_tests():
    print("=" * 60)
    print("  AgentCore Runtime EFS 隔离验证测试")
    print("=" * 60)
    print(f"  Runtime: {RUNTIME_ID}")
    print(f"  Region:  {REGION}")
    print(f"  Session A: {SESSION_A}")
    print(f"  Session B: {SESSION_B}")
    print("=" * 60)
    print()

    t = TestResult()

    # ─── Test 1: EFS 挂载验证 ─────────────────────────────────
    print("━━━ Test 1: EFS 挂载验证 ━━━")
    r = call(SESSION_A, "tenant-A", "run_command", {"command": "ls /mnt/shared/"})
    if "error" in r and "Runtime error" not in str(r.get("error", "")):
        print(f"  调用失败: {r}")
        print("  提示: 确认 Runtime 已 READY 且 EFS 已挂载")
        return False

    data = r.get("data", r)
    stdout = data.get("stdout", "")
    t.check("EFS /mnt/shared 可访问", "tenants" in stdout or data.get("exit_code") == 0, f"stdout: {stdout[:100]}")
    print()

    # ─── Test 2: Workspace bind mount ────────────────────────
    print("━━━ Test 2: Workspace bind mount 隔离 ━━━")
    r = call(SESSION_A, "tenant-A", "run_command", {"command": "ls /workspace/"})
    data = r.get("data", r)
    stdout = data.get("stdout", "")
    t.check("/workspace 存在且有内容", "input" in stdout and "output" in stdout, f"内容: {stdout.strip()}")

    r = call(SESSION_A, "tenant-A", "status", {})
    data = r.get("data", r)
    t.check("isolated = true (bind mount 生效)", data.get("isolated") == True, f"status: {data}")
    print()

    # ─── Test 3: 文件写入 ─────────────────────────────────────
    print("━━━ Test 3: Tenant-A 写入文件 ━━━")
    content_a = f"tenant-A secret data {int(time.time())}"
    r = call(SESSION_A, "tenant-A", "write_file", {"path": "output/secret_A.txt", "content": content_a})
    data = r.get("data", r)
    t.check("写入成功", data.get("written") == len(content_a), f"written: {data.get('written')}")
    print()

    # ─── Test 4: 文件读取 ─────────────────────────────────────
    print("━━━ Test 4: Tenant-A 读取自己的文件 ━━━")
    r = call(SESSION_A, "tenant-A", "read_file", {"path": "output/secret_A.txt"})
    data = r.get("data", r)
    t.check("读取内容正确", data.get("content") == content_a, f"content: {data.get('content', data.get('error', ''))[:50]}")
    print()

    # ─── Test 5: 路径遍历攻击 ─────────────────────────────────
    print("━━━ Test 5: Tenant-A 路径遍历攻击 (../tenant-B/) ━━━")
    attacks = [
        "../tenant-B/output/secret_B.txt",
        "../../tenants/tenant-B/output/secret_B.txt",
        "output/../../../etc/passwd",
    ]
    for path in attacks:
        r = call(SESSION_A, "tenant-A", "read_file", {"path": path})
        data = r.get("data", r)
        t.check(f"阻止: {path}", data.get("error") == "Path not allowed", f"响应: {data}")
    print()

    # ─── Test 6: Tenant-B 独立 session ────────────────────────
    print("━━━ Test 6: Tenant-B 独立 session 写入 ━━━")
    content_b = f"tenant-B secret data {int(time.time())}"
    r = call(SESSION_B, "tenant-B", "write_file", {"path": "output/secret_B.txt", "content": content_b})
    data = r.get("data", r)
    t.check("Tenant-B 写入成功", data.get("written") == len(content_b), f"written: {data.get('written')}")
    print()

    # ─── Test 7: Tenant-B 反向路径遍历 ────────────────────────
    print("━━━ Test 7: Tenant-B 路径遍历访问 Tenant-A ━━━")
    r = call(SESSION_B, "tenant-B", "read_file", {"path": "../tenant-A/output/secret_A.txt"})
    data = r.get("data", r)
    t.check("Tenant-B 无法访问 Tenant-A", data.get("error") == "Path not allowed", f"响应: {data}")
    print()

    # ─── Test 8: Tenant-B 读取自己的文件 ──────────────────────
    print("━━━ Test 8: Tenant-B 读取自己的文件 ━━━")
    r = call(SESSION_B, "tenant-B", "read_file", {"path": "output/secret_B.txt"})
    data = r.get("data", r)
    t.check("Tenant-B 读取自己文件成功", data.get("content") == content_b, f"content: {data.get('content', data.get('error', ''))[:50]}")
    print()

    # ─── Test 9: Session 租户绑定 ─────────────────────────────
    print("━━━ Test 9: 同一 Session 切换租户 (应被拒绝) ━━━")
    r = call(SESSION_A, "tenant-B", "read_file", {"path": "output/secret_B.txt"})
    data = r.get("data", r)
    error_msg = r.get("error", data.get("error", ""))
    t.check(
        "切换租户被拒绝 (PERMISSION_DENIED)",
        "cannot switch" in str(error_msg) or "PERMISSION_DENIED" in str(r),
        f"响应: {str(r)[:150]}"
    )
    print()

    # ─── Test 10: 代码执行 ────────────────────────────────────
    print("━━━ Test 10: Python 代码执行验证 ━━━")
    code = """
import os, json
info = {
    "uid": os.getuid(),
    "cwd": os.getcwd(),
    "workspace_is_mount": os.path.ismount("/workspace"),
    "files": os.listdir("/workspace"),
}
print(json.dumps(info))
"""
    r = call(SESSION_A, "tenant-A", "run_code", {"code": code, "language": "python"})
    data = r.get("data", r)
    stdout = data.get("stdout", "")
    try:
        info = json.loads(stdout.strip())
        t.check("代码执行成功", data.get("exit_code") == 0, f"exit_code: {data.get('exit_code')}")
        t.check("运行在 /workspace (bind mount)", info.get("workspace_is_mount") == True, f"ismount: {info.get('workspace_is_mount')}")
        t.check("workspace 包含 input/output", "input" in info.get("files", []) and "output" in info.get("files", []), f"files: {info.get('files')}")
    except (json.JSONDecodeError, TypeError):
        t.check("代码执行成功", False, f"无法解析输出: {stdout[:100]}")
    print()

    # ─── Test 11: 列目录 ─────────────────────────────────────
    print("━━━ Test 11: 列目录验证 ━━━")
    r = call(SESSION_A, "tenant-A", "list_files", {"path": "output"})
    data = r.get("data", r)
    entries = data.get("entries", [])
    names = [e["name"] for e in entries]
    t.check("list_files 返回文件列表", "secret_A.txt" in names, f"entries: {names}")
    print()

    # ─── Test 12: 目录遍历 list_files ────────────────────────
    print("━━━ Test 12: list_files 路径遍历防护 ━━━")
    r = call(SESSION_A, "tenant-A", "list_files", {"path": "../"})
    data = r.get("data", r)
    t.check("list_files 路径遍历被阻止", data.get("error") == "Path not allowed", f"响应: {data}")
    print()

    # ─── 清理 ─────────────────────────────────────────────────
    print("━━━ 清理: 停止 sessions ━━━")
    try:
        client = boto3.client("bedrock-agentcore", region_name=REGION)
        client.stop_runtime_session(agentRuntimeArn=RUNTIME_ARN, runtimeSessionId=SESSION_A)
        client.stop_runtime_session(agentRuntimeArn=RUNTIME_ARN, runtimeSessionId=SESSION_B)
        print("  Sessions 已停止")
    except Exception as e:
        print(f"  停止 session 失败 (可能已超时自动停止): {e}")
    print()

    # ─── 总结 ─────────────────────────────────────────────────
    return t.summary()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
