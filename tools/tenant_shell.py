#!/usr/bin/env python3
"""
tenant_shell.py - 交互式租户 shell，用来"手动"验证隔离

每敲一条命令，就是一次 InvokeAgentRuntime → 一次 mount namespace jail 内的执行。
你看到的文件系统就是那个租户在 jail 里看到的全部内容。

    $ ./tools/tenant_shell.py --tenant tenant-a
    [tenant-a] /workspace $ ls /
    bin dev etc lib opt proc sbin tmp usr workspace
    [tenant-a] /workspace $ cat /mnt/shared/tenants/tenant-b/output/b.txt
    cat: /mnt/shared/tenants/tenant-b/output/b.txt: No such file or directory

关于"登录"的一点说明（这是隔离模型的核心，不是实现偷懒）：

  这个 shell 不是 ssh —— 没有 tenant 侧的账号密码可登。租户身份来自**业务 Pod
  用共享密钥签发的 HMAC token**，Runtime 侧验签。所以能不能"登录成 tenant-a"，
  取决于你有没有签名密钥，而不是取决于你说自己是谁。

  这正是设计意图：如果 shell 能靠"我声明我是 tenant-a"就进去，那 tenant_id 就
  又变成自证的了。因此本工具必须拿到 TENANT_SIGNING_KEY 才能工作 ——
  它扮演的是**业务 Pod**（可信的签发方），而不是租户本人。

  --no-sign 会退化成明文 tenant_id，仅当 Runtime 处于 insecure_payload 模式时
  可用；正常部署下会被 Runtime 直接拒掉（UNAUTHENTICATED），这本身就是一次验证。

内置命令（不发到 Runtime，本地处理）：
    :help            命令列表
    :status          沙箱状态（tenant_id / auth_mode / sandbox / 配额）
    :probe           一键跑完隔离探测（挂载表、跨租户、逃逸、capability）
    :su <tenant>     切换租户（新开一个 session；同 session 内切换会被拒绝）
    :session         当前 session_id 与租户
    :switch-attack [tenant]  在**当前** session 里尝试换租户，演示会被拒绝
                     （先用自己的身份调一次坐实绑定，再去撞它）
    :read <path>     走受守卫 API 读（对比 jail 内 cat）
    :write <path>    走受守卫 API 写
    :ls [path]       走受守卫 API 列目录
    :py <code>       走 run_code 执行 python
    :timeout <秒>    设置命令超时
    :quit / Ctrl-D   退出

用法:
    export RUNTIME_ID=sandboxIsolationDemo-xxxx AWS_REGION=us-east-1
    ./tools/tenant_shell.py --tenant tenant-a

密钥来源（二者取一，本工具自己解析，不需要手动导出）：
    TENANT_SIGNING_KEY            直接给密钥
    TENANT_SIGNING_KEY_SECRET_ID  从 Secrets Manager 取（默认
                                  agentcore/tenant-signing-key，与 Runtime 同一个）
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import shlex
import sys
import time
import uuid

try:
    import boto3
except ImportError:
    sys.exit("boto3 required: pip install boto3")

try:
    import readline  # noqa: F401  行编辑与历史
except ImportError:
    pass


# ─── 颜色（非 tty 时自动关闭）────────────────────────────────────

class C:
    on = sys.stdout.isatty()

    @classmethod
    def _w(cls, code, s):
        return f"\033[{code}m{s}\033[0m" if cls.on else s

    @classmethod
    def dim(cls, s):
        return cls._w("2", s)

    @classmethod
    def red(cls, s):
        return cls._w("31", s)

    @classmethod
    def green(cls, s):
        return cls._w("32", s)

    @classmethod
    def yellow(cls, s):
        return cls._w("33", s)

    @classmethod
    def cyan(cls, s):
        return cls._w("36", s)

    @classmethod
    def bold(cls, s):
        return cls._w("1", s)


# ─── token 签发（与 runtime/tenant_identity.py 对应）──────────────

def sign_tenant_token(tenant_id, signing_key, ttl_seconds=900):
    expiry = int(time.time()) + ttl_seconds
    sig = hmac.new(signing_key, f"{tenant_id}.{expiry}".encode(), hashlib.sha256).digest()
    return f"{tenant_id}.{expiry}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


def load_signing_key(region, secret_id):
    """
    取签名密钥。优先 TENANT_SIGNING_KEY，否则从 Secrets Manager 拉 ——
    和 Runtime 的 tenant_identity.py 读同一个 secret，避免两边不一致。
    返回 (key_bytes, 来源描述)；拿不到返回 (None, None)。
    """
    raw = os.environ.get("TENANT_SIGNING_KEY")
    if raw:
        return raw.encode(), "env TENANT_SIGNING_KEY"
    try:
        sm = boto3.client("secretsmanager", region_name=region)
        val = sm.get_secret_value(SecretId=secret_id)
        val = val.get("SecretString") or val.get("SecretBinary")
        if isinstance(val, bytes):
            return val, f"secretsmanager:{secret_id}"
        try:
            parsed = json.loads(val)
            if isinstance(parsed, dict):
                for k in ("signing_key", "TENANT_SIGNING_KEY", "key"):
                    if k in parsed:
                        return str(parsed[k]).encode(), f"secretsmanager:{secret_id}[{k}]"
        except (json.JSONDecodeError, TypeError):
            pass
        return str(val).encode(), f"secretsmanager:{secret_id}"
    except Exception as e:
        print(C.dim(f"  (无法从 Secrets Manager 读取 {secret_id}: {type(e).__name__})"))
        return None, None


KEY_HELP = """需要签名密钥（与 Runtime 的一致）才能签出租户身份。

这个 shell 扮演业务 Pod（可信签发方），不是租户本人 —— 租户身份来自 HMAC
签名 token，不是自证。没有密钥就签不出合法身份，Runtime 会回 UNAUTHENTICATED。

两条路，任选其一：

  1) 直接给密钥
     export TENANT_SIGNING_KEY="$(aws secretsmanager get-secret-value \\
       --secret-id agentcore/tenant-signing-key \\
       --query SecretString --output text)"

  2) 让本工具自己去 Secrets Manager 取（需要当前 AWS 身份有
     secretsmanager:GetSecretValue 权限）
     export TENANT_SIGNING_KEY_SECRET_ID=agentcore/tenant-signing-key

想看未认证的调用会怎样，用 --no-sign。"""


class TenantShell:
    def __init__(self, runtime_arn, region, signing_key, tenant_id,
                 session_id=None, timeout=60, key_source=""):
        self.client = boto3.client("bedrock-agentcore", region_name=region)
        self.runtime_arn = runtime_arn
        self.signing_key = signing_key
        self.key_source = key_source
        self.tenant_id = tenant_id
        self.timeout = timeout
        self.session_id = self._pad(session_id) if session_id \
            else self._new_session_id(tenant_id)
        self.cwd = "/workspace"
        # -c 模式要把它当进程退出码用：脚本里 `shell -c 'cmd' && next` 得能短路。
        # 认证/传输失败也记在这里，否则调用根本没打通却返回 0。
        self.last_rc = 0
        self.probe_failed = 0

    @staticmethod
    def _pad(sid):
        """AgentCore 要求 runtimeSessionId >= 33 字符。手动传入的短 id 也补齐 ——
        否则只会撞上 boto3 的 ParamValidationError，对使用者毫无信息量。"""
        return sid + "0" * max(0, 33 - len(sid))

    @classmethod
    def _new_session_id(cls, tenant_id):
        return cls._pad(f"shell-{tenant_id}-{uuid.uuid4().hex}")

    # ─── 传输层 ──────────────────────────────────────────────────

    def invoke(self, action, params=None, tenant_override=None, raw_token=None):
        tenant = tenant_override or self.tenant_id
        body = {"action": action, "params": params or {}}
        if raw_token is not None:
            body["tenant_token"] = raw_token
        elif self.signing_key:
            body["tenant_token"] = sign_tenant_token(tenant, self.signing_key)
        else:
            body["tenant_id"] = tenant

        try:
            resp = self.client.invoke_agent_runtime(
                agentRuntimeArn=self.runtime_arn,
                runtimeSessionId=self.session_id,
                payload=json.dumps(body).encode(),
            )
            chunks = []
            for chunk in resp.get("response", []):
                chunks.append(chunk if isinstance(chunk, bytes) else chunk["chunk"]["bytes"])
            return json.loads(b"".join(chunks)) if chunks else {"error": "empty response"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)[:300]}"}

    @staticmethod
    def data_of(resp):
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def _show_error(self, resp):
        """Runtime 层错误（认证/权限）单独提示，避免和命令输出混淆"""
        if isinstance(resp, dict) and resp.get("status") == "error":
            code = resp.get("code", "ERROR")
            print(C.red(f"[{code}] {resp.get('error', '')}"))
            self.last_rc = 1      # 调用被拒 —— 不能让 -c 返回 0
            return True
        if isinstance(resp, dict) and "error" in resp and "data" not in resp:
            print(C.red(f"[transport] {resp['error']}"))
            self.last_rc = 1
            return True
        return False

    # ─── shell 命令执行 ──────────────────────────────────────────

    # /workspace 之外的写入都落在那次执行私有的 tmpfs 上，下次调用就没了。
    # 这不是 bug，但命令会返回 exit 0，看起来像"成功了却没生效" —— 所以要提示。
    EPHEMERAL_HINT = ("写入 {paths} 只在本次调用内有效（jail 的 rootfs 每次执行重建）。"
                      "要持久化请写 /workspace。")

    def _ephemeral_targets(self, command):
        """
        挑出命令里指向非 /workspace 绝对路径的写入目标。
        故意保守：只认常见写命令 + 明确的重定向，宁可漏报也不要对着
        `cat /etc/passwd` 这种纯读操作瞎提示。
        """
        WRITERS = {"touch", "mkdir", "rm", "rmdir", "cp", "mv", "ln", "dd",
                   "tee", "truncate", "install", "chmod", "chown", "sed"}
        PERSIST = ("/workspace", "/proc", "/dev", "/sys")
        try:
            tokens = shlex.split(command)
        except ValueError:      # 引号不配对 —— 交给 jail 里的 bash 去报错
            return []
        # cwd 在 /workspace 之外时，相对路径同样是易失的（在 /etc 里 `touch a.txt`
        # 和 `touch /etc/a.txt` 一样活不过这次调用），所以按 cwd 补全再判断
        outside_ws = not self.cwd.startswith(PERSIST)

        # shlex 不切 shell 元字符，`touch /etc/x; ls /etc/x` 会给出 "/etc/x;" ——
        # 分号既粘进路径，又让后半段命令继续顶着"前面见过写命令"的状态。
        # 所以先按分隔符切成独立命令段，每段单独判断。
        segments, cur = [], []
        for tok in tokens:
            parts = tok.replace("&&", ";").replace("||", ";").replace("|", ";") \
                       .replace("&", ";").split(";")
            for j, part in enumerate(parts):
                if j:
                    segments.append(cur)
                    cur = []
                if part:
                    cur.append(part)
        segments.append(cur)

        hits = []
        for seg in segments:
            saw_writer = False
            for i, tok in enumerate(seg):
                if tok.rsplit("/", 1)[-1] in WRITERS:
                    saw_writer = True
                    continue                       # 命令名本身不是写入目标
                redirect = tok.startswith(">")
                if not (saw_writer or redirect):
                    continue
                # 重定向目标可能贴在 > 后面（>/etc/x），也可能是下一个 token
                if redirect:
                    cands = [tok.lstrip(">")] or []
                    if not cands[0] and i + 1 < len(seg):
                        cands = [seg[i + 1]]
                else:
                    cands = [tok]
                for c in cands:
                    if not c or c.startswith("-"):
                        continue                   # 选项不是路径
                    if c.startswith("/"):
                        if not c.startswith(PERSIST):
                            hits.append(c)
                    elif outside_ws:
                        hits.append(f"{self.cwd.rstrip('/')}/{c}")
        # /tmp 也是易失的，但那是所有人都预期的语义，不值得每次都念一遍
        return sorted({h for h in hits if not h.startswith("/tmp")})

    def exec_command(self, command):
        self.last_rc = 0
        # cwd 由 shell 侧维护：每次 invoke 都是新进程，cd 不会跨调用保留
        wrapped = f"cd {self.cwd} 2>/dev/null || cd /workspace; {command}"
        resp = self.invoke("run_command", {"command": wrapped, "timeout": self.timeout})
        if self._show_error(resp):
            return
        d = self.data_of(resp)
        if d.get("sandbox_error"):
            print(C.red("沙箱不可用，执行被拒绝（jail 建立失败，fail-closed）"))
            self.last_rc = 126
            return
        sys.stdout.write(d.get("stdout", ""))
        err = d.get("stderr", "")
        if err:
            sys.stderr.write(C.red(err) if C.on else err)
        rc = d.get("exit_code", -1)
        self.last_rc = rc if isinstance(rc, int) else 1
        if rc not in (0, None):
            print(C.dim(f"[exit {rc}]"))
        # 只在写入"看起来成功了"时提示 —— 失败的话 stderr 已经说明问题了
        if rc == 0:
            eph = self._ephemeral_targets(command)
            if eph:
                paths = " ".join(eph[:3]) + ("…" if len(eph) > 3 else "")
                print(C.yellow("  ⓘ " + self.EPHEMERAL_HINT.format(paths=paths)))

    def track_cd(self, command):
        """
        `cd X` 单独处理：更新本地 cwd。
        用 jail 内的 pwd 回读结果，所以逃逸尝试（cd /mnt/shared）会如实失败。
        """
        target = command[2:].strip() or "/workspace"
        resp = self.invoke("run_command", {
            "command": f"cd {self.cwd} 2>/dev/null || cd /workspace; cd {target} && pwd",
            "timeout": self.timeout,
        })
        if self._show_error(resp):
            return
        d = self.data_of(resp)
        if d.get("exit_code") == 0 and d.get("stdout", "").strip():
            self.cwd = d["stdout"].strip().splitlines()[-1]
        else:
            sys.stderr.write(C.red(d.get("stderr") or f"cd: {target}: 无法进入\n"))

    # ─── 内置命令 ────────────────────────────────────────────────

    def cmd_status(self):
        resp = self.invoke("status")
        if self._show_error(resp):
            return
        d = self.data_of(resp)
        for k in ("tenant_id", "workspace", "auth_mode", "sandbox",
                  "used_bytes", "quota_bytes"):
            if k in d:
                print(f"  {C.cyan(k):<24} {d[k]}")

    def cmd_session(self):
        print(f"  {C.cyan('tenant_id'):<24} {self.tenant_id}")
        print(f"  {C.cyan('session_id'):<24} {self.session_id}")
        print(f"  {C.cyan('auth'):<24} "
              f"{'hmac signed token' if self.signing_key else C.red('unsigned tenant_id')}")
        print(f"  {C.cyan('key source'):<24} {self.key_source}")
        print(f"  {C.cyan('timeout'):<24} {self.timeout}s")

    def cmd_su(self, tenant):
        """切租户 = 新开 session。同 session 内切换必被拒（见 :switch-attack）"""
        if not tenant:
            print("用法: :su <tenant_id>")
            return
        self.tenant_id = tenant
        self.session_id = self._new_session_id(tenant)
        self.cwd = "/workspace"
        print(C.green(f"已切换到 {tenant}"))
        print(C.dim(f"  新 session: {self.session_id}"))

    def cmd_switch_attack(self, victim=""):
        """在当前 session 里冒充另一个租户 —— 应该被 PERMISSION_DENIED 拒绝"""
        # 不给参数就自动挑一个不是自己的租户；`:switch-attack tenant-b` 也能用
        victim = victim or ("tenant-b" if self.tenant_id != "tenant-b" else "tenant-a")
        if victim == self.tenant_id:
            print("这就是当前租户，换一个才叫越权：:switch-attack <别的 tenant_id>")
            return
        # 绑定是由 session 的**第一次**调用建立的。走 `-c ':switch-attack'` 时这就是
        # 第一次调用，没有既有绑定可违反 —— 于是 session 直接绑到 victim，看起来像
        # 越权成功。所以先用自己的身份调一次把绑定坐实，再去撞它。
        pre = self.invoke("status")
        if isinstance(pre, dict) and pre.get("status") != "ok":
            print(C.red(f"[前置] 建立 session 绑定失败: {str(pre)[:160]}"))
            self.last_rc = 1
            return
        print(C.dim(f"session 已绑定 {self.tenant_id}，"
                    f"现在在同一 session 内用 {victim} 的 token 调用 status …"))
        resp = self.invoke("status", tenant_override=victim)
        code = resp.get("code") if isinstance(resp, dict) else None
        if code == "PERMISSION_DENIED":
            print(C.green(f"✅ 被拒绝: {resp.get('error')}"))
        else:
            # 没被拒就是隔离失效，退出码必须非零，不然 -c 跑在 CI 里会静默放过
            print(C.red(f"❌ 未被拒绝！响应: {str(resp)[:200]}"))
            self.last_rc = 1
        print(C.dim("（换租户需要新 session —— 用 :su）"))

    def cmd_read(self, path):
        if not path:
            print("用法: :read <path>")
            return
        resp = self.invoke("read_file", {"path": path})
        if self._show_error(resp):
            return
        d = self.data_of(resp)
        if "error" in d:
            print(C.red(f"[guard] {d['error']}"))
            self.last_rc = 1        # 守卫拒绝也是失败，-c 不能返回 0
        else:
            print(d.get("content", ""), end="" if d.get("content", "").endswith("\n") else "\n")

    def cmd_write(self, rest):
        parts = rest.split(None, 1)
        if len(parts) < 2:
            print("用法: :write <path> <content>")
            return
        resp = self.invoke("write_file", {"path": parts[0], "content": parts[1]})
        if self._show_error(resp):
            return
        d = self.data_of(resp)
        if "error" in d:
            print(C.red(f"[guard] {d['error']}"))
            self.last_rc = 1
        else:
            print(C.green(f"已写入 {d.get('written')} 字节 → {d.get('path')}"))

    def cmd_ls(self, path):
        resp = self.invoke("list_files", {"path": path or "."})
        if self._show_error(resp):
            return
        d = self.data_of(resp)
        if "error" in d:
            print(C.red(f"[guard] {d['error']}"))
            self.last_rc = 1
            return
        for e in d.get("entries", []):
            kind = "d" if e.get("is_dir") else ("l" if e.get("is_symlink") else "-")
            name = e["name"] + ("/" if e.get("is_dir") else "")
            print(f"  {kind} {e.get('size', 0):>10}  {name}")
        if d.get("truncated"):
            print(C.yellow("  … 已截断"))

    def cmd_py(self, code):
        if not code:
            print("用法: :py <python 代码>")
            return
        resp = self.invoke("run_code", {"code": code, "timeout": self.timeout})
        if self._show_error(resp):
            return
        d = self.data_of(resp)
        sys.stdout.write(d.get("stdout", ""))
        if d.get("stderr"):
            sys.stderr.write(C.red(d["stderr"]))

    def cmd_probe(self):
        """一键隔离探测。判定标准与 tests/test_agentcore_live.py 一致。"""
        self.probe_failed = 0
        print(C.bold("\n  隔离探测（当前租户视角）"))
        print(C.dim(f"  tenant={self.tenant_id}  session={self.session_id}\n"))

        # 先确认能打通：认证失败时后面每一项都会"失败"，但那不是隔离结论，
        # 是探测本身没跑起来 —— 必须区分开，否则等于用一堆 ❌ 骗自己。
        first = self.invoke("run_command", {"command": "cat /proc/mounts"})
        if self._show_error(first):
            print(C.yellow("\n  探测未执行：调用没打通，上面的错误先解决。"
                           f"\n  当前密钥来源: {self.key_source}\n"))
            self.probe_failed = -1        # 未执行 ≠ 全部通过，同样得非零退出
            self.last_rc = 1
            return
        d = self.data_of(first)
        mounts = d.get("stdout", "")
        efs = [l for l in mounts.splitlines() if " nfs4 " in l or " nfs " in l]
        self._verdict("挂载表里没有 /mnt/shared",
                      bool(mounts) and "/mnt/shared " not in mounts,
                      f"{len(mounts.splitlines())} 条挂载")
        self._verdict("只有一条 EFS 挂载，且挂在 /workspace",
                      len(efs) == 1 and " /workspace " in efs[0],
                      efs[0].split()[0] if efs else "none")

        d = self.data_of(self.invoke("run_command", {
            "command": "grep -E '^Cap(Eff|Bnd):' /proc/self/status"}))
        caps = d.get("stdout", "").strip()
        self._verdict("所有 capability 已丢弃",
                      bool(caps) and all(l.split(":")[1].strip().strip("0") == ""
                                         for l in caps.splitlines()),
                      caps.replace("\n", "  "))

        others = [t for t in ("tenant-a", "tenant-b", "tenant-c") if t != self.tenant_id]
        for victim in others[:2]:
            d = self.data_of(self.invoke("run_command", {
                "command": f"cat /mnt/shared/tenants/{victim}/output/*.txt 2>&1 | head -2"}))
            out = d.get("stdout", "") + d.get("stderr", "")
            self._verdict(f"读不到 {victim} 的数据",
                          "No such file" in out or not out.strip(),
                          out.replace("\n", " ")[:70])

        for label, cmd, expect in (
            ("看不到 EFS 挂载点", "ls /mnt/shared", "No such file"),
            ("看不到 Runtime 源码 /app", "ls /app", "No such file"),
            ("nsenter 进宿主 ns 失败", "nsenter -t 1 -m -- ls /mnt 2>&1", "not permitted"),
            ("二次 unshare 失败", "unshare -m sh -c 'ls /mnt' 2>&1", "not permitted"),
            ("mount --bind 逃逸失败", "mkdir -p /tmp/e && mount --bind / /tmp/e 2>&1", "denied"),
            ("chroot 逃逸失败", "chroot / /bin/sh -c 'ls /mnt' 2>&1", "peration"),
            ("/.oldroot 已移除", "ls /.oldroot 2>&1", "No such file"),
        ):
            d = self.data_of(self.invoke("run_command", {"command": cmd, "timeout": 25}))
            out = d.get("stdout", "") + d.get("stderr", "")
            self._verdict(label, expect.lower() in out.lower(),
                          out.replace("\n", " ")[:70])

        d = self.data_of(self.invoke("run_command", {"command": "env"}))
        env = d.get("stdout", "")
        self._verdict("环境里没有 AWS 凭证 / 签名密钥",
                      not any(m in env for m in ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                                                 "TENANT_SIGNING_KEY",
                                                 "AWS_CONTAINER_CREDENTIALS")),
                      f"{len(env.splitlines())} 个变量")
        if self.probe_failed:
            print(C.red(f"\n  {self.probe_failed} 项未通过 —— 隔离不成立，别忽略。"))
        # 走 -c ':probe' 时退出码取自 last_rc，这里同步一份
        self.last_rc = 1 if self.probe_failed else 0
        print()

    def _verdict(self, name, ok, detail=""):
        if not ok:
            self.probe_failed += 1        # --probe 的退出码要能进 CI 门禁
        print(f"  {C.green('✅') if ok else C.red('❌')} {name:<34} {C.dim(detail)}")

    # ─── REPL ────────────────────────────────────────────────────

    HELP = """
  内置命令（本地处理，不发到 jail）:
    :help              本帮助
    :status            沙箱状态
    :probe             一键隔离探测
    :session           当前 session 与租户
    :su <tenant>       切换租户（新 session）
    :switch-attack [t] 当前 session 内换租户（演示被拒）
    :read <path>       受守卫 API 读
    :write <path> <内容>  受守卫 API 写
    :ls [path]         受守卫 API 列目录
    :py <code>         run_code 执行 python
    :timeout <秒>      设置超时
    :quit              退出

  ⚠ 每条命令 = 一次 InvokeAgentRuntime = 一个全新 jail。
    rootfs（/ /etc /dev 以及 /tmp）每次执行现搭现拆，写进去的东西**下一条命令
    就没了** —— touch 会返回 exit 0，同一条命令里也读得到，但不跨调用存活。
    只有 /workspace 是真实的 EFS 目录，唯一能持久化的地方。
    非 /workspace 的写入会看到一行 ⓘ 提示。

  其余输入都当 shell 命令送进 jail 执行。试试这些：
    ls /                                       jail 里的全部内容
    cat /proc/mounts                           内核挂载表（没有 /mnt/shared）
    cat /mnt/shared/tenants/tenant-b/output/b.txt   跨租户读 → ENOENT
    ls /app                                    Runtime 源码 → 不存在
    cat /etc/passwd                            合成的最小 passwd
    id; grep Cap /proc/self/status             uid 0 但零 capability
"""

    def repl(self):
        print(C.bold("\n  AgentCore 租户 shell") + C.dim("  (:help 查看命令, :probe 一键探测)"))
        # session_id 完整打印：这是要复制去传 --session-id 的值，截断就没用了
        print(C.dim(f"  tenant  = {self.tenant_id}"))
        print(C.dim(f"  session = {self.session_id}"))
        print(C.dim(f"  key     = {self.key_source}"))
        if not self.signing_key:
            print(C.red("  警告: 未提供签名密钥，将发送明文 tenant_id"))
            print(C.red("        正常部署下 Runtime 会拒绝（UNAUTHENTICATED）"))
        print()

        while True:
            try:
                line = input(f"{C.cyan('[' + self.tenant_id + ']')} {self.cwd} $ ")
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if self.dispatch(line.strip()) == "quit":
                break

    def dispatch(self, cmd):
        """
        跑一行输入。REPL 与 -c 共用这一份分发，否则 `-c ':help'` 会被当成
        shell 命令送进 jail（`:help: command not found`）。
        返回 "quit" 表示要退出。
        """
        if not cmd:
            return None

        if cmd in (":quit", ":q", "exit", "quit"):
            return "quit"
        if cmd in (":help", ":h", "help", "?"):
            print(self.HELP)
        elif cmd == ":status":
            self.cmd_status()
        elif cmd == ":probe":
            self.cmd_probe()
        elif cmd == ":session":
            self.cmd_session()
        elif cmd.startswith(":switch-attack"):
            self.cmd_switch_attack(cmd[14:].strip())
        elif cmd.startswith(":su"):
            self.cmd_su(cmd[3:].strip())
        elif cmd.startswith(":read"):
            self.cmd_read(cmd[5:].strip())
        elif cmd.startswith(":write"):
            self.cmd_write(cmd[6:].strip())
        elif cmd.startswith(":ls"):
            self.cmd_ls(cmd[3:].strip())
        elif cmd.startswith(":py"):
            self.cmd_py(cmd[3:].strip())
        elif cmd.startswith(":timeout"):
            try:
                self.timeout = max(1, min(300, int(cmd[8:].strip())))
                print(C.green(f"timeout = {self.timeout}s"))
            except ValueError:
                print("用法: :timeout <秒>")
        elif cmd.startswith(":"):
            print(C.red(f"未知内置命令: {cmd.split()[0]}  (:help)"))
        elif cmd == "cd" or cmd.startswith("cd "):
            self.track_cd(cmd)
        else:
            self.exec_command(cmd)
        return None

    def stop(self):
        try:
            self.client.stop_runtime_session(
                agentRuntimeArn=self.runtime_arn, runtimeSessionId=self.session_id)
        except Exception:
            pass


def main():
    p = argparse.ArgumentParser(
        description="交互式租户 shell，用于验证 AgentCore 多租户隔离",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  ./tools/tenant_shell.py --tenant tenant-a\n"
               "  ./tools/tenant_shell.py --tenant tenant-b -c 'ls /; cat /proc/mounts'\n"
               "  ./tools/tenant_shell.py --tenant tenant-a --probe\n"
               "\n"
               "  # 指定 runtime（二者取一）\n"
               "  ./tools/tenant_shell.py --runtime-id sandboxIsolationDemo-xxxx \\\n"
               "      --account 123456789012 --region us-east-1 --tenant tenant-a\n"
               "  ./tools/tenant_shell.py --runtime-arn "
               "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/xxx\n"
               "\n"
               "  # 复用同一 session：跨两次调用观察 rootfs 是否重建\n"
               "  S=demo-session-$(uuidgen)\n"
               "  ./tools/tenant_shell.py --session-id $S --keep-session "
               "-c 'touch /etc/x; ls /etc/x'\n"
               "  ./tools/tenant_shell.py --session-id $S "
               "-c 'ls /etc/x'   # No such file\n")
    p.add_argument("--tenant", default="tenant-a", help="租户 id (默认 tenant-a)")
    p.add_argument("--runtime-arn", default=os.environ.get("RUNTIME_ARN"),
                   help="Runtime 完整 ARN；给了就忽略 --runtime-id/--account "
                        "(env RUNTIME_ARN)")
    p.add_argument("--runtime-id", default=os.environ.get("RUNTIME_ID",
                   "sandboxIsolationDemo-COIZYqEK2d"),
                   help="Runtime id，与 --account/--region 拼成 ARN (env RUNTIME_ID)")
    p.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"),
                   help="AWS region (env AWS_REGION)")
    p.add_argument("--account", default=os.environ.get("ACCOUNT_ID", "123456789012"),
                   help="AWS 账号 id (env ACCOUNT_ID)")
    p.add_argument("--secret-id",
                   default=os.environ.get("TENANT_SIGNING_KEY_SECRET_ID",
                                          "agentcore/tenant-signing-key"),
                   help="未设 TENANT_SIGNING_KEY 时，从这个 Secrets Manager "
                        "secret 取密钥（默认 agentcore/tenant-signing-key）")
    p.add_argument("--session-id", default=os.environ.get("RUNTIME_SESSION_ID"),
                   help="复用已有 session（不足 33 字符会自动补齐，AgentCore 的下限）"
                        "。同一 id 落到同一容器，可观察 session 绑定与"
                        "「rootfs 每次执行重建」(env RUNTIME_SESSION_ID)")
    p.add_argument("--timeout", type=int, default=60, help="命令超时（秒）")
    p.add_argument("-c", "--command", help="执行单条命令后退出")
    p.add_argument("--probe", action="store_true", help="跑隔离探测后退出")
    p.add_argument("--no-sign", action="store_true",
                   help="发送明文 tenant_id（仅 insecure_payload 模式可用；"
                        "正常部署下会被拒绝，这本身也是一次验证）")
    p.add_argument("--keep-session", action="store_true",
                   help="退出时不停止 session")
    args = p.parse_args()

    key, key_source = None, "unsigned (--no-sign)"
    if not args.no_sign:
        key, key_source = load_signing_key(args.region, args.secret_id)
        if not key:
            sys.exit(KEY_HELP)
        if len(key) < 32:
            sys.exit(f"签名密钥太短（{len(key)} 字节，需 >= 32）—— 来源: {key_source}")

    arn = args.runtime_arn or (f"arn:aws:bedrock-agentcore:{args.region}:{args.account}"
                               f":runtime/{args.runtime_id}")
    sh = TenantShell(arn, args.region, key, args.tenant,
                     session_id=args.session_id, timeout=args.timeout,
                     key_source=key_source)

    # 退出码要能被脚本和 CI 依赖：--probe 有未通过项 → 非零；
    # -c 透传 jail 内命令的退出码（认证/传输失败也算失败）。
    rc = 0
    try:
        if args.probe:
            sh.cmd_probe()
            rc = 1 if sh.probe_failed else 0
        elif args.command:
            # session id 打到 stderr：-c 的 stdout 经常被管道消费，不能污染。
            # 出问题时要靠这个 id 去 CloudWatch 对日志，所以不能不打。
            print(f"[session] {sh.session_id}", file=sys.stderr)
            sh.dispatch(args.command)      # 内置命令（:probe / :read …）也能用
            rc = sh.last_rc
        else:
            sh.repl()
    finally:
        if not args.keep_session:
            sh.stop()
    sys.exit(rc)


if __name__ == "__main__":
    main()
