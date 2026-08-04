"""
隔离性测试 - 对抗性验证

覆盖旧版被绕过的所有攻击面：
- run_command / run_code 用绝对路径读写其他租户 (旧版可成功)
- run_command / run_code 读宿主根目录 (旧版可成功)
- 环境变量中的 AWS 凭证泄漏给租户代码 (旧版可成功)
- tenant_id 自证 (旧版无认证)
- 受守卫 API 的路径遍历、symlink 逃逸、绝对路径改写
- symlink 退化路径摧毁其他租户数据 (旧版可成功)

jail 相关测试需要 root（mount namespace 需要 CAP_SYS_ADMIN），非 root 时跳过。
路径守卫与身份认证测试不需要 root。

运行：
    python3 -m unittest discover -s tests -v
    sudo python3 -m unittest discover -s tests -v   # 含 jail 测试
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest

RUNTIME_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runtime")
sys.path.insert(0, os.path.abspath(RUNTIME_DIR))

# stub SDK，使 main.py 可在无 bedrock_agentcore 的环境下导入
if "bedrock_agentcore" not in sys.modules:
    try:
        import bedrock_agentcore  # noqa: F401
    except ImportError:
        stub = types.ModuleType("bedrock_agentcore")

        class _App:
            def entrypoint(self, fn):
                return fn

            def run(self):
                pass

        stub.BedrockAgentCoreApp = _App
        sys.modules["bedrock_agentcore"] = stub

import tenant_identity
from tenant_identity import (
    SessionBinding,
    TenantAuthError,
    TenantResolver,
    is_valid_tenant_id,
    sign_tenant_token,
    verify_tenant_token,
)
from workspace_guard import PathNotAllowed, WorkspaceGuard

JAIL_PY = os.path.abspath(os.path.join(RUNTIME_DIR, "jail.py"))
IS_ROOT = os.geteuid() == 0
SECRET = "VICTIM-TOP-SECRET-DO-NOT-LEAK"
KEY = b"k" * 32


class _EfsFixture(unittest.TestCase):
    """构造模拟 EFS：两个租户，victim 目录下有机密文件"""

    def setUp(self):
        self.efs = tempfile.mkdtemp(prefix="efs_test_")
        for t in ("victim", "attacker"):
            os.makedirs(f"{self.efs}/tenants/{t}/input", exist_ok=True)
            os.makedirs(f"{self.efs}/tenants/{t}/output", exist_ok=True)
        with open(f"{self.efs}/tenants/victim/input/secret.txt", "w") as f:
            f.write(SECRET)
        self.guard = WorkspaceGuard(efs_mount=self.efs)
        self.attacker = self.guard.setup("attacker")
        self.victim = self.guard.setup("victim")

    def tearDown(self):
        shutil.rmtree(self.efs, ignore_errors=True)

    def victim_secret_abs(self):
        return f"{self.efs}/tenants/victim/input/secret.txt"


# ─── 路径守卫 (不需要 root) ────────────────────────────────────────

class TestPathGuard(_EfsFixture):

    def test_own_files_accessible(self):
        with open(f"{self.efs}/tenants/attacker/input/mine.txt", "w") as f:
            f.write("mine")
        safe = self.guard.resolve_path(self.attacker, "input/mine.txt")
        with open(safe) as f:
            self.assertEqual(f.read(), "mine")

    def test_parent_traversal_blocked(self):
        for path in ("../victim/input/secret.txt",
                     "../../tenants/victim/input/secret.txt",
                     "input/../../victim/input/secret.txt",
                     "..",
                     "input/../.."):
            with self.assertRaises(PathNotAllowed, msg=f"should block {path}"):
                self.guard.resolve_path(self.attacker, path)

    def test_absolute_path_rejected_not_rewritten(self):
        """旧版把 /etc/passwd 静默改写为 workspace/etc/passwd 并返回成功"""
        for path in ("/etc/passwd", "/", self.victim_secret_abs()):
            with self.assertRaises(PathNotAllowed, msg=f"should reject {path}"):
                self.guard.resolve_path(self.attacker, path)

    def test_symlink_escape_blocked(self):
        """租户在自己目录里种 symlink 指向其他租户"""
        link = f"{self.efs}/tenants/attacker/link.txt"
        os.symlink(self.victim_secret_abs(), link)
        with self.assertRaises(PathNotAllowed):
            self.guard.resolve_path(self.attacker, "link.txt")

    def test_symlink_dir_escape_blocked(self):
        """symlink 指向目录，再穿透访问"""
        os.symlink(f"{self.efs}/tenants/victim", f"{self.efs}/tenants/attacker/vlink")
        with self.assertRaises(PathNotAllowed):
            self.guard.resolve_path(self.attacker, "vlink/input/secret.txt")

    def test_symlink_escape_blocked_on_write(self):
        """写路径的 symlink 逃逸：父目录是指向外部的 symlink"""
        os.symlink(f"{self.efs}/tenants/victim/output",
                   f"{self.efs}/tenants/attacker/vout")
        with self.assertRaises(PathNotAllowed):
            self.guard.resolve_path(self.attacker, "vout/pwned.txt", for_write=True)

    def test_nul_byte_rejected(self):
        with self.assertRaises(PathNotAllowed):
            self.guard.resolve_path(self.attacker, "input/x\x00.txt")

    def test_empty_path_rejected(self):
        with self.assertRaises(PathNotAllowed):
            self.guard.resolve_path(self.attacker, "")

    def test_write_to_new_file_allowed(self):
        safe = self.guard.resolve_path(self.attacker, "output/new.txt", for_write=True)
        self.assertTrue(safe.startswith(os.path.realpath(self.attacker.efs_tenant_path)))

    def test_invalid_tenant_id_rejected(self):
        for bad in ("../evil", "", "tenant/../B", "/absolute", ".hidden",
                    "-dash", "a" * 65, None, 42):
            self.assertFalse(is_valid_tenant_id(bad), f"should reject {bad!r}")
        with self.assertRaises(ValueError):
            self.guard.setup("../evil")

    def test_no_destructive_fallback(self):
        """
        旧版 _setup_symlink 会 rmtree(WORKSPACE)，若上一个租户的 bind mount
        还挂在那里，会穿过挂载点删除该租户在 EFS 上的真实数据。
        该退化路径必须已整体移除。
        """
        for attr in ("_setup_symlink", "_setup_isolation", "_try_bind_mount"):
            self.assertFalse(hasattr(self.guard, attr),
                             f"destructive fallback {attr} still present")

        # 解析 AST 而非匹配文本，避免误伤 docstring 里对旧行为的说明
        import ast
        src = os.path.abspath(os.path.join(RUNTIME_DIR, "workspace_guard.py"))
        with open(src) as f:
            tree = ast.parse(f.read())
        called = {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        for destructive in ("rmtree", "unlink", "remove", "symlink", "mount"):
            self.assertNotIn(destructive, called,
                             f"{destructive}() must not be called in workspace_guard")

    def test_setup_is_idempotent_and_preserves_data(self):
        with open(f"{self.efs}/tenants/attacker/input/keep.txt", "w") as f:
            f.write("keep me")
        self.guard.setup("attacker")
        self.guard.setup("attacker")
        with open(f"{self.efs}/tenants/attacker/input/keep.txt") as f:
            self.assertEqual(f.read(), "keep me")


# ─── 租户身份 (不需要 root) ────────────────────────────────────────

class TestTenantIdentity(unittest.TestCase):

    def test_valid_token_roundtrip(self):
        token = sign_tenant_token("tenant-a", KEY)
        self.assertEqual(verify_tenant_token(token, KEY), "tenant-a")

    def test_forged_signature_rejected(self):
        token = sign_tenant_token("tenant-a", KEY)
        tid, exp, _sig = token.split(".")
        forged = f"{tid}.{exp}.{'A' * 43}"
        with self.assertRaises(TenantAuthError):
            verify_tenant_token(forged, KEY)

    def test_tenant_swap_rejected(self):
        """攻击者拿自己的合法 token 改成别人的租户名"""
        token = sign_tenant_token("attacker", KEY)
        _tid, exp, sig = token.split(".")
        with self.assertRaises(TenantAuthError):
            verify_tenant_token(f"victim.{exp}.{sig}", KEY)

    def test_wrong_key_rejected(self):
        token = sign_tenant_token("tenant-a", KEY)
        with self.assertRaises(TenantAuthError):
            verify_tenant_token(token, b"x" * 32)

    def test_expired_token_rejected(self):
        token = sign_tenant_token("tenant-a", KEY, ttl_seconds=-3600)
        with self.assertRaises(TenantAuthError):
            verify_tenant_token(token, KEY)

    def test_malformed_tokens_rejected(self):
        for bad in ("", "a.b", "a.b.c.d", "..", "tenant.notanint.sig",
                    "../evil.999999999999.sig", None, 42):
            with self.assertRaises(TenantAuthError):
                verify_tenant_token(bad, KEY)

    def test_resolver_hmac_requires_token(self):
        r = TenantResolver(mode="hmac")
        os.environ["TENANT_SIGNING_KEY"] = KEY.decode()
        try:
            with self.assertRaises(TenantAuthError):
                r.resolve({"tenant_id": "victim"}, None)  # 自证的 tenant_id 无效
            token = sign_tenant_token("attacker", KEY)
            self.assertEqual(r.resolve({"tenant_token": token}, None), "attacker")
        finally:
            os.environ.pop("TENANT_SIGNING_KEY", None)

    def test_resolver_ignores_payload_tenant_id_in_hmac_mode(self):
        """payload 里的 tenant_id 在 hmac 模式下不得影响解析结果"""
        r = TenantResolver(mode="hmac")
        os.environ["TENANT_SIGNING_KEY"] = KEY.decode()
        try:
            token = sign_tenant_token("attacker", KEY)
            got = r.resolve({"tenant_token": token, "tenant_id": "victim"}, None)
            self.assertEqual(got, "attacker")
        finally:
            os.environ.pop("TENANT_SIGNING_KEY", None)

    def test_short_key_rejected(self):
        r = TenantResolver(mode="hmac")
        os.environ["TENANT_SIGNING_KEY"] = "tooshort"
        try:
            with self.assertRaises(TenantAuthError):
                r.resolve({"tenant_token": "a.1.b"}, None)
        finally:
            os.environ.pop("TENANT_SIGNING_KEY", None)

    def test_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            TenantResolver(mode="whatever")


class TestSessionBinding(unittest.TestCase):

    def test_cannot_switch_tenant_within_session(self):
        b = SessionBinding()
        b.bind("sess-1", "tenant-a", lambda t: f"ws-{t}")
        with self.assertRaises(PermissionError):
            b.bind("sess-1", "tenant-b", lambda t: f"ws-{t}")

    def test_same_tenant_reuses_workspace(self):
        b = SessionBinding()
        calls = []

        def setup(t):
            calls.append(t)
            return f"ws-{t}"

        w1 = b.bind("sess-1", "tenant-a", setup)
        w2 = b.bind("sess-1", "tenant-a", setup)
        self.assertIs(w1, w2)
        self.assertEqual(calls, ["tenant-a"], "setup should run once per session")

    def test_distinct_sessions_can_hold_distinct_tenants(self):
        """旧版模块级全局会让复用容器的第二个租户撞上 PermissionError"""
        b = SessionBinding()
        self.assertEqual(b.bind("s1", "tenant-a", lambda t: t), "tenant-a")
        self.assertEqual(b.bind("s2", "tenant-b", lambda t: t), "tenant-b")


# ─── jail 隔离 (需要 root) ─────────────────────────────────────────

@unittest.skipUnless(IS_ROOT, "mount namespace jail requires root (CAP_SYS_ADMIN)")
class TestJailIsolation(_EfsFixture):
    """
    这些测试针对旧版可以成功的攻击。每一项在修复前都会通过（= 越权成功），
    修复后必须失败（= 被阻止）。
    """

    def _jail(self, command, tenant="attacker", timeout=30, env=None):
        root = f"{self.efs}/tenants/{tenant}"
        proc = subprocess.run(
            [sys.executable, JAIL_PY, "--tenant-root", root,
             "--cpu-seconds", str(timeout), "--", "/bin/bash", "-c", command],
            capture_output=True, text=True, timeout=timeout + 20,
            env=env if env is not None else {"PATH": os.environ.get("PATH", "")},
        )
        return proc

    # --- 核心：旧版的绝对路径越权 ---

    def test_cannot_read_other_tenant_by_absolute_path(self):
        p = self._jail(f"cat {self.victim_secret_abs()}")
        self.assertNotIn(SECRET, p.stdout + p.stderr)
        self.assertNotEqual(p.returncode, 0)

    def test_cannot_write_other_tenant_by_absolute_path(self):
        target = f"{self.efs}/tenants/victim/output/pwned.txt"
        self._jail(f"echo PWNED > {target}")
        self.assertFalse(os.path.exists(target),
                         "attacker wrote into victim's directory")

    def test_cannot_list_tenants_root(self):
        p = self._jail(f"ls {self.efs}/tenants/")
        self.assertNotIn("victim", p.stdout)

    def test_cannot_read_efs_mount(self):
        p = self._jail("ls /mnt/shared 2>&1; ls /mnt 2>&1")
        self.assertNotIn("tenants", p.stdout)

    def test_cannot_reach_relative_parent(self):
        p = self._jail("cat ../victim/input/secret.txt 2>&1")
        self.assertNotIn(SECRET, p.stdout)

    def test_cannot_read_host_rootfs(self):
        p = self._jail("cat /etc/shadow 2>&1; cat /proc/1/environ 2>&1")
        self.assertNotIn("root:", p.stdout)

    def test_etc_passwd_does_not_leak_host_accounts(self):
        """jail 内 /etc/passwd 为合成最小版本，不暴露宿主用户名"""
        p = self._jail("cat /etc/passwd")
        self.assertIn("root", p.stdout)
        self.assertEqual(len(p.stdout.strip().splitlines()), 1,
                         "host accounts leaked via /etc/passwd")
        # 解释器仍需能解析当前 uid
        p2 = self._jail("python3 -c 'import pwd,os; print(pwd.getpwuid(os.getuid()).pw_name)'")
        self.assertIn("root", p2.stdout)

    def test_cannot_read_runtime_source(self):
        """租户不得读到 Runtime 自身代码（含签名逻辑）"""
        p = self._jail("ls /app 2>&1; cat /app/tenant_identity.py 2>&1")
        self.assertNotIn("sign_tenant_token", p.stdout)

    def test_root_listing_has_no_host_dirs(self):
        p = self._jail("ls /")
        listing = set(p.stdout.split())
        for leaked in ("mnt", "app", "home", "root", "var", "srv"):
            self.assertNotIn(leaked, listing, f"/{leaked} visible inside jail")
        self.assertIn("workspace", listing)

    # --- 环境变量泄漏 ---

    def test_no_credential_leak_to_tenant_code(self):
        """旧版 env={**os.environ} 把 AWS 凭证透传给租户代码"""
        env = {
            "PATH": os.environ.get("PATH", ""),
            "AWS_SECRET_ACCESS_KEY": "SHOULD-NOT-LEAK-SECRET",
            "AWS_SESSION_TOKEN": "SHOULD-NOT-LEAK-TOKEN",
            "TENANT_SIGNING_KEY": "SHOULD-NOT-LEAK-KEY",
        }
        p = self._jail("env", env=env)
        for marker in ("SHOULD-NOT-LEAK-SECRET", "SHOULD-NOT-LEAK-TOKEN",
                       "SHOULD-NOT-LEAK-KEY"):
            self.assertNotIn(marker, p.stdout)

    # --- 逃逸手法 ---

    def test_cannot_mount_to_escape(self):
        p = self._jail(f"mkdir -p /tmp/esc && mount --bind / /tmp/esc 2>&1; "
                       f"cat {self.victim_secret_abs()} 2>&1")
        self.assertNotIn(SECRET, p.stdout)

    def test_capabilities_fully_dropped(self):
        p = self._jail("grep -E '^Cap(Eff|Prm|Bnd):' /proc/self/status")
        for line in p.stdout.strip().splitlines():
            self.assertRegex(line, r":\s*0+$", f"capability not dropped: {line}")

    def test_no_new_privs_set(self):
        p = self._jail("grep NoNewPrivs /proc/self/status")
        self.assertIn("1", p.stdout)

    def test_cannot_see_host_processes(self):
        p = self._jail("ls /proc | grep -cE '^[0-9]+$'")
        try:
            count = int(p.stdout.strip())
        except ValueError:
            self.skipTest("no /proc in jail")
        self.assertLess(count, 10, "host processes visible in jail")

    def test_symlink_into_jail_does_not_escape(self):
        """租户预先在自己目录里种 symlink，jail 内也不该穿透"""
        os.symlink(self.victim_secret_abs(),
                   f"{self.efs}/tenants/attacker/link.txt")
        p = self._jail("cat /workspace/link.txt 2>&1")
        self.assertNotIn(SECRET, p.stdout)

    def test_python_cannot_escape(self):
        code = (f"import os\n"
                f"try: print(open({self.victim_secret_abs()!r}).read())\n"
                f"except Exception as e: print('blocked', type(e).__name__)\n"
                f"print(sorted(os.listdir('/')))\n")
        root = f"{self.efs}/tenants/attacker"
        proc = subprocess.run(
            [sys.executable, JAIL_PY, "--tenant-root", root, "--",
             "/usr/bin/env", "python3", "-"],
            input=code, capture_output=True, text=True, timeout=60,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertNotIn(SECRET, proc.stdout)
        self.assertNotIn("'mnt'", proc.stdout)

    # --- 正常功能不受影响 ---

    def test_own_workspace_readable_and_writable(self):
        p = self._jail("echo hello > /workspace/output/mine.txt && "
                       "cat /workspace/output/mine.txt && ls /workspace")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("hello", p.stdout)
        self.assertIn("input", p.stdout)

    def test_writes_persist_to_efs(self):
        self._jail("echo persisted > /workspace/output/r.txt")
        real = f"{self.efs}/tenants/attacker/output/r.txt"
        self.assertTrue(os.path.exists(real))
        with open(real) as f:
            self.assertEqual(f.read().strip(), "persisted")

    def test_business_pod_input_visible_in_jail(self):
        """业务 Pod 直接写 EFS → jail 内可读（双向流转仍然成立）"""
        with open(f"{self.efs}/tenants/attacker/input/task.json", "w") as f:
            f.write('{"task": "go"}')
        p = self._jail("cat /workspace/input/task.json")
        self.assertIn('"task": "go"', p.stdout)

    def test_tmp_is_writable_and_private(self):
        p = self._jail("echo t > /tmp/x && cat /tmp/x")
        self.assertIn("t", p.stdout)
        self.assertFalse(os.path.exists("/tmp/x") and
                         open("/tmp/x").read().strip() == "t",
                         "jail /tmp leaked to host")

    def test_interpreters_available(self):
        p = self._jail("python3 -c 'print(1+1)' && bash -c 'echo ok'")
        self.assertIn("2", p.stdout)
        self.assertIn("ok", p.stdout)

    def test_missing_tenant_root_fails_closed(self):
        proc = subprocess.run(
            [sys.executable, JAIL_PY, "--tenant-root",
             f"{self.efs}/tenants/does-not-exist", "--", "/bin/bash", "-c", "echo ran"],
            capture_output=True, text=True, timeout=30,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(proc.returncode, 126)
        self.assertNotIn("ran", proc.stdout)


@unittest.skipUnless(IS_ROOT, "requires root")
class TestJailCrossTenant(_EfsFixture):
    """两个租户各自 jail，互不可见"""

    def _run(self, tenant, command):
        return subprocess.run(
            [sys.executable, JAIL_PY, "--tenant-root",
             f"{self.efs}/tenants/{tenant}", "--", "/bin/bash", "-c", command],
            capture_output=True, text=True, timeout=60,
            env={"PATH": os.environ.get("PATH", "")},
        )

    def test_each_tenant_sees_only_own_data(self):
        self._run("attacker", "echo A-DATA > /workspace/output/a.txt")
        self._run("victim", "echo B-DATA > /workspace/output/b.txt")

        pa = self._run("attacker", "cat /workspace/output/*.txt")
        self.assertIn("A-DATA", pa.stdout)
        self.assertNotIn("B-DATA", pa.stdout)

        pb = self._run("victim", "cat /workspace/output/*.txt")
        self.assertIn("B-DATA", pb.stdout)
        self.assertNotIn("A-DATA", pb.stdout)

    def test_jail_teardown_leaves_host_intact(self):
        """jail 退出后宿主视图不受影响（挂载未泄漏到宿主 namespace）"""
        before = sorted(os.listdir(f"{self.efs}/tenants"))
        self._run("attacker", "true")
        self.assertEqual(sorted(os.listdir(f"{self.efs}/tenants")), before)
        self.assertTrue(os.path.exists(self.victim_secret_abs()))


if __name__ == "__main__":
    unittest.main()
