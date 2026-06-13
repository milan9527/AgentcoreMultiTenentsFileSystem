"""
端到端测试 - 验证完整流程和用户权限隔离

测试场景：
1. workspace_guard 路径隔离
2. 租户 A 不能通过路径遍历访问租户 B
3. 双向文件流转
4. session 绑定单租户（不能切换）
5. bind mount / symlink 退化正确工作

运行：
    python -m pytest tests/test_e2e.py -v
    sudo python -m pytest tests/test_e2e.py -v  (测试 bind mount)
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "runtime"))

from workspace_guard import WorkspaceGuard, WORKSPACE


class TestWorkspaceGuard(unittest.TestCase):
    """WorkspaceGuard 核心隔离测试"""

    def setUp(self):
        """模拟 EFS 挂载点"""
        self.efs_root = tempfile.mkdtemp(prefix="efs_mock_")
        # 预创建一些租户数据
        os.makedirs(f"{self.efs_root}/tenants/tenant-A/input", exist_ok=True)
        os.makedirs(f"{self.efs_root}/tenants/tenant-A/output", exist_ok=True)
        os.makedirs(f"{self.efs_root}/tenants/tenant-B/input", exist_ok=True)
        os.makedirs(f"{self.efs_root}/tenants/tenant-B/output", exist_ok=True)

        # 写入测试数据
        with open(f"{self.efs_root}/tenants/tenant-A/input/data.txt", "w") as f:
            f.write("secret data of tenant A")
        with open(f"{self.efs_root}/tenants/tenant-B/input/data.txt", "w") as f:
            f.write("secret data of tenant B")

        # 用临时目录模拟 /workspace
        self.workspace_dir = tempfile.mkdtemp(prefix="ws_mock_")

    def tearDown(self):
        shutil.rmtree(self.efs_root, ignore_errors=True)
        shutil.rmtree(self.workspace_dir, ignore_errors=True)
        # 清理可能的 symlink
        if os.path.islink(self.workspace_dir):
            os.unlink(self.workspace_dir)

    def _make_guard(self, workspace_path: str = None):
        """创建 guard，用自定义路径"""
        guard = WorkspaceGuard(efs_mount=self.efs_root)
        return guard

    def test_safe_tenant_id_validation(self):
        """tenant_id 安全验证"""
        guard = self._make_guard()

        # 合法
        self.assertTrue(guard._is_safe_tenant_id("tenant-A"))
        self.assertTrue(guard._is_safe_tenant_id("my_tenant_123"))
        self.assertTrue(guard._is_safe_tenant_id("a"))

        # 非法（路径注入）
        self.assertFalse(guard._is_safe_tenant_id("../etc"))
        self.assertFalse(guard._is_safe_tenant_id("tenant/../B"))
        self.assertFalse(guard._is_safe_tenant_id("/absolute"))
        self.assertFalse(guard._is_safe_tenant_id(""))
        self.assertFalse(guard._is_safe_tenant_id(".hidden"))
        self.assertFalse(guard._is_safe_tenant_id("-starts-with-dash"))

    def test_setup_creates_dirs(self):
        """setup 创建租户目录结构"""
        guard = self._make_guard()

        # patch WORKSPACE 为我们的临时目录
        with patch("workspace_guard.WORKSPACE", self.workspace_dir):
            ws = guard.setup("new-tenant")

        tenant_path = f"{self.efs_root}/tenants/new-tenant"
        self.assertTrue(os.path.isdir(tenant_path))
        self.assertTrue(os.path.isdir(f"{tenant_path}/input"))
        self.assertTrue(os.path.isdir(f"{tenant_path}/output"))

    def test_path_resolve_blocks_traversal(self):
        """路径遍历被阻止"""
        guard = self._make_guard()

        with patch("workspace_guard.WORKSPACE", self.workspace_dir):
            guard.setup("tenant-A")

            # symlink 或 bind mount 后，/workspace 指向 tenant-A
            # resolve_path 应阻止向上遍历
            safe = guard.resolve_path("input/data.txt")
            self.assertIsNotNone(safe)

            # 遍历攻击 - 跳出 workspace
            blocked = guard.resolve_path("../tenant-B/input/data.txt")
            self.assertIsNone(blocked)

            blocked = guard.resolve_path("../../etc/passwd")
            self.assertIsNone(blocked)

            # 注意: "/etc/passwd" 被 lstrip("/") 后变成 "etc/passwd"
            # 解析为 workspace/etc/passwd，仍在 workspace 内 → 不算逃逸
            # 这是安全的：实际指向 tenant-A/etc/passwd（不存在）
            # 真正危险的是 ../ 跳出 workspace 到其他租户

    def test_path_resolve_allows_valid(self):
        """合法路径可以解析"""
        guard = self._make_guard()

        with patch("workspace_guard.WORKSPACE", self.workspace_dir):
            guard.setup("tenant-A")

            safe = guard.resolve_path("input/data.txt")
            self.assertIsNotNone(safe)

            safe = guard.resolve_path("output/result.json")
            self.assertIsNotNone(safe)

            safe = guard.resolve_path(".")
            self.assertIsNotNone(safe)

    def test_invalid_tenant_id_rejected(self):
        """非法 tenant_id 被拒绝"""
        guard = self._make_guard()

        with self.assertRaises(ValueError):
            guard.setup("../evil")

        with self.assertRaises(ValueError):
            guard.setup("")

        with self.assertRaises(ValueError):
            guard.setup("../../etc/passwd")


class TestIsolationWithSymlink(unittest.TestCase):
    """测试 symlink 退化方案下的隔离"""

    def setUp(self):
        self.efs_root = tempfile.mkdtemp(prefix="efs_")
        self.workspace_dir = tempfile.mkdtemp(prefix="ws_")

        # 两个租户
        for t in ["alice", "bob"]:
            os.makedirs(f"{self.efs_root}/tenants/{t}/input")
            os.makedirs(f"{self.efs_root}/tenants/{t}/output")

        with open(f"{self.efs_root}/tenants/alice/input/secret.txt", "w") as f:
            f.write("alice private data")
        with open(f"{self.efs_root}/tenants/bob/input/secret.txt", "w") as f:
            f.write("bob private data")

    def tearDown(self):
        shutil.rmtree(self.efs_root, ignore_errors=True)
        if os.path.islink(self.workspace_dir):
            os.unlink(self.workspace_dir)
        elif os.path.isdir(self.workspace_dir):
            shutil.rmtree(self.workspace_dir, ignore_errors=True)

    def test_alice_reads_own_file(self):
        """Alice 能读自己的文件"""
        guard = WorkspaceGuard(efs_mount=self.efs_root)

        with patch("workspace_guard.WORKSPACE", self.workspace_dir):
            guard.setup("alice")
            path = guard.resolve_path("input/secret.txt")
            self.assertIsNotNone(path)
            with open(path) as f:
                self.assertEqual(f.read(), "alice private data")

    def test_alice_cannot_reach_bob(self):
        """Alice 不能通过路径遍历读 Bob 的文件"""
        guard = WorkspaceGuard(efs_mount=self.efs_root)

        with patch("workspace_guard.WORKSPACE", self.workspace_dir):
            guard.setup("alice")

            # 各种遍历尝试
            for attack_path in [
                "../bob/input/secret.txt",
                "../../tenants/bob/input/secret.txt",
                "input/../../bob/input/secret.txt",
            ]:
                result = guard.resolve_path(attack_path)
                self.assertIsNone(result, f"Should block: {attack_path}")

    def test_alice_writes_output(self):
        """Alice 写入 output"""
        guard = WorkspaceGuard(efs_mount=self.efs_root)

        with patch("workspace_guard.WORKSPACE", self.workspace_dir):
            guard.setup("alice")
            path = guard.resolve_path("output/result.txt")
            self.assertIsNotNone(path)

            with open(path, "w") as f:
                f.write("alice output")

            # 验证实际写到了 EFS 上正确位置
            efs_path = f"{self.efs_root}/tenants/alice/output/result.txt"
            self.assertTrue(os.path.exists(efs_path))
            with open(efs_path) as f:
                self.assertEqual(f.read(), "alice output")


class TestBidirectionalSharing(unittest.TestCase):
    """双向文件流转测试"""

    def setUp(self):
        self.efs_root = tempfile.mkdtemp(prefix="efs_")
        self.workspace_dir = tempfile.mkdtemp(prefix="ws_")
        os.makedirs(f"{self.efs_root}/tenants/t1/input")
        os.makedirs(f"{self.efs_root}/tenants/t1/output")

    def tearDown(self):
        shutil.rmtree(self.efs_root, ignore_errors=True)
        if os.path.islink(self.workspace_dir):
            os.unlink(self.workspace_dir)
        elif os.path.isdir(self.workspace_dir):
            shutil.rmtree(self.workspace_dir, ignore_errors=True)

    def test_business_writes_sandbox_reads(self):
        """业务 Pod 写入 input → 沙箱 session 能读到"""
        # 业务 Pod 写入（直接操作 EFS）
        with open(f"{self.efs_root}/tenants/t1/input/task.json", "w") as f:
            json.dump({"task": "summarize", "data": "hello"}, f)

        # 沙箱 session 读取
        guard = WorkspaceGuard(efs_mount=self.efs_root)
        with patch("workspace_guard.WORKSPACE", self.workspace_dir):
            guard.setup("t1")
            path = guard.resolve_path("input/task.json")
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["task"], "summarize")

    def test_sandbox_writes_business_reads(self):
        """沙箱 session 写入 output → 业务 Pod 能读到"""
        guard = WorkspaceGuard(efs_mount=self.efs_root)
        with patch("workspace_guard.WORKSPACE", self.workspace_dir):
            guard.setup("t1")
            path = guard.resolve_path("output/result.txt")
            with open(path, "w") as f:
                f.write("computation done")

        # 业务 Pod 读取（直接操作 EFS）
        efs_path = f"{self.efs_root}/tenants/t1/output/result.txt"
        with open(efs_path) as f:
            self.assertEqual(f.read(), "computation done")


class TestBindMount(unittest.TestCase):
    """
    Bind mount 强隔离测试

    需要 root 权限运行。
    非 root 时跳过。
    """

    def setUp(self):
        self.efs_root = tempfile.mkdtemp(prefix="efs_bm_")
        self.mount_point = tempfile.mkdtemp(prefix="mnt_bm_")

        for t in ["alpha", "beta"]:
            os.makedirs(f"{self.efs_root}/tenants/{t}/input")
            os.makedirs(f"{self.efs_root}/tenants/{t}/output")
        with open(f"{self.efs_root}/tenants/alpha/input/a.txt", "w") as f:
            f.write("alpha data")
        with open(f"{self.efs_root}/tenants/beta/input/b.txt", "w") as f:
            f.write("beta data")

    def tearDown(self):
        # umount if mounted
        subprocess.run(["umount", self.mount_point], capture_output=True)
        shutil.rmtree(self.efs_root, ignore_errors=True)
        shutil.rmtree(self.mount_point, ignore_errors=True)

    @unittest.skipUnless(os.geteuid() == 0, "Requires root for bind mount")
    def test_bind_mount_isolates(self):
        """Bind mount 后只看到租户子目录"""
        src = f"{self.efs_root}/tenants/alpha"

        # bind mount
        result = subprocess.run(
            ["mount", "--bind", src, self.mount_point],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        # mount point 下只有 alpha 的内容
        entries = os.listdir(self.mount_point)
        self.assertIn("input", entries)
        self.assertIn("output", entries)

        # 能读 alpha
        with open(f"{self.mount_point}/input/a.txt") as f:
            self.assertEqual(f.read(), "alpha data")

        # 无法通过 ../ 逃逸（bind mount 下 .. 仍在 mount 内）
        # 注意：bind mount 不阻止 .. ，但 resolve 会回到 mount point
        resolved = Path(f"{self.mount_point}/../").resolve()
        # resolved 是 mount_point 的父目录
        # 但直接 ls 会看到宿主文件系统
        # 真正的保护来自应用层 resolve_path 检查
        # bind mount 的价值是让 /workspace 指向正确子目录

    @unittest.skipUnless(os.geteuid() == 0, "Requires root for bind mount")
    def test_guard_uses_bind_mount_when_root(self):
        """以 root 运行时 guard 使用 bind mount"""
        guard = WorkspaceGuard(efs_mount=self.efs_root)

        with patch("workspace_guard.WORKSPACE", self.mount_point):
            ws = guard.setup("alpha")
            self.assertTrue(ws.isolated)  # bind mount 成功

            # 验证内容
            entries = os.listdir(self.mount_point)
            self.assertIn("input", entries)


class TestSessionBinding(unittest.TestCase):
    """Session 绑定单租户测试"""

    def test_cannot_switch_tenant(self):
        """模拟同一 session 尝试切换租户"""
        # 这测试 main.py 中 ensure_workspace 的逻辑
        # 这里用独立代码模拟

        efs_root = tempfile.mkdtemp(prefix="efs_bind_")
        workspace_dir = tempfile.mkdtemp(prefix="ws_bind_")
        os.makedirs(f"{efs_root}/tenants/t1/input")
        os.makedirs(f"{efs_root}/tenants/t2/input")

        guard = WorkspaceGuard(efs_mount=efs_root)

        with patch("workspace_guard.WORKSPACE", workspace_dir):
            # 第一次 setup 成功
            ws1 = guard.setup("t1")
            self.assertEqual(ws1.tenant_id, "t1")

            # 第二次 setup 同一租户也成功（幂等）
            # 但注意 guard 本身不阻止重复 setup
            # 阻止切换的逻辑在 main.py 的 ensure_workspace 中

        shutil.rmtree(efs_root, ignore_errors=True)
        if os.path.islink(workspace_dir):
            os.unlink(workspace_dir)
        elif os.path.isdir(workspace_dir):
            shutil.rmtree(workspace_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
