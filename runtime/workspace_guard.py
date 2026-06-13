"""
WorkspaceGuard - 租户目录隔离

在 AgentCore Runtime 的 /invocation 入口中：
1. 根据 payload 中的 tenant_id 确定租户子目录
2. 通过 bind mount 将租户子目录映射到 /workspace
3. 后续所有操作限制在 /workspace 内

隔离原理：
- AgentCore 每个 session 是独立 microVM → session 间天然隔离
- 本模块解决的是：限制 session 内可见的 EFS 数据范围

注意：
- AgentCore microVM 内容器通常以 root 运行
- bind mount 需要 root 权限（或 unshare --mount）
- 如果 bind mount 不可用，退化为应用层路径限制
"""

import os
import subprocess
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# AgentCore 挂载 EFS 的路径 (通过 filesystemConfigurations 配置)
EFS_MOUNT = "/mnt/shared"
TENANTS_DIR = f"{EFS_MOUNT}/tenants"

# session 内暴露给 agent 的工作目录
WORKSPACE = "/workspace"


@dataclass
class TenantWorkspace:
    """租户工作空间"""
    tenant_id: str
    efs_tenant_path: str   # EFS 上的实际路径: /mnt/shared/tenants/{tenant_id}
    workspace_path: str     # session 内暴露的路径: /workspace
    input_path: str         # /workspace/input
    output_path: str        # /workspace/output
    isolated: bool          # 是否成功建立隔离 (bind mount)


class WorkspaceGuard:
    """
    租户工作空间隔离器

    每个 AgentCore session 启动时调用一次 setup()，
    将该 session 的可见范围限制到指定租户的子目录。
    """

    def __init__(self, efs_mount: str = EFS_MOUNT):
        self.efs_mount = efs_mount
        self.tenants_dir = f"{efs_mount}/tenants"
        self._current_tenant: Optional[TenantWorkspace] = None

    def setup(self, tenant_id: str) -> TenantWorkspace:
        """
        为 session 设置租户工作空间

        流程：
        1. 确保租户目录存在
        2. 尝试 bind mount 到 /workspace (最强隔离)
        3. 如果 bind mount 失败，退化为 symlink + 路径守卫

        Args:
            tenant_id: 租户标识

        Returns:
            TenantWorkspace 描述
        """
        # 验证 tenant_id 安全性（防止路径注入）
        if not self._is_safe_tenant_id(tenant_id):
            raise ValueError(f"Invalid tenant_id: {tenant_id}")

        # 租户目录路径
        tenant_path = os.path.join(self.tenants_dir, tenant_id)

        # 确保目录结构
        self._ensure_tenant_dirs(tenant_path)

        # 尝试建立隔离
        isolated = self._setup_isolation(tenant_path)

        workspace = TenantWorkspace(
            tenant_id=tenant_id,
            efs_tenant_path=tenant_path,
            workspace_path=WORKSPACE,
            input_path=f"{WORKSPACE}/input",
            output_path=f"{WORKSPACE}/output",
            isolated=isolated,
        )

        self._current_tenant = workspace
        logger.info(
            f"Workspace ready: tenant={tenant_id}, "
            f"isolated={isolated}, path={WORKSPACE}"
        )
        return workspace

    def _is_safe_tenant_id(self, tenant_id: str) -> bool:
        """验证 tenant_id 不含路径注入字符"""
        if not tenant_id:
            return False
        # 只允许字母数字和 - _
        import re
        return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$', tenant_id))

    def _ensure_tenant_dirs(self, tenant_path: str):
        """创建租户目录结构"""
        os.makedirs(tenant_path, mode=0o755, exist_ok=True)
        os.makedirs(f"{tenant_path}/input", mode=0o755, exist_ok=True)
        os.makedirs(f"{tenant_path}/output", mode=0o755, exist_ok=True)

    def _setup_isolation(self, tenant_path: str) -> bool:
        """
        建立隔离：优先 bind mount，退化为 symlink

        Returns:
            True = bind mount 成功 (强隔离)
            False = 退化为 symlink (弱隔离，依赖路径守卫)
        """
        os.makedirs(WORKSPACE, exist_ok=True)

        # 尝试 bind mount
        if self._try_bind_mount(tenant_path):
            return True

        # 退化：symlink
        logger.warning("Bind mount unavailable, falling back to symlink + path guard")
        self._setup_symlink(tenant_path)
        return False

    def _try_bind_mount(self, tenant_path: str) -> bool:
        """尝试 bind mount"""
        try:
            result = subprocess.run(
                ["mount", "--bind", tenant_path, WORKSPACE],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info(f"Bind mount: {tenant_path} → {WORKSPACE}")
                return True
            else:
                logger.warning(f"Bind mount failed (rc={result.returncode}): {result.stderr.strip()}")
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.warning(f"Bind mount not available: {e}")
            return False

    def _setup_symlink(self, tenant_path: str):
        """退化方案：symlink"""
        # 清理旧的
        if os.path.islink(WORKSPACE):
            os.unlink(WORKSPACE)
        elif os.path.isdir(WORKSPACE):
            # 如果已经是目录（可能之前 bind mount 过），清空
            import shutil
            shutil.rmtree(WORKSPACE)

        os.symlink(tenant_path, WORKSPACE)
        logger.info(f"Symlink: {WORKSPACE} → {tenant_path}")

    def resolve_path(self, relative_path: str) -> Optional[str]:
        """
        安全解析路径，确保不逃逸出 workspace

        Args:
            relative_path: 相对于 /workspace 的路径

        Returns:
            解析后的安全路径，逃逸则返回 None
        """
        if self._current_tenant is None:
            return None

        # 清理路径
        clean = relative_path.lstrip("/")
        resolved = Path(WORKSPACE).joinpath(clean).resolve()

        # 如果是 bind mount，resolved 就在 /workspace 下
        # 如果是 symlink，resolved 会指向实际的 tenant_path
        workspace_real = Path(WORKSPACE).resolve()

        try:
            resolved.relative_to(workspace_real)
            return str(resolved)
        except ValueError:
            logger.warning(f"Path escape blocked: {relative_path} → {resolved}")
            return None

    @property
    def current_tenant(self) -> Optional[TenantWorkspace]:
        return self._current_tenant
