"""
WorkspaceGuard - 租户目录解析与路径守卫

职责（相对旧版已收窄）：
1. 确定租户在 EFS 上的目录，确保目录结构存在
2. 为受守卫的文件 API (read_file/write_file/list_files) 提供安全路径解析

**不再**负责把租户目录 bind mount 到 /workspace。原因：bind mount 只把租户
目录 *映射* 到 /workspace，并没有 *隐藏* /mnt/shared —— 租户代码用绝对路径
/mnt/shared/tenants/<其他租户> 可以直接读写。文件系统视图的隔离改由
jail.py 用 mount namespace + pivot_root 实现，那里 /mnt/shared 根本不存在。

本模块因此只做两件事：目录管理 + 路径解析。所有租户代码执行都必须走 jail。

路径守卫相对旧版的三处修正：
- 绝对路径不再被静默改写。旧版 lstrip("/") 把 "/etc/passwd" 变成
  workspace/etc/passwd 并返回成功，既在租户目录里种出影子目录树，也把明显的
  越权尝试伪装成正常操作，审计日志里看不到。现在直接拒绝。
- symlink 逃逸：解析父目录的真实路径，租户自己种下的 symlink 无法指向外部。
- 不再有 rmtree/symlink 退化逻辑。旧版在 bind mount 失败时 rmtree(WORKSPACE)，
  若 /workspace 上残留着上一个租户的活动 bind mount，会穿过挂载点删除该租户
  在 EFS 上的真实数据。该代码路径已整体移除。
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional

from tenant_identity import is_valid_tenant_id

logger = logging.getLogger(__name__)

# AgentCore 挂载 EFS 的路径 (通过 filesystemConfigurations 的 mountPath 配置)
EFS_MOUNT = os.environ.get("EFS_MOUNT", "/mnt/shared")

# 租户目录的父目录。
# 若 EFS Access Point 的 root directory 已经是 /tenants（见 infra/setup-efs.sh），
# 则挂载点本身就是 tenants 目录，此时应设 TENANTS_DIR=/mnt/shared。
TENANTS_DIR = os.environ.get("TENANTS_DIR") or os.path.join(EFS_MOUNT, "tenants")

# jail 内暴露给租户代码的工作目录路径
WORKSPACE = "/workspace"


@dataclass
class TenantWorkspace:
    """租户工作空间"""
    tenant_id: str
    efs_tenant_path: str   # EFS 上的实际路径: /mnt/shared/tenants/{tenant_id}
    workspace_path: str    # jail 内暴露的路径: /workspace
    input_path: str        # /workspace/input
    output_path: str       # /workspace/output


class PathNotAllowed(Exception):
    """路径越界 —— 操作必须被拒绝"""


class WorkspaceGuard:
    """租户目录解析器 + 路径守卫"""

    def __init__(self, efs_mount: str = EFS_MOUNT, tenants_dir: Optional[str] = None):
        self.efs_mount = efs_mount
        if tenants_dir:
            self.tenants_dir = tenants_dir
        elif efs_mount == EFS_MOUNT:
            self.tenants_dir = TENANTS_DIR
        else:
            self.tenants_dir = os.path.join(efs_mount, "tenants")

    # ─── 目录管理 ────────────────────────────────────────────────

    def setup(self, tenant_id: str) -> TenantWorkspace:
        """
        确保租户目录就绪，返回描述。

        不做任何 mount —— 文件系统隔离由 jail.py 负责。

        Raises:
            ValueError: tenant_id 非法
        """
        if not is_valid_tenant_id(tenant_id):
            raise ValueError(f"Invalid tenant_id: {tenant_id!r}")

        tenant_path = os.path.join(self.tenants_dir, tenant_id)

        # 防御性检查：即使 tenant_id 校验被绕过，也不允许目录跑到 tenants_dir 之外
        real_tenants = os.path.realpath(self.tenants_dir)
        if os.path.dirname(os.path.realpath(tenant_path)) != real_tenants:
            raise ValueError(f"Tenant path escapes tenants dir: {tenant_id!r}")

        os.makedirs(tenant_path, mode=0o700, exist_ok=True)
        for sub in ("input", "output"):
            os.makedirs(os.path.join(tenant_path, sub), mode=0o700, exist_ok=True)

        logger.info("Workspace ready: tenant=%s", tenant_id)
        return TenantWorkspace(
            tenant_id=tenant_id,
            efs_tenant_path=tenant_path,
            workspace_path=WORKSPACE,
            input_path=f"{WORKSPACE}/input",
            output_path=f"{WORKSPACE}/output",
        )

    # ─── 路径守卫 ────────────────────────────────────────────────

    def resolve_path(self, workspace: TenantWorkspace, relative_path: str,
                     for_write: bool = False) -> str:
        """
        把 workspace 相对路径解析为 EFS 上的真实路径。

        Args:
            workspace: 当前 session 绑定的租户工作空间
            relative_path: 相对于 /workspace 的路径；绝对路径一律拒绝
            for_write: 写操作时允许目标文件尚不存在

        Returns:
            EFS 上的绝对路径，保证位于租户目录内

        Raises:
            PathNotAllowed: 越界、绝对路径、symlink 逃逸、非法路径
        """
        if not isinstance(relative_path, str) or not relative_path:
            raise PathNotAllowed("Empty path")

        if "\x00" in relative_path:
            raise PathNotAllowed("Path contains NUL byte")

        # 绝对路径直接拒绝，不做静默改写
        if relative_path.startswith("/"):
            raise PathNotAllowed("Absolute paths are not allowed; use a workspace-relative path")

        # 纯字面量层面先拒明显的向上遍历，便于审计日志留痕
        parts = PurePosixPath(relative_path).parts
        if any(p == ".." for p in parts):
            raise PathNotAllowed("Parent directory traversal is not allowed")

        tenant_root = Path(os.path.realpath(workspace.efs_tenant_path))
        target = tenant_root.joinpath(relative_path)

        # 逐级解析真实路径：租户可能在自己目录里种 symlink 指向外部。
        # 对写操作，目标本身可以不存在，但其父目录必须已在租户目录内。
        probe = target if target.exists() or not for_write else target.parent
        try:
            real = Path(os.path.realpath(str(probe)))
        except OSError as e:
            raise PathNotAllowed(f"Cannot resolve path: {e.strerror}")

        if real != tenant_root and tenant_root not in real.parents:
            logger.warning("Path escape blocked: tenant=%s path=%r",
                           workspace.tenant_id, relative_path)
            raise PathNotAllowed("Path is outside the workspace")

        # 已存在的路径若是 symlink，realpath 已经解到真实位置并通过了上面的检查；
        # 但 symlink 本身指向租户目录外的情况在这里也被覆盖（real 会落在外部）。
        resolved = real if probe is target else real / target.name
        return str(resolved)

    def to_workspace_view(self, workspace: TenantWorkspace, efs_path: str) -> str:
        """把 EFS 真实路径转回租户看到的 /workspace 视图，避免向租户泄漏宿主路径"""
        tenant_root = os.path.realpath(workspace.efs_tenant_path)
        rel = os.path.relpath(efs_path, tenant_root)
        return str(PurePosixPath(WORKSPACE) / rel) if rel != "." else WORKSPACE
