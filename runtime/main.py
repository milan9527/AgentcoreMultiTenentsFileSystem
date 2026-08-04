"""
AgentCore Runtime - 多租户隔离入口

隔离模型（四层，每层独立成立）：

1. microVM (AgentCore 原生)
   每个 session 独立 Firecracker microVM，session 之间物理隔离。

2. 可信身份 (tenant_identity.py)
   tenant_id 从 HMAC 签名 token 或已验签 JWT claim 中取得，调用方无法自证。
   session 首次调用时绑定租户，之后不允许切换。

3. mount namespace jail (jail.py)
   run_command / run_code 在独立 mount namespace 中执行，pivot_root 到只包含
   租户目录的新 rootfs。/mnt/shared 与其他租户目录在该视图里不存在，
   全部 capability 已丢弃，因此租户代码无法重新 mount 逃逸。
   jail 建立失败时拒绝执行（fail closed），绝不退化为无隔离执行。

4. 路径守卫 (workspace_guard.py)
   read_file / write_file / list_files 的路径必须落在租户目录内，
   绝对路径与 symlink 逃逸均被拒绝。

配额：单文件大小、workspace 总量、目录条目数均有上限，防止单租户写满共享 EFS。
"""

import logging
import os
import stat as stat_mod
import subprocess
import sys
import tempfile

from bedrock_agentcore import BedrockAgentCoreApp

from tenant_identity import TenantAuthError, TenantResolver, SessionBinding
from workspace_guard import (
    WORKSPACE,
    PathNotAllowed,
    WorkspaceGuard,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = BedrockAgentCoreApp()
guard = WorkspaceGuard()
resolver = TenantResolver()
bindings = SessionBinding()

JAIL_LAUNCHER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jail.py")
JAIL_SETUP_FAILED = 126

# ─── 配额 (可通过环境变量覆盖) ─────────────────────────────────────

def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default

MAX_WRITE_BYTES = _int_env("MAX_WRITE_BYTES", 32 * 1024 * 1024)        # 单次写入
MAX_READ_BYTES = _int_env("MAX_READ_BYTES", 32 * 1024 * 1024)          # 单次读取
MAX_WORKSPACE_BYTES = _int_env("MAX_WORKSPACE_BYTES", 5 * 1024**3)     # workspace 总量
MAX_LIST_ENTRIES = _int_env("MAX_LIST_ENTRIES", 1000)
MAX_OUTPUT_BYTES = _int_env("MAX_OUTPUT_BYTES", 1024 * 1024)           # stdout/stderr 截断

MAX_TIMEOUT = _int_env("MAX_TIMEOUT", 300)
DEFAULT_TIMEOUT = _int_env("DEFAULT_TIMEOUT", 60)

JAIL_TMP_MB = _int_env("JAIL_TMP_MB", 64)
JAIL_MAX_FILE_MB = _int_env("JAIL_MAX_FILE_MB", 256)
JAIL_MAX_PROCS = _int_env("JAIL_MAX_PROCS", 256)
JAIL_MAX_MEMORY_MB = _int_env("JAIL_MAX_MEMORY_MB", 0)                 # 0 = 不限

MAX_CODE_BYTES = _int_env("MAX_CODE_BYTES", 1024 * 1024)
MAX_COMMAND_BYTES = _int_env("MAX_COMMAND_BYTES", 64 * 1024)

LANGUAGES = {
    "python": ("python3", ".py"),
    "bash": ("bash", ".sh"),
    "sh": ("sh", ".sh"),
}


# ─── 工具函数 ──────────────────────────────────────────────────────

def _clamp_timeout(raw):
    try:
        t = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(1, min(t, MAX_TIMEOUT))


def _truncate(s):
    if not isinstance(s, str):
        return s
    encoded = s.encode("utf-8", "replace")
    if len(encoded) <= MAX_OUTPUT_BYTES:
        return s
    return encoded[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore") + "\n...[truncated]"


def _workspace_usage(tenant_root):
    """当前 workspace 已用字节数（仅统计常规文件，不跟随 symlink）"""
    total = 0
    for dirpath, dirnames, filenames in os.walk(tenant_root, followlinks=False):
        for name in filenames:
            try:
                st = os.lstat(os.path.join(dirpath, name))
            except OSError:
                continue
            if stat_mod.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def _check_quota(workspace, incoming_bytes):
    used = _workspace_usage(workspace.efs_tenant_path)
    if used + incoming_bytes > MAX_WORKSPACE_BYTES:
        raise PathNotAllowed(
            f"Workspace quota exceeded: {used + incoming_bytes} > {MAX_WORKSPACE_BYTES} bytes"
        )


def _run_in_jail(workspace, argv, timeout, stdin_data=None):
    """
    在 mount namespace jail 内执行 argv。

    租户代码在 jail 里只能看到自己的目录；宿主环境变量不会透传（见 jail.build_env）。
    jail 无法建立时返回 126 并附带明确错误，绝不在无隔离状态下执行。
    """
    launcher = [
        sys.executable, JAIL_LAUNCHER,
        "--tenant-root", workspace.efs_tenant_path,
        "--workspace", WORKSPACE,
        "--tmp-size-mb", str(JAIL_TMP_MB),
        "--cpu-seconds", str(timeout),
        "--max-file-mb", str(JAIL_MAX_FILE_MB),
        "--max-procs", str(JAIL_MAX_PROCS),
        "--max-memory-mb", str(JAIL_MAX_MEMORY_MB),
        "--",
    ] + argv

    try:
        proc = subprocess.run(
            launcher,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
            # jail launcher 自身需要宿主 env 才能找到 python;
            # 传给租户代码的 env 由 jail.build_env() 白名单重建
            env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                 "LANG": os.environ.get("LANG", "C.UTF-8")},
        )
    except subprocess.TimeoutExpired as e:
        return {
            "exit_code": 124,
            "stdout": _truncate(e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")),
            "stderr": "Execution timed out",
            "timed_out": True,
        }

    if proc.returncode == JAIL_SETUP_FAILED and "jail:" in (proc.stderr or ""):
        logger.error("Jail setup failed for tenant=%s: %s",
                     workspace.tenant_id, proc.stderr.strip()[:500])
        return {
            "exit_code": JAIL_SETUP_FAILED,
            "stdout": "",
            "stderr": "Sandbox unavailable; execution refused",
            "sandbox_error": True,
        }

    return {
        "exit_code": proc.returncode,
        "stdout": _truncate(proc.stdout or ""),
        "stderr": _truncate(proc.stderr or ""),
    }


# ─── action handlers ──────────────────────────────────────────────

def do_run_command(workspace, params):
    command = params.get("command", "")
    if not isinstance(command, str) or not command.strip():
        return {"error": "command required"}
    if len(command.encode()) > MAX_COMMAND_BYTES:
        return {"error": "command too large"}
    timeout = _clamp_timeout(params.get("timeout", DEFAULT_TIMEOUT))
    return _run_in_jail(workspace, ["/bin/bash", "-c", command], timeout)


def do_run_code(workspace, params):
    code = params.get("code", "")
    language = str(params.get("language", "python")).lower()
    if not isinstance(code, str) or not code:
        return {"error": "code required"}
    if len(code.encode()) > MAX_CODE_BYTES:
        return {"error": "code too large"}
    if language not in LANGUAGES:
        return {"error": f"Unsupported language: {language}"}

    interp, _ext = LANGUAGES[language]
    timeout = _clamp_timeout(params.get("timeout", DEFAULT_TIMEOUT))

    # 旧版把脚本写进租户目录（.tmp_exec.py），会污染 workspace，也让租户代码
    # 能相互覆盖脚本。改为 stdin 传入，租户目录不落任何临时文件。
    if language == "python":
        argv = [f"/usr/bin/env", interp, "-"]
    else:
        argv = [f"/usr/bin/env", interp, "-s"]

    return _run_in_jail(workspace, argv, timeout, stdin_data=code)


def do_read_file(workspace, params):
    try:
        safe = guard.resolve_path(workspace, params.get("path", ""))
    except PathNotAllowed as e:
        return {"error": str(e)}

    if not os.path.isfile(safe):
        return {"error": "Not found"}

    size = os.path.getsize(safe)
    if size > MAX_READ_BYTES:
        return {"error": f"File too large ({size} > {MAX_READ_BYTES} bytes)"}

    with open(safe, "r", errors="replace") as f:
        content = f.read()
    return {"content": content, "size": len(content)}


def do_write_file(workspace, params):
    content = params.get("content", "")
    if not isinstance(content, str):
        return {"error": "content must be a string"}

    encoded = content.encode()
    if len(encoded) > MAX_WRITE_BYTES:
        return {"error": f"Content too large ({len(encoded)} > {MAX_WRITE_BYTES} bytes)"}

    try:
        safe = guard.resolve_path(workspace, params.get("path", ""), for_write=True)
        _check_quota(workspace, len(encoded))
    except PathNotAllowed as e:
        return {"error": str(e)}

    parent = os.path.dirname(safe)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)

    # 原子写入，避免并发调用看到半截文件
    fd, tmp = tempfile.mkstemp(dir=parent or None, prefix=".w-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, safe)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    # 报字节数而非字符数：配额与 MAX_WRITE_BYTES 都按 len(encoded) 算，
    # 这里也必须一致，否则非 ASCII 内容下"写入 18 字节"和 ls 的 44 对不上
    return {"written": len(encoded),
            "path": guard.to_workspace_view(workspace, safe)}


def do_list_files(workspace, params):
    try:
        safe = guard.resolve_path(workspace, params.get("path", "."))
    except PathNotAllowed as e:
        return {"error": str(e)}

    if not os.path.isdir(safe):
        return {"error": "Not a directory"}

    entries = []
    truncated = False
    for name in sorted(os.listdir(safe)):
        if len(entries) >= MAX_LIST_ENTRIES:
            truncated = True
            break
        full = os.path.join(safe, name)
        try:
            st = os.lstat(full)
        except OSError:
            continue
        entries.append({
            "name": name,
            "is_dir": stat_mod.S_ISDIR(st.st_mode),
            "is_symlink": stat_mod.S_ISLNK(st.st_mode),
            "size": st.st_size,
        })

    result = {"entries": entries}
    if truncated:
        result["truncated"] = True
    return result


def do_status(workspace, params):
    return {
        "tenant_id": workspace.tenant_id,
        "workspace": workspace.workspace_path,
        "auth_mode": resolver.mode,
        "sandbox": "mount-namespace-jail",
        "quota_bytes": MAX_WORKSPACE_BYTES,
        "used_bytes": _workspace_usage(workspace.efs_tenant_path),
    }


HANDLERS = {
    "run_command": do_run_command,
    "run_code": do_run_code,
    "read_file": do_read_file,
    "write_file": do_write_file,
    "list_files": do_list_files,
    "status": do_status,
}


# ─── 入口 ─────────────────────────────────────────────────────────

@app.entrypoint
def handle(payload, context=None):
    try:
        if not isinstance(payload, dict):
            return {"status": "error", "error": "payload must be a JSON object"}

        action = payload.get("action")
        params = payload.get("params", {})
        if not action:
            return {"status": "error", "error": "action required"}
        if not isinstance(params, dict):
            return {"status": "error", "error": "params must be an object"}

        handler = HANDLERS.get(action)
        if not handler:
            return {"status": "error", "error": "Unknown action"}

        # 1. 可信身份：签名 token / 已验签 JWT claim，而非调用方自证
        tenant_id = resolver.resolve(payload, context)

        # 2. session 绑定：同一 session 不允许切换租户
        session_id = getattr(context, "session_id", None)
        workspace = bindings.bind(session_id, tenant_id, guard.setup)

        result = handler(workspace, params)
        return {"status": "ok", "action": action, "data": result}

    except TenantAuthError as e:
        logger.warning("Tenant auth rejected: %s", e)
        return {"status": "error", "code": "UNAUTHENTICATED", "error": str(e)}
    except PermissionError as e:
        logger.warning("Permission denied: %s", e)
        return {"status": "error", "code": "PERMISSION_DENIED", "error": str(e)}
    except PathNotAllowed as e:
        return {"status": "error", "code": "PATH_NOT_ALLOWED", "error": str(e)}
    except ValueError as e:
        return {"status": "error", "code": "INVALID_ARGUMENT", "error": str(e)}
    except Exception:
        # 不向调用方回传内部异常文本，避免泄漏宿主路径等信息
        logger.exception("Request failed")
        return {"status": "error", "code": "INTERNAL", "error": "Internal error"}


if __name__ == "__main__":
    app.run()
