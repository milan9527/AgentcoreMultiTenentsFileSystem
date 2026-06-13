"""
AgentCore Runtime - Sandbox Isolation Demo
Uses bedrock_agentcore SDK (BedrockAgentCoreApp)
"""
import json
import os
import subprocess
import logging

from bedrock_agentcore import BedrockAgentCoreApp
from workspace_guard import WorkspaceGuard, WORKSPACE

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = BedrockAgentCoreApp()
guard = WorkspaceGuard()

_initialized = False
_tenant_id = None


def ensure_workspace(tenant_id):
    global _initialized, _tenant_id
    if not _initialized:
        guard.setup(tenant_id)
        _initialized = True
        _tenant_id = tenant_id
    elif _tenant_id != tenant_id:
        raise PermissionError(f"Session bound to '{_tenant_id}', cannot switch to '{tenant_id}'")


@app.entrypoint
def handle(payload):
    try:
        tenant_id = payload.get("tenant_id")
        action = payload.get("action")
        params = payload.get("params", {})

        if not tenant_id:
            return {"status": "error", "error": "tenant_id required"}
        if not action:
            return {"status": "error", "error": "action required"}

        ensure_workspace(tenant_id)

        handlers = {
            "run_command": do_run_command,
            "run_code": do_run_code,
            "read_file": do_read_file,
            "write_file": do_write_file,
            "list_files": do_list_files,
            "status": do_status,
        }
        handler = handlers.get(action)
        if not handler:
            return {"status": "error", "error": f"Unknown action: {action}"}

        result = handler(params)
        return {"status": "ok", "action": action, "data": result}

    except PermissionError as e:
        return {"status": "error", "code": "PERMISSION_DENIED", "error": str(e)}
    except Exception as e:
        logger.exception("Request failed")
        return {"status": "error", "error": str(e)}


def do_run_command(params):
    command = params.get("command", "")
    timeout = params.get("timeout", 60)
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True, text=True, timeout=timeout, cwd=WORKSPACE,
        env={**os.environ, "HOME": WORKSPACE, "WORKSPACE": WORKSPACE},
    )
    return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def do_run_code(params):
    code = params.get("code", "")
    language = params.get("language", "python")
    timeout = params.get("timeout", 60)
    ext = {"python": ".py", "bash": ".sh"}.get(language, ".py")
    script = f"{WORKSPACE}/.tmp_exec{ext}"
    try:
        with open(script, "w") as f:
            f.write(code)
        os.chmod(script, 0o755)
        interp = {"python": "python3", "bash": "bash"}.get(language, "python3")
        result = subprocess.run([interp, script], capture_output=True, text=True, timeout=timeout, cwd=WORKSPACE)
        return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    finally:
        try:
            os.unlink(script)
        except OSError:
            pass


def do_read_file(params):
    path = params.get("path", "")
    safe = guard.resolve_path(path)
    if safe is None:
        return {"error": "Path not allowed"}
    if not os.path.isfile(safe):
        return {"error": f"Not found: {path}"}
    with open(safe) as f:
        content = f.read()
    return {"content": content, "size": len(content)}


def do_write_file(params):
    path = params.get("path", "")
    content = params.get("content", "")
    safe = guard.resolve_path(path)
    if safe is None:
        return {"error": "Path not allowed"}
    os.makedirs(os.path.dirname(safe), exist_ok=True)
    with open(safe, "w") as f:
        f.write(content)
    return {"written": len(content), "path": path}


def do_list_files(params):
    path = params.get("path", ".")
    safe = guard.resolve_path(path)
    if safe is None:
        return {"error": "Path not allowed"}
    if not os.path.isdir(safe):
        return {"error": f"Not a directory: {path}"}
    entries = []
    for name in sorted(os.listdir(safe)):
        full = os.path.join(safe, name)
        entries.append({"name": name, "is_dir": os.path.isdir(full), "size": os.path.getsize(full)})
    return {"entries": entries}


def do_status(params):
    ws = guard.current_tenant
    if ws is None:
        return {"initialized": False}
    return {"tenant_id": ws.tenant_id, "workspace": ws.workspace_path, "isolated": ws.isolated}


if __name__ == "__main__":
    app.run()
