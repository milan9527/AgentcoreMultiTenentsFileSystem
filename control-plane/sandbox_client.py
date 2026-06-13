"""
SandboxClient - 业务 Pod 侧调用 AgentCore Runtime

封装对 AgentCore Runtime 的调用：
- 为每个租户创建/复用 session
- 传递 tenant_id 到 Runtime
- session 内 microVM 物理隔离
- session 内文件限制到租户子目录
"""

import json
import uuid
import logging
from typing import Optional
from dataclasses import dataclass

import boto3

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


class SandboxSession:
    """
    一个租户的沙箱 session

    对应 AgentCore 的一个 runtime session (独立 microVM)。
    所有操作通过 InvokeAgentRuntime 发送到该 session。
    """

    def __init__(self, client, runtime_arn: str, session_id: str, tenant_id: str):
        self._client = client
        self._runtime_arn = runtime_arn
        self._session_id = session_id
        self._tenant_id = tenant_id

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def _invoke(self, action: str, params: dict = None) -> dict:
        """调用 AgentCore Runtime"""
        payload = json.dumps({
            "tenant_id": self._tenant_id,
            "action": action,
            "params": params or {},
        })

        response = self._client.invoke_agent_runtime(
            agentRuntimeArn=self._runtime_arn,
            runtimeSessionId=self._session_id,
            payload=payload.encode(),
        )

        # 读取响应
        body = b"".join(response.get("response", []))
        return json.loads(body)

    def run_command(self, command: str, timeout: int = 60) -> CommandResult:
        """
        在沙箱内执行命令

        命令在 /workspace 目录内执行，只能看到本租户数据。
        """
        resp = self._invoke("run_command", {
            "command": command,
            "timeout": timeout,
        })
        data = resp.get("data", resp)
        return CommandResult(
            exit_code=data.get("exit_code", -1),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
        )

    def run_code(self, code: str, language: str = "python", timeout: int = 60) -> CommandResult:
        """执行代码"""
        resp = self._invoke("run_code", {
            "code": code,
            "language": language,
            "timeout": timeout,
        })
        data = resp.get("data", resp)
        return CommandResult(
            exit_code=data.get("exit_code", -1),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
        )

    def read_file(self, path: str) -> Optional[str]:
        """读取文件（相对于 /workspace）"""
        resp = self._invoke("read_file", {"path": path})
        data = resp.get("data", resp)
        if "error" in data:
            raise FileNotFoundError(data["error"])
        return data.get("content")

    def write_file(self, path: str, content: str) -> int:
        """写入文件（相对于 /workspace）"""
        resp = self._invoke("write_file", {"path": path, "content": content})
        data = resp.get("data", resp)
        if "error" in data:
            raise IOError(data["error"])
        return data.get("written", 0)

    def list_files(self, path: str = ".") -> list[dict]:
        """列目录"""
        resp = self._invoke("list_files", {"path": path})
        data = resp.get("data", resp)
        return data.get("entries", [])

    def status(self) -> dict:
        """获取 workspace 状态"""
        resp = self._invoke("status")
        return resp.get("data", resp)

    def stop(self):
        """停止 session，释放 microVM"""
        try:
            self._client.stop_runtime_session(
                agentRuntimeArn=self._runtime_arn,
                runtimeSessionId=self._session_id,
            )
            logger.info(f"Session stopped: {self._session_id}")
        except Exception as e:
            logger.error(f"Failed to stop session: {e}")


class SandboxClient:
    """
    沙箱客户端

    业务 Pod 通过此客户端管理 AgentCore Runtime sessions。
    每个 session = 一个独立 microVM = 一个租户的沙箱。
    """

    def __init__(self, runtime_arn: str, region: str = "us-west-2"):
        self._runtime_arn = runtime_arn
        self._client = boto3.client("bedrock-agentcore", region_name=region)
        self._sessions: dict[str, SandboxSession] = {}

    def create_session(self, tenant_id: str, session_id: str = None) -> SandboxSession:
        """
        为租户创建沙箱 session

        每个 session 运行在独立 microVM 中。
        首次 invoke 时会触发 workspace 初始化（bind mount 到租户子目录）。

        Args:
            tenant_id: 租户标识
            session_id: 可选，不指定则自动生成（需 >= 33 字符）
        """
        if not session_id:
            session_id = f"sandbox-{tenant_id}-{uuid.uuid4().hex}"
            # 确保 >= 33 字符
            while len(session_id) < 33:
                session_id += "0"

        session = SandboxSession(
            client=self._client,
            runtime_arn=self._runtime_arn,
            session_id=session_id,
            tenant_id=tenant_id,
        )

        self._sessions[session_id] = session
        logger.info(f"Session created: tenant={tenant_id}, id={session_id}")
        return session

    def get_session(self, session_id: str) -> Optional[SandboxSession]:
        return self._sessions.get(session_id)

    def stop_session(self, session_id: str):
        """停止并清理 session"""
        session = self._sessions.pop(session_id, None)
        if session:
            session.stop()

    def stop_all(self):
        """停止所有 session"""
        for sid in list(self._sessions.keys()):
            self.stop_session(sid)
