"""
SandboxClient - 业务 Pod 侧调用 AgentCore Runtime

封装对 AgentCore Runtime 的调用：
- 为每个租户创建/复用 session
- 用共享密钥签发 tenant token，Runtime 侧验签后才认可租户身份
- session 内 microVM 物理隔离
- session 内文件与执行限制到租户子目录 (mount namespace jail)

租户身份不再由请求体自证：Runtime 校验 HMAC 签名的 tenant_token。
signing_key 必须与 Runtime 的 TENANT_SIGNING_KEY / TENANT_SIGNING_KEY_SECRET_ID
一致，且只能存在于业务 Pod 与 Runtime 两侧，不可下发给租户。
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Optional

import boto3

logger = logging.getLogger(__name__)

DEFAULT_TOKEN_TTL = 900


def sign_tenant_token(tenant_id: str, signing_key: bytes, ttl_seconds: int = DEFAULT_TOKEN_TTL) -> str:
    """
    签发 tenant token: "<tenant_id>.<expiry>.<base64url(HMAC-SHA256)>"

    与 runtime/tenant_identity.py 的 verify_tenant_token 对应。
    """
    expiry = int(time.time()) + ttl_seconds
    msg = f"{tenant_id}.{expiry}".encode()
    sig = hmac.new(signing_key, msg, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{tenant_id}.{expiry}.{encoded}"


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

    def __init__(self, client, runtime_arn: str, session_id: str, tenant_id: str,
                 signing_key: Optional[bytes] = None, token_ttl: int = DEFAULT_TOKEN_TTL):
        self._client = client
        self._runtime_arn = runtime_arn
        self._session_id = session_id
        self._tenant_id = tenant_id
        self._signing_key = signing_key
        self._token_ttl = token_ttl

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def _invoke(self, action: str, params: dict = None) -> dict:
        """调用 AgentCore Runtime"""
        body = {"action": action, "params": params or {}}

        if self._signing_key:
            # 每次调用重新签发，token 短期有效，避免长期凭证被复用
            body["tenant_token"] = sign_tenant_token(
                self._tenant_id, self._signing_key, self._token_ttl
            )
        else:
            # 仅在 Runtime 配置为 insecure_payload / jwt 模式时走到这里
            body["tenant_id"] = self._tenant_id

        payload = json.dumps(body)

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
        """写入文件（相对于 /workspace），返回写入的**字节数**（UTF-8，非字符数）"""
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

    def __init__(self, runtime_arn: str, region: str = "us-west-2",
                 signing_key: Optional[bytes] = None,
                 token_ttl: int = DEFAULT_TOKEN_TTL):
        """
        Args:
            signing_key: 与 Runtime 共享的 HMAC 密钥（>= 32 字节）。
                         省略时回退到环境变量 TENANT_SIGNING_KEY。
                         两者都没有时退化为传 tenant_id 明文 —— 只在 Runtime
                         配置为 jwt 或 insecure_payload 模式下可用。
        """
        self._runtime_arn = runtime_arn
        self._client = boto3.client("bedrock-agentcore", region_name=region)
        self._sessions: dict[str, SandboxSession] = {}
        self._token_ttl = token_ttl

        if signing_key is None:
            env_key = os.environ.get("TENANT_SIGNING_KEY")
            signing_key = env_key.encode() if env_key else None
        if signing_key is None:
            logger.warning(
                "No signing key provided; tenant_id will be sent unsigned. "
                "This only works if the Runtime is in jwt or insecure_payload mode."
            )
        elif len(signing_key) < 32:
            raise ValueError("signing_key too short (need >= 32 bytes)")
        self._signing_key = signing_key

    def create_session(self, tenant_id: str, session_id: str = None) -> SandboxSession:
        """
        为租户创建沙箱 session

        每个 session 运行在独立 microVM 中。首次 invoke 时 Runtime 会把该
        session 绑定到 token 中的租户，之后该 session 不接受其他租户身份。

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
            signing_key=self._signing_key,
            token_ttl=self._token_ttl,
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
