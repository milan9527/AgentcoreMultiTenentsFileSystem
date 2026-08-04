"""
tenant_identity.py - 可信租户身份解析

问题：旧版直接取 payload["tenant_id"]。任何能调用 InvokeAgentRuntime 的主体
都可以声明任意租户身份，整个隔离的信任根落在业务 Pod 的正确性上。

解法：tenant_id 必须来自不可伪造的来源。按优先级：

  1. TENANT_AUTH_MODE=hmac (默认)
     业务 Pod 用共享密钥签发 tenant token，Runtime 本地验签。
     token 格式: <tenant_id>.<expiry_unix>.<base64url(HMAC-SHA256)>
     密钥来自 TENANT_SIGNING_KEY 或 TENANT_SIGNING_KEY_SECRET_ID (Secrets Manager)。

  2. TENANT_AUTH_MODE=jwt
     从 Authorization: Bearer 中读取指定 claim。
     前提：AgentCore Runtime 已配置 inbound JWT authorizer，网关已验签。
     未配置 authorizer 时不要用这个模式 —— claim 将不可信。

  3. TENANT_AUTH_MODE=insecure_payload
     退回读 payload["tenant_id"]。仅用于本地开发，会打 CRITICAL 日志。
     生产环境绝不可用。

无论哪种模式，解析出的 tenant_id 都会与 session 绑定（见 SessionBinding），
同一 session 不允许切换租户。
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

TENANT_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$')

MODE_HMAC = "hmac"
MODE_JWT = "jwt"
MODE_INSECURE = "insecure_payload"

DEFAULT_MODE = MODE_HMAC


class TenantAuthError(Exception):
    """租户身份不可信 —— 调用必须被拒绝"""


def is_valid_tenant_id(tenant_id) -> bool:
    """
    校验 tenant_id 字面值安全。

    注意大小写：'Tenant-A' 与 'tenant-a' 会映射到两个不同目录。若上游身份
    系统大小写不敏感，应在签发 token 前统一规范化，避免身份与目录错配。
    """
    return isinstance(tenant_id, str) and bool(TENANT_ID_RE.match(tenant_id))


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def sign_tenant_token(tenant_id: str, signing_key: bytes, ttl_seconds: int = 900) -> str:
    """
    签发 tenant token（业务 Pod 侧使用；放在这里便于两端共用同一实现）。

    Returns:
        "<tenant_id>.<expiry>.<sig>"
    """
    if not is_valid_tenant_id(tenant_id):
        raise ValueError(f"Invalid tenant_id: {tenant_id!r}")
    expiry = int(time.time()) + ttl_seconds
    msg = f"{tenant_id}.{expiry}".encode()
    sig = hmac.new(signing_key, msg, hashlib.sha256).digest()
    return f"{tenant_id}.{expiry}.{_b64url_encode(sig)}"


def verify_tenant_token(token: str, signing_key: bytes, clock_skew: int = 60) -> str:
    """
    验签并返回 tenant_id。

    Raises:
        TenantAuthError: 格式错误 / 签名不符 / 已过期
    """
    if not isinstance(token, str) or token.count(".") != 2:
        raise TenantAuthError("Malformed tenant token")

    tenant_id, expiry_raw, sig_raw = token.split(".")

    if not is_valid_tenant_id(tenant_id):
        raise TenantAuthError("Malformed tenant token")

    try:
        expiry = int(expiry_raw)
    except ValueError:
        raise TenantAuthError("Malformed tenant token")

    msg = f"{tenant_id}.{expiry}".encode()
    expected = hmac.new(signing_key, msg, hashlib.sha256).digest()
    try:
        provided = _b64url_decode(sig_raw)
    except Exception:
        raise TenantAuthError("Malformed tenant token")

    # 恒定时间比较，避免签名内容通过时序泄漏
    if not hmac.compare_digest(expected, provided):
        raise TenantAuthError("Tenant token signature mismatch")

    if time.time() > expiry + clock_skew:
        raise TenantAuthError("Tenant token expired")

    return tenant_id


class TenantResolver:
    """从请求中解析可信 tenant_id"""

    def __init__(self, mode: Optional[str] = None):
        self.mode = (mode or os.environ.get("TENANT_AUTH_MODE") or DEFAULT_MODE).strip().lower()
        self.jwt_claim = os.environ.get("TENANT_JWT_CLAIM", "custom:tenant_id")
        self._key: Optional[bytes] = None
        self._key_lock = threading.Lock()

        if self.mode == MODE_INSECURE:
            logger.critical(
                "TENANT_AUTH_MODE=insecure_payload: tenant_id is caller-asserted and "
                "NOT verified. Any caller can impersonate any tenant. "
                "DO NOT USE IN PRODUCTION."
            )
        elif self.mode not in (MODE_HMAC, MODE_JWT):
            raise ValueError(f"Unknown TENANT_AUTH_MODE: {self.mode!r}")

    # ─── 密钥加载 ────────────────────────────────────────────────

    def _signing_key(self) -> bytes:
        if self._key is not None:
            return self._key
        with self._key_lock:
            if self._key is not None:
                return self._key
            raw = os.environ.get("TENANT_SIGNING_KEY")
            if raw:
                self._key = raw.encode()
            else:
                secret_id = os.environ.get("TENANT_SIGNING_KEY_SECRET_ID")
                if not secret_id:
                    raise TenantAuthError(
                        "No signing key configured: set TENANT_SIGNING_KEY or "
                        "TENANT_SIGNING_KEY_SECRET_ID"
                    )
                self._key = self._load_from_secrets_manager(secret_id)
            if len(self._key) < 32:
                raise TenantAuthError("Signing key too short (need >= 32 bytes)")
            return self._key

    @staticmethod
    def _load_from_secrets_manager(secret_id: str) -> bytes:
        try:
            import boto3
            client = boto3.client("secretsmanager")
            resp = client.get_secret_value(SecretId=secret_id)
            value = resp.get("SecretString") or resp.get("SecretBinary")
            if isinstance(value, bytes):
                return value
            # 允许 {"signing_key": "..."} 或裸字符串
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    for k in ("signing_key", "TENANT_SIGNING_KEY", "key"):
                        if k in parsed:
                            return str(parsed[k]).encode()
            except (json.JSONDecodeError, TypeError):
                pass
            return str(value).encode()
        except TenantAuthError:
            raise
        except Exception as e:
            raise TenantAuthError(f"Failed to load signing key: {type(e).__name__}")

    # ─── 解析 ────────────────────────────────────────────────────

    def resolve(self, payload: dict, context=None) -> str:
        """
        Returns:
            可信 tenant_id

        Raises:
            TenantAuthError: 身份不可信
        """
        if self.mode == MODE_HMAC:
            token = payload.get("tenant_token")
            if not token:
                raise TenantAuthError("tenant_token required (TENANT_AUTH_MODE=hmac)")
            return verify_tenant_token(token, self._signing_key())

        if self.mode == MODE_JWT:
            return self._from_jwt(context)

        # MODE_INSECURE
        tenant_id = payload.get("tenant_id")
        if not is_valid_tenant_id(tenant_id):
            raise TenantAuthError("Invalid or missing tenant_id")
        return tenant_id

    def _from_jwt(self, context) -> str:
        headers = getattr(context, "request_headers", None) or {}
        # header 名大小写不敏感
        auth = None
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth = v
                break
        if not auth or not auth.lower().startswith("bearer "):
            raise TenantAuthError("Missing bearer token (TENANT_AUTH_MODE=jwt)")

        token = auth[7:].strip()
        parts = token.split(".")
        if len(parts) != 3:
            raise TenantAuthError("Malformed JWT")

        # 签名由 AgentCore inbound authorizer 校验；此处只取 claim。
        # 未配置 authorizer 时该 claim 不可信 —— 见模块 docstring。
        try:
            claims = json.loads(_b64url_decode(parts[1]))
        except Exception:
            raise TenantAuthError("Malformed JWT payload")

        if not isinstance(claims, dict):
            raise TenantAuthError("Malformed JWT payload")

        exp = claims.get("exp")
        if isinstance(exp, (int, float)) and time.time() > exp + 60:
            raise TenantAuthError("JWT expired")

        tenant_id = claims.get(self.jwt_claim)
        if not is_valid_tenant_id(tenant_id):
            raise TenantAuthError(f"JWT claim {self.jwt_claim!r} missing or invalid")
        return tenant_id


@dataclass
class _Binding:
    tenant_id: str
    workspace: object


class SessionBinding:
    """
    session → tenant 绑定表。

    旧版用模块级全局 _tenant_id 记录绑定，如果容器被复用来服务多个 session，
    第二个租户会撞上 PermissionError（失败方向安全，但会造成难排查的故障）。
    这里按 session_id 分别记录，既支持容器复用，也仍然拒绝同一 session 内切换租户。
    """

    def __init__(self):
        self._bindings: dict = {}
        self._lock = threading.Lock()

    def bind(self, session_id: Optional[str], tenant_id: str, setup_fn):
        """
        绑定 session 到 tenant，返回 workspace。首次调用时执行 setup_fn。

        Raises:
            PermissionError: 该 session 已绑定到其他租户
        """
        key = session_id or "__no_session__"
        with self._lock:
            existing = self._bindings.get(key)
            if existing is not None:
                if existing.tenant_id != tenant_id:
                    raise PermissionError(
                        f"Session already bound to a different tenant; "
                        f"cannot switch to '{tenant_id}'"
                    )
                return existing.workspace

            workspace = setup_fn(tenant_id)
            self._bindings[key] = _Binding(tenant_id=tenant_id, workspace=workspace)
            return workspace

    def release(self, session_id: Optional[str]):
        with self._lock:
            self._bindings.pop(session_id or "__no_session__", None)
