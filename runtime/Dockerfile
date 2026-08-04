FROM --platform=linux/arm64 python:3.12-slim

# util-linux: mount/umount 工具（jail 用 libc syscall，但排障时需要）
# libcap2-bin: capsh，用于验证 capability 已丢弃
RUN apt-get update && apt-get install -y --no-install-recommends \
    util-linux libcap2-bin curl bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY workspace_guard.py .
COPY tenant_identity.py .
COPY jail.py .

# /jail: jail.py 在此挂 tmpfs 并 pivot_root
# /mnt/shared: EFS 挂载点 (AgentCore filesystemConfigurations)
# 注意不再预创建 /workspace —— 租户目录只在 jail 内部可见，
# 宿主 rootfs 上不存在 /workspace，避免误以为可以直接写它。
RUN mkdir -p /jail /mnt/shared/tenants && chmod 700 /jail

EXPOSE 8080

ENTRYPOINT ["python", "-u", "main.py"]
