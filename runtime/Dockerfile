FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    util-linux curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY workspace_guard.py .

RUN mkdir -p /workspace /mnt/shared/tenants

EXPOSE 8080

ENTRYPOINT ["python", "-u", "main.py"]
