#!/usr/bin/env python3
"""
给已存在的 AgentCore Runtime 挂上 EFS Access Point（以及更新镜像 / 环境变量）。

用的是 SigV4 直签 PUT /runtimes/{id}：boto3 的 update_agent_runtime 在部分版本里
不带 filesystemConfigurations 字段，走 API 直调更可靠。

注意 **PUT 是整体替换，不是合并**：没带上的字段会被清掉。所以下面把镜像、角色、
网络、EFS、环境变量一次性全部给出 —— 少给 environmentVariables 会把
TENANT_AUTH_MODE / TENANT_SIGNING_KEY_SECRET_ID 一起抹掉，Runtime 随即拒绝
所有调用（UNAUTHENTICATED），而且不会有任何提示。

全部参数从环境变量取，没有硬编码的账号/子网/AP：

    export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    export AWS_REGION=us-east-1
    export RUNTIME_ID=sandboxIsolationDemo-xxxx
    export EFS_ACCESS_POINT_ID=fsap-xxx        # root directory 必须是 /tenants
    export SUBNET_IDS=subnet-aaa,subnet-bbb    # 与 EFS mount target 同 AZ
    export SECURITY_GROUP_IDS=sg-xxx           # 允许 outbound TCP 2049
    export IMAGE_TAG=jail                      # 默认 jail
    python3 infra/update_runtime_efs.py

先 --dry-run 看一遍将要提交的 body，确认无误再真跑：
    python3 infra/update_runtime_efs.py --dry-run
"""

import argparse
import json
import os
import sys
import time

import boto3
import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        sys.exit(f"缺少环境变量 {name}（见本文件顶部注释）")
    return val


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dry-run", action="store_true", help="只打印将提交的 body")
    args = ap.parse_args()

    region = env("AWS_REGION", "us-east-1")
    account = env("ACCOUNT_ID", required=True)
    runtime_id = env("RUNTIME_ID", required=True)
    ap_id = env("EFS_ACCESS_POINT_ID", required=True)
    subnets = [s.strip() for s in env("SUBNET_IDS", required=True).split(",") if s.strip()]
    sgs = [s.strip() for s in env("SECURITY_GROUP_IDS", required=True).split(",") if s.strip()]
    image_tag = env("IMAGE_TAG", "jail")
    repo = env("ECR_REPO", "sandbox-isolation-runtime")
    role_name = env("ROLE_NAME", "AgentCoreSandboxRole")
    secret_id = env("TENANT_SIGNING_KEY_SECRET_ID", "agentcore/tenant-signing-key")
    # AP 的 root directory 已经是 /tenants，所以挂载点本身就是租户目录的父目录
    tenants_dir = env("TENANTS_DIR", "/mnt/shared")

    body = json.dumps({
        "agentRuntimeArtifact": {
            "containerConfiguration": {
                "containerUri": f"{account}.dkr.ecr.{region}.amazonaws.com/{repo}:{image_tag}"
            }
        },
        "roleArn": f"arn:aws:iam::{account}:role/{role_name}",
        "networkConfiguration": {
            "networkMode": "VPC",
            "networkModeConfig": {"subnets": subnets, "securityGroups": sgs},
        },
        "filesystemConfigurations": [{
            "efsAccessPoint": {
                "accessPointArn": (f"arn:aws:elasticfilesystem:{region}:{account}"
                                   f":access-point/{ap_id}"),
                "mountPath": "/mnt/shared",
            }
        }],
        # PUT 整体替换 —— 这几个必须每次都带上，否则认证配置被清空
        "environmentVariables": {
            "AWS_REGION": region,
            "TENANT_AUTH_MODE": "hmac",
            "TENANT_SIGNING_KEY_SECRET_ID": secret_id,
            "TENANTS_DIR": tenants_dir,
        },
    }, indent=2)

    if args.dry_run:
        print(f"PUT /runtimes/{runtime_id}\n{body}")
        return

    client = boto3.client("bedrock-agentcore-control", region_name=region)
    print("等待 Runtime 进入 READY …")
    for _ in range(30):
        status = client.get_agent_runtime(agentRuntimeId=runtime_id)["status"]
        print(f"  status: {status}")
        if status == "READY":
            break
        time.sleep(10)
    else:
        sys.exit("超时：Runtime 未进入 READY")

    url = f"https://bedrock-agentcore-control.{region}.amazonaws.com/runtimes/{runtime_id}"
    creds = boto3.Session(region_name=region).get_credentials().get_frozen_credentials()
    signed = AWSRequest(method="PUT", url=url, data=body,
                        headers={"Content-Type": "application/json"})
    SigV4Auth(creds, "bedrock-agentcore", region).add_auth(signed)

    resp = urllib3.PoolManager().request("PUT", url, body=body, headers=dict(signed.headers))
    print(f"HTTP {resp.status}")
    print(resp.data.decode()[:2000])
    if resp.status >= 300:
        sys.exit(1)
    print("\n提交成功。等新版本 READY 后跑一遍验证：")
    print("  python3 tests/test_agentcore_live.py")
    print("  ./tools/tenant_shell.py --tenant tenant-a --probe")


if __name__ == "__main__":
    main()
