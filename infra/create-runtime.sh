#!/bin/bash
# 创建 AgentCore Runtime (EFS 挂载)
#
# 需要:
#   export AWS_REGION=us-east-1
#   export ROLE_ARN=arn:aws:iam::xxx:role/AgentCoreSandboxRole
#   export EFS_ACCESS_POINT_ARN=arn:aws:elasticfilesystem:...
#   export SUBNET_IDS="subnet-aaa,subnet-bbb"
#   export SECURITY_GROUP_ID=sg-xxx
#   export ECR_IMAGE_URI=xxx.dkr.ecr.region.amazonaws.com/sandbox-isolation-runtime:jail
#                         （build-and-push.sh 末尾会直接打印这一行）
# 可选:
#   export TENANT_SIGNING_KEY_SECRET_ID=agentcore/tenant-signing-key
#   export TENANTS_DIR=/mnt/shared   # AP root 已是 /tenants 时用这个（默认）
#   export RUNTIME_NAME=sandboxIsolationDemo   # 只能 [a-zA-Z0-9_]，不能带连字符

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
ROLE_ARN="${ROLE_ARN:?required}"
EFS_AP_ARN="${EFS_ACCESS_POINT_ARN:?required}"
SUBNET_IDS="${SUBNET_IDS:?required}"
SG_ID="${SECURITY_GROUP_ID:?required}"
IMAGE="${ECR_IMAGE_URI:?required}"
SECRET_ID="${TENANT_SIGNING_KEY_SECRET_ID:-agentcore/tenant-signing-key}"
# setup-efs.sh 建的 AP root 就是 /tenants，挂载点本身即租户目录的父目录。
# 不设这个变量的话代码会去找 /mnt/shared/tenants —— 多了一层，租户目录全都定位不到。
TENANTS_DIR="${TENANTS_DIR:-/mnt/shared}"
# 文档、测试、tenant_shell 里出现的 RUNTIME_ID 都是 sandboxIsolationDemo-xxxx 的形式，
# 名字取自这里；改名的话上面那些地方的示例 id 也就跟着变。
RUNTIME_NAME="${RUNTIME_NAME:-sandboxIsolationDemo}"

IFS=',' read -ra SUBNETS <<< "$SUBNET_IDS"
SUBNETS_JSON=$(printf '"%s",' "${SUBNETS[@]}")
SUBNETS_JSON="[${SUBNETS_JSON%,}]"

echo "=== Creating AgentCore Runtime ==="

aws bedrock-agentcore-control create-agent-runtime \
  --agent-runtime-name "$RUNTIME_NAME" \
  --role-arn "$ROLE_ARN" \
  --region "$REGION" \
  --network-configuration "{
    \"networkMode\": \"VPC\",
    \"networkModeConfig\": {
      \"subnets\": $SUBNETS_JSON,
      \"securityGroups\": [\"$SG_ID\"]
    }
  }" \
  --agent-runtime-artifact "{
    \"containerConfiguration\": {
      \"containerUri\": \"$IMAGE\"
    }
  }" \
  --filesystem-configurations "[{
    \"efsAccessPoint\": {
      \"accessPointArn\": \"$EFS_AP_ARN\",
      \"mountPath\": \"/mnt/shared\"
    }
  }]" \
  --environment-variables "{
    \"AWS_REGION\": \"$REGION\",
    \"TENANT_AUTH_MODE\": \"hmac\",
    \"TENANT_SIGNING_KEY_SECRET_ID\": \"$SECRET_ID\",
    \"TENANTS_DIR\": \"$TENANTS_DIR\"
  }"

echo ""
echo "Runtime created. EFS mounted at /mnt/shared in every session."
echo "TENANT_AUTH_MODE=hmac —— 调用方必须带签名 tenant_token。"
echo ""
echo "等 READY 后验证:"
echo "  export RUNTIME_ID=<新建的 runtime id>"
echo "  python3 tests/test_agentcore_live.py"
echo "  ./tools/tenant_shell.py --tenant tenant-a --probe"
