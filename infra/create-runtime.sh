#!/bin/bash
# 创建 AgentCore Runtime (EFS 挂载)
#
# 需要:
#   export AWS_REGION=us-west-2
#   export ROLE_ARN=arn:aws:iam::xxx:role/AgentCoreSandboxRole
#   export EFS_ACCESS_POINT_ARN=arn:aws:elasticfilesystem:...
#   export SUBNET_IDS="subnet-aaa,subnet-bbb"
#   export SECURITY_GROUP_ID=sg-xxx
#   export ECR_IMAGE_URI=xxx.dkr.ecr.region.amazonaws.com/sandbox-agent-runtime:latest

set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"
ROLE_ARN="${ROLE_ARN:?required}"
EFS_AP_ARN="${EFS_ACCESS_POINT_ARN:?required}"
SUBNET_IDS="${SUBNET_IDS:?required}"
SG_ID="${SECURITY_GROUP_ID:?required}"
IMAGE="${ECR_IMAGE_URI:?required}"

IFS=',' read -ra SUBNETS <<< "$SUBNET_IDS"
SUBNETS_JSON=$(printf '"%s",' "${SUBNETS[@]}")
SUBNETS_JSON="[${SUBNETS_JSON%,}]"

echo "=== Creating AgentCore Runtime ==="

aws bedrock-agentcore-control create-agent-runtime \
  --agent-runtime-name "sandbox-storage-agent" \
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
  }]"

echo ""
echo "Runtime created. EFS mounted at /mnt/shared in every session."
