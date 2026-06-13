#!/bin/bash
# 创建 EFS + 单个 Access Point (root 挂载)
#
# 需要:
#   export AWS_REGION=us-west-2
#   export VPC_ID=vpc-xxx
#   export SUBNET_IDS="subnet-aaa,subnet-bbb"
#   export SECURITY_GROUP_ID=sg-xxx

set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"
VPC_ID="${VPC_ID:?required}"
SUBNET_IDS="${SUBNET_IDS:?required (comma-separated)}"
SG_ID="${SECURITY_GROUP_ID:?required}"

echo "=== Creating EFS ==="
FS_ID=$(aws efs create-file-system \
  --region "$REGION" \
  --performance-mode generalPurpose \
  --throughput-mode bursting \
  --encrypted \
  --tags Key=Name,Value=agentcore-sandbox-efs \
  --query 'FileSystemId' --output text)
echo "EFS: $FS_ID"

sleep 5

echo "=== Creating Mount Targets ==="
IFS=',' read -ra SUBNETS <<< "$SUBNET_IDS"
for S in "${SUBNETS[@]}"; do
  aws efs create-mount-target \
    --file-system-id "$FS_ID" --subnet-id "$S" \
    --security-groups "$SG_ID" --region "$REGION" \
    --output text 2>/dev/null || true
done

sleep 10

echo "=== Creating Access Point (root) ==="
AP_ARN=$(aws efs create-access-point \
  --file-system-id "$FS_ID" \
  --posix-user "Uid=0,Gid=0" \
  --root-directory "Path=/,CreationInfo={OwnerUid=0,OwnerGid=0,Permissions=755}" \
  --tags Key=Name,Value=agentcore-root-ap \
  --region "$REGION" \
  --query 'AccessPointArn' --output text)

echo ""
echo "Done."
echo "export EFS_FILE_SYSTEM_ID=$FS_ID"
echo "export EFS_ACCESS_POINT_ARN=$AP_ARN"
