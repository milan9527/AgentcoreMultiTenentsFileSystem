#!/bin/bash
# 创建 EFS + 单个 Access Point (root 挂载)
#
# 需要:
#   export AWS_REGION=us-east-1
#   export VPC_ID=vpc-xxx
#   export SUBNET_IDS="subnet-aaa,subnet-bbb"
#   export SECURITY_GROUP_ID=sg-xxx

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
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

# Access Point 的根目录限定到 /tenants，而不是 /。
# 这样即使 Runtime 侧代码出现缺陷，通过该 AP 也看不到 EFS 上 /tenants 以外的数据。
# 权限 700：只有 AP 的 posix-user (root) 可访问，租户代码在 jail 内以 root 身份
# 访问自己的目录，但 jail 的 mount namespace 已经把可见范围限制到单个租户目录。
echo "=== Creating Access Point (scoped to /tenants) ==="
AP_ARN=$(aws efs create-access-point \
  --file-system-id "$FS_ID" \
  --posix-user "Uid=0,Gid=0" \
  --root-directory "Path=/tenants,CreationInfo={OwnerUid=0,OwnerGid=0,Permissions=700}" \
  --tags Key=Name,Value=agentcore-tenants-ap \
  --region "$REGION" \
  --query 'AccessPointArn' --output text)

echo ""
echo "Done."
echo "export EFS_FILE_SYSTEM_ID=$FS_ID"
echo "export EFS_ACCESS_POINT_ARN=$AP_ARN"
echo ""
echo "NOTE: AP root is /tenants, mounted at /mnt/shared in the Runtime."
echo "      Set EFS_MOUNT accordingly if you change the AP root directory."
echo ""
echo "Generate the tenant-token signing key (shared by business Pod and Runtime):"
echo "  aws secretsmanager create-secret --name agentcore/tenant-signing-key \\"
echo "    --secret-string \"\$(openssl rand -base64 48)\" --region $REGION"
