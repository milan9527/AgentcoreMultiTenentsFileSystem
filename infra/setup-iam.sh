#!/bin/bash
# 创建 AgentCore Runtime 执行角色
#
# 需要:
#   export AWS_REGION=us-west-2
#   export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
#   export EFS_FILE_SYSTEM_ID=fs-xxx
#   export EFS_ACCESS_POINT_ARN=arn:aws:elasticfilesystem:...

set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:?required}"
EFS_FS_ID="${EFS_FILE_SYSTEM_ID:?required}"
EFS_AP_ARN="${EFS_ACCESS_POINT_ARN:?required}"
ROLE_NAME="AgentCoreSandboxRole"

echo "=== Creating IAM Role ==="
cat > /tmp/trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"aws:SourceAccount": "${ACCOUNT_ID}"}}
  }]
}
EOF

aws iam create-role --role-name "$ROLE_NAME" \
  --assume-role-policy-document file:///tmp/trust.json 2>/dev/null || true

echo "=== Attaching EFS Policy ==="
cat > /tmp/efs.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["elasticfilesystem:ClientMount","elasticfilesystem:ClientWrite"],
    "Resource": "arn:aws:elasticfilesystem:${REGION}:${ACCOUNT_ID}:file-system/${EFS_FS_ID}",
    "Condition": {"ArnEquals": {"elasticfilesystem:AccessPointArn": "${EFS_AP_ARN}"}}
  }]
}
EOF

aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name EFSAccess --policy-document file:///tmp/efs.json

rm -f /tmp/trust.json /tmp/efs.json

echo ""
echo "Done."
echo "export ROLE_ARN=arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
