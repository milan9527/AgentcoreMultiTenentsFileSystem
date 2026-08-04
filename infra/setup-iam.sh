#!/bin/bash
# 创建 AgentCore Runtime 执行角色
#
# 需要:
#   export AWS_REGION=us-east-1
#   export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
#   export EFS_FILE_SYSTEM_ID=fs-xxx
#   export EFS_ACCESS_POINT_ARN=arn:aws:elasticfilesystem:...

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
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
# EFS 访问被限定到单个 Access Point。AP 的 root directory 是 /tenants，
# 因此该角色通过 EFS 只能触及 /tenants 子树，不能访问文件系统的其他部分。
# Describe* 是挂载前的必需权限：缺了会在创建 Runtime 时报 424（挂载失败），
# 且错误信息不会指向 IAM。这几个动作是只读元数据，不能加 AccessPointArn 条件
# （Describe 调用不带该上下文键，加了会永远拒绝），所以单列一条语句。
cat > /tmp/efs.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["elasticfilesystem:ClientMount","elasticfilesystem:ClientWrite"],
    "Resource": "arn:aws:elasticfilesystem:${REGION}:${ACCOUNT_ID}:file-system/${EFS_FS_ID}",
    "Condition": {"ArnEquals": {"elasticfilesystem:AccessPointArn": "${EFS_AP_ARN}"}}
  }, {
    "Effect": "Allow",
    "Action": ["elasticfilesystem:DescribeAccessPoints",
               "elasticfilesystem:DescribeMountTargets",
               "elasticfilesystem:DescribeFileSystems"],
    "Resource": "*"
  }]
}
EOF

aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name EFSAccessPolicy --policy-document file:///tmp/efs.json

echo "=== Attaching ECR + CloudWatch Logs Policy ==="
# 拉镜像与写日志。没有这条 Runtime 会卡在 CREATING 或起不来。
cat > /tmp/ecrlogs.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["ecr:GetDownloadUrlForLayer","ecr:BatchGetImage","ecr:GetAuthorizationToken"],
    "Resource": "*"
  }, {
    "Effect": "Allow",
    "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
    "Resource": "*"
  }]
}
EOF

aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name ECRAndLogsPolicy --policy-document file:///tmp/ecrlogs.json

# 租户 token 签名密钥的读取权限（TENANT_AUTH_MODE=hmac）。
# 该密钥绝不能进入 jail —— jail 只透传 PATH/LANG 等白名单变量，
# 租户代码看不到 Runtime 的环境变量（见 runtime/jail.py build_env）。
if [ -n "${TENANT_SIGNING_KEY_SECRET_ARN:-}" ]; then
  echo "=== Attaching Secrets Manager Policy ==="
  cat > /tmp/secret.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "${TENANT_SIGNING_KEY_SECRET_ARN}"
  }]
}
EOF
  aws iam put-role-policy --role-name "$ROLE_NAME" \
    --policy-name TenantSigningKey --policy-document file:///tmp/secret.json
  rm -f /tmp/secret.json
else
  echo "WARN: TENANT_SIGNING_KEY_SECRET_ARN not set; skipping Secrets Manager policy."
  echo "      Set it, or pass TENANT_SIGNING_KEY directly as a Runtime env var."
fi

rm -f /tmp/trust.json /tmp/efs.json /tmp/ecrlogs.json

echo ""
echo "Done."
echo "export ROLE_ARN=arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
