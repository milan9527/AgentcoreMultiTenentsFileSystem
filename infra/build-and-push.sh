#!/bin/bash
# 构建 Runtime 镜像推送 ECR
#
# 需要:
#   export AWS_REGION=us-west-2
#   export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:?required}"
REPO="sandbox-agent-runtime"
ECR="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPO}"

aws ecr create-repository --repository-name "$REPO" --region "$REGION" 2>/dev/null || true

aws ecr get-login-password --region "$REGION" | \
  docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

cd "$(dirname "$0")/../runtime"
docker build --platform linux/arm64 -t "${REPO}:latest" .
docker tag "${REPO}:latest" "${ECR}:latest"
docker push "${ECR}:latest"

echo ""
echo "export ECR_IMAGE_URI=${ECR}:latest"
