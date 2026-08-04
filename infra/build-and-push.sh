#!/bin/bash
# 构建 Runtime 镜像推送 ECR
#
# 需要:
#   export AWS_REGION=us-east-1
#   export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID="${ACCOUNT_ID:?required}"
# 与 create-runtime.sh / update_runtime_efs.py / README 用的是同一个仓库名与 tag，
# 三处对不上就会部署到一个陈旧镜像上（而且 Runtime 照样 READY，很难发现）
REPO="${ECR_REPO:-sandbox-isolation-runtime}"
TAG="${IMAGE_TAG:-jail}"
ECR="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPO}"

aws ecr create-repository --repository-name "$REPO" --region "$REGION" 2>/dev/null || true

aws ecr get-login-password --region "$REGION" | \
  docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

cd "$(dirname "$0")/../runtime"
docker build --platform linux/arm64 -t "${REPO}:${TAG}" .
docker tag "${REPO}:${TAG}" "${ECR}:${TAG}"
docker push "${ECR}:${TAG}"

echo ""
echo "export ECR_IMAGE_URI=${ECR}:${TAG}"
