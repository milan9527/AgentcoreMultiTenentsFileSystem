#!/usr/bin/env python3
"""Update AgentCore Runtime to add EFS filesystem configuration."""

import boto3
import json
import time
import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

REGION = "us-east-1"
RUNTIME_ID = "sandboxIsolationDemo-COIZYqEK2d"
ACCOUNT = "632930644527"

session = boto3.Session(region_name=REGION)
client = boto3.client('bedrock-agentcore-control', region_name=REGION)

# Wait for READY
print("Waiting for runtime to be READY...")
for i in range(30):
    resp = client.get_agent_runtime(agentRuntimeId=RUNTIME_ID)
    status = resp['status']
    print(f"  Status: {status}")
    if status == 'READY':
        break
    time.sleep(10)
else:
    print("ERROR: Timeout")
    exit(1)

# Update with EFS
print("\nUpdating runtime with EFS configuration...")
endpoint = f'https://bedrock-agentcore-control.{REGION}.amazonaws.com'
url = f'{endpoint}/runtimes/{RUNTIME_ID}'

body = json.dumps({
    'agentRuntimeArtifact': {
        'containerConfiguration': {
            'containerUri': f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/sandbox-isolation-runtime:latest'
        }
    },
    'roleArn': f'arn:aws:iam::{ACCOUNT}:role/AgentCoreSandboxRole',
    'networkConfiguration': {
        'networkMode': 'VPC',
        'networkModeConfig': {
            'subnets': ['subnet-062a148d1354577b3', 'subnet-023880de85fb9261b'],
            'securityGroups': ['sg-02c7e61a5da4a79da']
        }
    },
    'filesystemConfigurations': [{
        'efsAccessPoint': {
            'accessPointArn': f'arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:access-point/fsap-02dc22485f760354d',
            'mountPath': '/mnt/shared'
        }
    }]
})

creds = session.get_credentials().get_frozen_credentials()
request = AWSRequest(method='PUT', url=url, data=body, headers={'Content-Type': 'application/json'})
SigV4Auth(creds, 'bedrock-agentcore', REGION).add_auth(request)

http = urllib3.PoolManager()
response = http.request('PUT', url, body=body, headers=dict(request.headers))
print(f"Response: {response.status}")
print(response.data.decode()[:2000])
