#!/bin/bash
#set -ex

aws ssm get-parameter --name '/cloudhsm/workshop/selfsignedcert' --query Parameter.Value --output text  > customerCA.crt
mv customerCA.crt /opt/cloudhsm/etc/
chown root:root /opt/cloudhsm/etc/customerCA.crt
CLUSTER_ID=$(aws ssm get-parameter --name "/cloudhsm/workshop/clusterId" --query Parameter.Value --output text)
HSM_IP=$(aws cloudhsmv2 describe-clusters --filters clusterIds=$CLUSTER_ID --query Clusters[0].Hsms[0].EniIp --output text)
HSM_USER=$(aws secretsmanager get-secret-value --secret-id '/cloudhsm/workshop/cupassowrd' --query SecretString --output text | jq .username  -r)
HSM_PASSWORD=$(aws secretsmanager get-secret-value --secret-id '/cloudhsm/workshop/cupassowrd' --query SecretString --output text | jq .password  -r)

/opt/cloudhsm/bin/configure-pkcs11 -a $HSM_IP
while :
do
    /app/build/src/encrypt/aes_gcm --pin crypto_user:$HSM_PASSWORD
    sleep 1
done
