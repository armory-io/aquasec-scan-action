#!/bin/sh -l

AQUA_USER=${1}
AQUA_PASSWORD=${2}
AQUA_URL=${3}
REGISTRY=${4}
IMAGE_TO_SCAN=${5}

## Login
AQUA_TOKEN=`curl -s -X POST ${AQUA_URL}/api/v1/login -D "{ \"id\":\"${AQUA_USER}\", \"password\":\"${AQUA_PASSWORD}\"}" -H "Content-Type: application/json"|jq '.token'`
echo "Done aquiring logins to Aquasec... using token ${AQUA_TOKEN}"
BASE_COMMAND="curl -s -H 'Content-Type: application/json' -H \"Authorization: Bearer ${AQUA_TOKEN}\"  ${AQUA_URL}/api/v1/scanner/registry/${REGISTRY}/${IMAGE_TO_SCAN}"
echo "Triggering a scan using ${BASE_COMMAND}/scan -X POST"

## Trigger a scan...
bash -c "${BASE_COMMAND}/scan -X POST"
echo "Scan triggered..."

## Get the status and wait for it to finish.
STATUS=`bash -c "${BASE_COMMAND}/status"|jq '.status'`
    while [[ ${STATUS} != "Scanned" ]] || [[ ${STATUS} != "Fail" ]]; do
    STATUS=`bash -c "${BASE_COMMAND}/status"|jq '.status'`
    echo "Build hasn't finished scanning... waiting.."
    sleep 30
done

bash -C "${BASE_COMMAND}/scan_result"|jq
# Fail the build
if [[ ${STATUS} == "Fail" ]];  then
    echo "** FAILING THE BUILD Security scan has FAILED **"
    exit 500
fi