#!/bin/bash

cur_dir=$(cd `dirname $0` && pwd)

echo "Using payload file ${PAYLOAD_FILE:=$cur_dir/ingest.payload.json}"
echo "Using endpoint ${INGEST_ENDPOINT:=http://localhost:5001/api/v1/webhook/pre-receive}"

basic_auth_token=$(grep ingest $cur_dir/../secret_generated/basic_auth.conf | awk '{print $3}' | cut -d, -f1 )

curl -X POST -u $basic_auth_token -H 'Content-Type: application/json' -d@${PAYLOAD_FILE} ${INGEST_ENDPOINT}
