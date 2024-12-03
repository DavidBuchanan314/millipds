#!/bin/bash

set -euxo pipefail

rm -rf ./data

millipds init localhost:8123 --dev
millipds account create did:plc:bwxddkvw5c6pkkntbtp2j4lx local.dev.retr0.id --unsafe_password="lol"

millipds run &
PDS_PID=$!

# wait for server to start up
until curl -s http://localhost:8123/
do
	echo "waiting for service startup"
	sleep 0.05
done

python3 tests/integration_test.py
kill $PDS_PID
