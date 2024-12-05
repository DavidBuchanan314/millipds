#!/bin/sh

PDS_HOST="192.168.0.97:8123"
PLC_HOST="http://192.168.0.73:2582"
RELAY_HOST="http://192.168.0.73:2470"
HANDLE="bob.test"

rm -rf ./data

millipds init millipds.test

./create_identity.sh $HANDLE http://$PDS_HOST $PLC_HOST

DID_PLC=$(cat "${HANDLE}_did.txt")

millipds config --pds_pfx=http://$PDS_HOST
millipds account create $DID_PLC $HANDLE --unsafe_password="lol" --signing_key="${HANDLE}_repo_key.pem"

#millipds run
# curl --json '{"hostname": "http://192.168.0.97:8123"}' "http://192.168.0.73:2470/xrpc/com.atproto.sync.requestCrawl"
# curl --json '{"hostname": "http://192.168.0.97:8123"}' "http://192.168.0.73:2470/admin/pds/requestCrawl" -H "Authorization: Bearer localdev"
