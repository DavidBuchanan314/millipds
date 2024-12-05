#!/bin/sh

if [ "$3" = "" ]
then
	echo "USAGE: $0 <handle> <pds_host> <plc_host>"
	exit
fi

set -eu

HANDLE=$1
PDS_HOST=$2
PLC_HOST=$3

ROTATION_KEY_PATH="${HANDLE}_rotation_key.pem"
REPO_KEY_PATH="${HANDLE}_repo_key.pem"
GENESIS_JSON_PATH="${HANDLE}_plc_genesis.json"

echo "Generating keys..."

millipds util keygen > $ROTATION_KEY_PATH
millipds util keygen > $REPO_KEY_PATH

DID_PLC=$(
	millipds util plcgen \
		--genesis_json=$GENESIS_JSON_PATH \
		--rotation_key=$ROTATION_KEY_PATH \
		--handle=$HANDLE \
		--pds_host=$PDS_HOST \
		--repo_pubkey=$(millipds util print_pubkey $REPO_KEY_PATH)
)

echo $DID_PLC > "${HANDLE}_did.txt"

echo "Submitting genesis op to PLC..."

PLC_URL="${PLC_HOST}/${DID_PLC}"

curl --json @$GENESIS_JSON_PATH $PLC_URL
echo

echo "Created identity for ${HANDLE} at ${DID_PLC}"
echo $PLC_URL
