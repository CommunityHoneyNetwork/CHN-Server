#!/bin/bash

URL=$1
DEPLOY=$2
ARCH=$4
SERVER=$(echo ${URL} | awk -F/ '{print $3}')

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '2'
services:
    uhp:
        image: stingar/uhp${ARCH}:1.7
        restart: always
        volumes:
            - ./uhp.sysconfig:/etc/default/uhp:z
            - ./uhp:/etc/uhp:z
        ports:
            - "25:2525"
EOF
echo 'Done!'
echo 'Creating uhp.sysconfig...'
cat << EOF > uhp.sysconfig
# This file is read from /etc/sysconfig/uhp or /etc/default/uhp
# depending on the base distro
#
# This can be modified to change the default setup of the uhp unattended installation

DEBUG=false

# IP Address of the honeypot
# Leaving this blank will default to the docker container IP
IP_ADDRESS=

# CHN Server api to register to
CHN_SERVER="${URL}"

# Server to stream data to
FEEDS_SERVER="${SERVER}"
FEEDS_SERVER_PORT=10000

# Deploy key from the FEEDS_SERVER administrator
# This is a REQUIRED value
DEPLOY_KEY=${DEPLOY}

# Registration information file
# If running in a container, this needs to persist
UHP_JSON="/etc/uhp/uhp.json"

# Defaults include auto-config-gen.json, avtech-devices.json, generic-listener.json,
# hajime.json, http-log-headers.json, http.json, pop3.json, and smtp.json
UHP_CONFIG="smtp.json"

UHP_LISTEN_PORT=2525

# Comma separated tags for honeypot
TAGS=""
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose ps" to confirm your honeypot is running'
echo 'You may type "docker-compose logs" to get any error or informational logs from your honeypot'
