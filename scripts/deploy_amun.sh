#!/bin/bash

URL=$1
DEPLOY=$2
SERVER=$(echo ${URL} | awk -F/ '{print $3}')

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '2'
services:
    amun:
        image: stingar/amun:0.2-alpha-centos
        volumes:
            - ./amun.sysconfig:/etc/sysconfig/amun
            - ./amun:/etc/amun
        ports:
            - "445:445"
EOF
echo 'Done!'
echo 'Creating amun.sysconfig...'
cat << EOF > amun.sysconfig
# This file is read from /etc/sysconfig/amun or /etc/default/amun
# depending on the base distro
#
# This can be modified to change the default setup of the amun unattended installation

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
AMUN_JSON="/etc/amun/amun.json"
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose ps" to confirm your honeypot is running'
echo 'You may type "docker-compose logs" to get any error or informational logs from your honeypot'
