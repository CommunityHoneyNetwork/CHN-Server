#!/bin/bash

URL=$1
DEPLOY=$2
SERVER=$(echo ${URL} | awk -F/ '{print $3}')

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '2'
services:
    rdphoney:
        image: stingar/rdphoney:0.2-alpha-centos
        volumes:
            - ./rdphoney.sysconfig:/etc/sysconfig/rdphoney
            - ./rdphoney:/etc/rdphoney
        ports:
            - "3389:3389"
EOF
echo 'Done!'
echo 'Creating rdphoney.sysconfig...'
cat << EOF > rdphoney.sysconfig
# This file is read from /etc/sysconfig/rdphoney or /etc/default/rdphoney
# depending on the base distro
#
# This can be modified to change the default setup of the rdphoney unattended installation

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
# RDPHONEY_JSON="/etc/rdphoney/rdphoney.json
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose up" to start your honeypot!'