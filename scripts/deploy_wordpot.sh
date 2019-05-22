#!/bin/bash

URL=$1
DEPLOY=$2
ARCH=$4
SERVER=$(echo ${URL} | awk -F/ '{print $3}')

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '2'
services:
    wordpot:
        image: stingar/wordpot${ARCH}:1.7
        restart: always
        volumes:
            - ./wordpot.sysconfig:/etc/default/wordpot:z
            - ./wordpot:/etc/wordpot:z
        ports:
            - "8080:8080"
EOF
echo 'Done!'
echo 'Creating wordpot.sysconfig...'
cat << EOF > wordpot.sysconfig
# This file is read from /etc/sysconfig/wordpot or /etc/default/wordpot
# depending on the base distro
#
# This can be modified to change the default setup of the wordpot unattended installation

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
WORDPOT_JSON="/etc/wordpot/wordpot.json"

# Wordpress options
WORDPRESS_PORT=8080
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose ps" to confirm your honeypot is running'
echo 'You may type "docker-compose logs" to get any error or informational logs from your honeypot'
