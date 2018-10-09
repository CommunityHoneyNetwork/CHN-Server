#!/bin/bash

URL=$1
DEPLOY=$2
SERVER=$(echo ${URL} | awk -F/ '{print $3}')

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '2'
services:
    glastopf:
        image: stingar/glastopf:0.2-alpha-ubuntu
        volumes:
            - ./glastopf.sysconfig:/etc/default/glastopf
            - ./glastopf:/etc/glastopf
        ports:
            - "8080:8080"
EOF
echo 'Done!'
echo 'Creating glastopf.sysconfig...'
cat << EOF > glastopf.sysconfig
# This file is read from /etc/default/glastopf
# depending on the base distro
#
# This can be modified to change the default setup of the glastopf unattended installation

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
GLASTOPF_JSON="/etc/glastopf/glastopf.json"

GLASTOPF_PORT=8080
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose up" to start your honeypot!'