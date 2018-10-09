#!/bin/bash

URL=$1
DEPLOY=$2
SERVER=$(echo ${URL} | awk -F/ '{print $3}')

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '2'
services:
    wordpot:
        image: stingar/wordpot:0.2-alpha-centos
        volumes:
            - ./wordpot.sysconfig:/etc/sysconfig/wordpot
            - ./wordpot:/etc/wordpot
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
# WORDPOT_JSON="/etc/wordpot/wordpot.json

# Wordpress options
WORDPRESS_PORT=8080
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose up" to start your honeypot!'