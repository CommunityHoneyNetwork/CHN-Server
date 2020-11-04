#!/bin/bash

URL=$1
DEPLOY=$2
ARCH=$3
SERVER=$(echo ${URL} | awk -F/ '{print $3}')
VERSION=1.9.1
TAGS=""

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '3'
services:
  ssh-auth-logger:
    image: stingar/ssh-auth-logger:${VERSION}
    restart: always
    volumes:
      - configs:/etc/ssh-auth-logger
    ports:
      - "2222:22222"
    env_file:
      - ssh-auth-logger.env
volumes:
    configs:
EOF
echo 'Done!'
echo 'Creating ssh-auth-logger.env...'
cat << EOF > ssh-auth-logger.env
# This can be modified to change the default setup of the big-hp unattended installation

DEBUG=false

# IP Address of the honeypot
# Leaving this blank will default to the docker container IP
IP_ADDRESS=

# Internal Docker port ssh-auth-logger should bind to. Don't adjust generally.
SSHD_BIND=:22222

# CHN Server api to register to
CHN_SERVER=${URL}

# Server to stream data to
FEEDS_SERVER=${SERVER}
FEEDS_SERVER_PORT=10000

# Deploy key from the FEEDS_SERVER administrator
# This is a REQUIRED value
DEPLOY_KEY=${DEPLOY}

# Registration information file
# If running in a container, this needs to persist
SSHAUTHLOGGER_JSON=/etc/ssh-auth-logger/ssh-auth-logger.json

# comma delimited tags may be specified, which will be included
# as a field in the hpfeeds output. Use cases include tagging provider
# infrastructure the sensor lives in, geographic location for the sensor, etc.
TAGS=${TAGS}
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose ps" to confirm your honeypot is running'
echo 'You may type "docker-compose logs" to get any error or informational logs from your honeypot'
