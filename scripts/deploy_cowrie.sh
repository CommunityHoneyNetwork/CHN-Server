#!/bin/bash

URL=$1
DEPLOY=$2
ARCH=$4
SERVER=$(echo ${URL} | awk -F/ '{print $3}')

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '2'
services:
  cowrie:
    image: stingar/cowrie${ARCH}:1.7
    restart: always
    volumes:
      - ./cowrie.sysconfig:/etc/default/cowrie:z
      - ./cowrie:/etc/cowrie:z
    ports:
      - "2222:2222"
      - "23:2223"
EOF
echo 'Done!'
echo 'Creating cowrie.sysconfig...'
cat << EOF > cowrie.sysconfig
# This file is read from /etc/sysconfig/cowrie or /etc/default/cowrie
# depending on the base distro
#
# This can be modified to change the default setup of the cowrie unattended installation

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
COWRIE_JSON="/etc/cowrie/cowrie.json"

# SSH Listen Port
# Can be set to 22 for deployments on real servers
# or left at 2222 and have the port mapped if deployed
# in a container
SSH_LISTEN_PORT=2222

# Telnet Listen Port
# Can be set to 23 for deployments on real servers
# or left at 2223 and have the port mapped if deployed
# in a container
TELNET_LISTEN_PORT=2223

# double quotes, comma delimited tags may be specified, which will be included
# as a field in the hpfeeds output. Use cases include tagging provider
# infrastructure the sensor lives in, geographic location for the sensor, etc.
TAGS=""

# A specific "personality" directory for the Cowrie honeypot may be specified
# here. These directories can include custom fs.pickle, cowrie.cfg, txtcmds and
# userdb.txt files which can influence the attractiveness of the honeypot.
PERSONALITY=default
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose ps" to confirm your honeypot is running'
echo 'You may type "docker-compose logs" to get any error or informational logs from your honeypot'
