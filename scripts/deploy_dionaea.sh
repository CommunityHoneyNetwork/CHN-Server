#!/bin/bash

URL=$1
DEPLOY=$2
ARCH=$4
SERVER=$(echo ${URL} | awk -F/ '{print $3}')

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
version: '2'
services:
  dionaea:
    image: stingar/dionaea${ARCH}:1.7
    restart: always
    volumes:
      - ./dionaea.sysconfig:/etc/default/dionaea:z
      - ./dionaea/dionaea:/etc/dionaea/:z
    ports:
      - "21:21"
      - "23:23"
      - "69:69"
      - "80:80"
      - "123:123"
      - "135:135"
      - "443:443"
      - "445:445"
      - "1433:1433"
      - "1723:1723"
      - "1883:1883"
      - "1900:1900"
      - "3306:3306"
      - "5000:5000"
      - "5060:5060"
      - "5061:5061"
      - "11211:11211"
      - "27017:27017"
EOF
echo 'Done!'
echo 'Creating dionaea.sysconfig...'
cat << EOF > dionaea.sysconfig
#
# This can be modified to change the default setup of the dionaea unattended installation

DEBUG=false

# IP Address of the honeypot
# Leaving this blank will default to the docker container IP
IP_ADDRESS=

CHN_SERVER="${URL}"
DEPLOY_KEY=${DEPLOY}

# Network options
LISTEN_ADDRESSES="0.0.0.0"
LISTEN_INTERFACES="eth0"


# Service options
# blackhole, epmap, ftp, http, memcache, mirror, mongo, mqtt, mssql, mysql, pptp, sip, smb, tftp, upnp
SERVICES=(blackhole epmap ftp http memcache mirror mongo mqtt pptp sip smb tftp upnp)

DIONAEA_JSON="/etc/dionaea/dionaea.json"

# Logging options
HPFEEDS_ENABLED=true
FEEDS_SERVER="${SERVER}"
FEEDS_SERVER_PORT=10000

# Comma separated tags for honeypot
TAGS=""
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose ps" to confirm your honeypot is running'
echo 'You may type "docker-compose logs" to get any error or informational logs from your honeypot'
