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
  honeydb:
    image: stingar/honeydb-agent:${VERSION}
    volumes:
    - configs:/etc/honeydb/
    env_file:
      - honeydb-agent.env
    ports:
      - "389:389"           # LDAP
      - "10001:10001"       # Gas
      - "7000:7000"         # Echo
      - "1883:1883"         # MQQT
      - "8:8"               # MOTD
      - "2100:2100"         # FTP
      - "2222:2222"         # SSH
      - "2323:2323"         # Telnet
      - "25:25"             # SMTP
      - "8081:8081"         # HTTP
      - "502:502"           # Modbus
      - "2000:2000"         # iKettle
      - "2048:2048"         # Random
      - "3306:3306"         # MySQL
      - "4096:4096"         # HashRandomCount
      - "3389:3389"         # RDP
      - "5900:5900"         # VNC
      - "6379:6379"         # Redis
      - "7001:7001"         # WebLogic
      - "9200:9200"         # Elasticsearch
      - "11211:11211"       # Memcached
      - "20547:20547"       # ProConOs

volumes:
    configs:
EOF
echo 'Done!'
echo 'Creating honeydb-agent.env...'
cat << EOF > honeydb-agent.env
DEBUG=false

# IP Address of the honeypot
# Leaving this blank will default to the docker container IP
IP_ADDRESS=

CHN_SERVER=${URL}
DEPLOY_KEY=${DEPLOY}
HONEYDB_JSON=/etc/honeydb/honeydb.json

# Logging options
FEEDS_SERVER=${SERVER}
FEEDS_SERVER_PORT=10000
TAGS=${TAGS}

# If you wish to also contribute your data to the Honeydb.io project, enable this option
# and create an account at https://honeydb.io/login to get an HoneyDB API ID and a HoneyDB Agent Secret Key
HONEYDB_ENABLED=No
HONEYDB_APIID=123
HONEYDB_APIKEY=123

# Honeydb-agent services to run. Use "Yes" to turn on a service, and "No" to turn it off.
# You can also remove the corresponding port mapping in the docker-compose file
HONEYDBSERVICE_LDAP=Yes
HONEYDBSERVICE_GAS=Yes
HONEYDBSERVICE_ECHO=Yes
HONEYDBSERVICE_MQTT=Yes
HONEYDBSERVICE_MOTD=Yes
HONEYDBSERVICE_FTP=Yes
HONEYDBSERVICE_SSH=Yes
HONEYDBSERVICE_TELNET=Yes
HONEYDBSERVICE_SMTP=Yes
HONEYDBSERVICE_HTTP=Yes
HONEYDBSERVICE_IKETTLE=Yes
HONEYDBSERVICE_RANDOM=Yes
HONEYDBSERVICE_MYSQL=Yes
HONEYDBSERVICE_HASHRANDOMCOUNT=Yes
HONEYDBSERVICE_RDP=Yes
HONEYDBSERVICE_VNC=Yes
HONEYDBSERVICE_REDIS=Yes
HONEYDBSERVICE_WEBLOGIC=Yes
HONEYDBSERVICE_ELASTICSEARCH=Yes
HONEYDBSERVICE_MEMCACHED=Yes
HONEYDBSERVICE_PROCONOS=Yes
EOF
echo 'Done!'
echo ''
echo ''
echo 'Type "docker-compose ps" to confirm your honeypot is running'
echo 'You may type "docker-compose logs" to get any error or informational logs from your honeypot'
