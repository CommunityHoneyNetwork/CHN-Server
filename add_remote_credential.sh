#!/bin/bash
if (( $# != 2 ))
then
    echo "$0 [ident] [remote_ip]"
    echo "Illegal number of parameters; please include an ident and remote parameter!"
    exit 1
fi
# This generates a new random password and inserts it into a command line that can be run on a remote CHN instance in order to add a remote hpfeeds user that can read all events

IDENT=$1
REMOTE=$2
SECRET=$(tr -dc _A-Z-a-z-0-9 < /dev/urandom | head -c 20)

echo "Command to run on remote server:"
echo "********************************"
echo docker-compose exec hpfeeds3 /app/bin/python3 /src/hpfeeds/add_user.py --owner chn --ident \"${IDENT}\" --secret \"${SECRET}\" --publish \"\" --subscribe \"amun.events,conpot.events,thug.events,beeswarm.hive,dionaea.capture,dionaea.connections,thug.files,beeswarm.feeder,cuckoo.analysis,kippo.sessions,cowrie.sessions,glastopf.events,glastopf.files,mwbinary.dionaea.sensorunique,snort.alerts,wordpot.events,p0f.events,suricata.events,shockpot.events,elastichoney.events,rdphoney.sessions,uhp.events,elasticpot.events,spylex.events,big-hp.events,honeydb-agent.events\" --mongodb-host mongodb --mongodb-port 27017
echo "********************************"
echo ""
echo "Config for a new hpfeeds-logger.env to listen on local server:"
echo "********************************"
cat << EOF
# This file is read from /etc/default/hpfeeds-logger
#
# This can be modified to change the default setup of the unattended installation
MONGODB_HOST=mongodb
MONGODB_PORT=27017
# Log to local file; the path is internal to the container and the host filesystem
# location is controlled by volume mapping in the docker-compose.yml
FILELOG_ENABLED=true
LOG_FILE=/var/log/hpfeeds-logger/chn-splunk.log
# Choose to rotate the log file based on 'size'(default), 'time', or 'none'
# Choosing 'none' is ideal if you want to handle rotation outside of the
# container
ROTATION_STRATEGY=size
# If rotating by 'size', the number of MB to rotate at
ROTATION_SIZE_MAX=100
# If rotating by 'time', the unit to count in; valid values are "m","h", and "d"
ROTATION_TIME_UNIT=h
# If rotating by 'time', the number of rotation_time_unit to rotate at
ROTATION_TIME_MAX=24
# How many backup files to keep when rotating in the container
ROTATION_BACKUPS=3
# Log to syslog
SYSLOG_ENABLED=false
SYSLOG_HOST=localhost
SYSLOG_PORT=514
SYSLOG_FACILITY=user
# Options are arcsight, json, raw_json, splunk
FORMATTER_NAME=splunk
IDENT=${IDENT}
SECRET=${SECRET}
CHANNELS=amun.events,conpot.events,thug.events,beeswarm.hive,dionaea.capture,dionaea.connections,thug.files,beeswarm.feeder,cuckoo.analysis,kippo.sessions,cowrie.sessions,glastopf.events,glastopf.files,mwbinary.dionaea.sensorunique,snort.alerts,wordpot.events,p0f.events,suricata.events,shockpot.events,elastichoney.events,rdphoney.sessions,uhp.events,elasticpot.events,spylex.events,big-hp.events,ssh-auth-logger.events,honeydb-agent.events
HPFEEDS_HOST=${REMOTE}
HPFEEDS_PORT=10000

EOF
