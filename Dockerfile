FROM ubuntu:18.04

LABEL maintainer Chris Collins <collins.christopher@gmail.com>
LABEL name "chn-server"
LABEL version "0.1"
LABEL release "1"
LABEL summary "Community Honey Network Server"
LABEL description "Multi-snort and honeypot sensor management, uses a network of VMs, small footprint SNORT installations, stealthy dionaeas, and a centralized server for management."
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/communityhoneynetwork"
LABEL changelog-url "https://github.com/CommunityHoneyNetwork/communityhoneynetwork/commits/master"

VOLUME /tls

ENV playbook "chnserver.yml"
ENV TZ "America/New_York"
ENV DEBIAN_FRONTEND "noninteractive"

RUN date
RUN apt-get update

RUN apt-get install -y gcc git nginx python3-pip python3-dev redis-server libgeoip-dev libsqlite3-dev runit python3-certbot-nginx net-tools jq curl

ADD requirements.txt /opt/requirements.txt
RUN pip3 install -r /opt/requirements.txt

# Make Nginx directories
RUN mkdir -p /opt/www /etc/nginx /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/pki/tls/certs /etc/pki/tls/private

# sites-enable link
RUN ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Create vhost conf
COPY nginx_vhost.conf /etc/nginx/sites-available/default

# Create nginx server conf
COPY nginx.conf /etc/nginx/nginx.conf

# Create runit directories
RUN mkdir -p /etc/service/nginx /etc/service/uwsgi

# Create nginx runit conf
COPY nginx.run /etc/service/nginx/run
RUN chmod 755 /etc/service/nginx/run

# Create CHNServer sysconfig file
COPY chnserver.sysconfig /etc/default/chnserver

# Create uwsgi runit conf
COPY uwsgi.run /etc/service/uwsgi/run
RUN chmod 755 /etc/service/uwsgi/run

# Create log file for uwsgi
RUN mkdir -p /var/log/mhn \
    && chown www-data /var/log/mhn \
    && chmod 0755 /var/log/mhn

# Create sqlite directory
RUN mkdir -p /opt/sqlite

# Link to hpfeeds in chnserver
RUN pip3 install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git

# Link chnctl.py to bindir
RUN ln -s /opt/chnctl.py /usr/local/bin/chnctl

ADD . /opt/

ENTRYPOINT ["/usr/bin/runsvdir", "-P", "/etc/service"]
