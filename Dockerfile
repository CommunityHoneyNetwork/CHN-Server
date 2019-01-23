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

RUN date
RUN apt-get update \
      && apt-get install -y ansible

RUN echo "localhost ansible_connection=local" >> /etc/ansible/hosts
ADD . /opt/
RUN ansible-playbook /opt/${playbook}

ENTRYPOINT ["/usr/bin/runsvdir", "-P", "/etc/service"]
