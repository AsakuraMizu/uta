FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus dbus-user-session sudo util-linux libcap2-bin \
        nftables iproute2 curl dnsutils dnsmasq socat ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG SING_BOX_VERSION=1.14.4
ARG TARGETARCH
ADD https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${TARGETARCH}.tar.gz /tmp/sing-box.tar.gz
RUN tar -xzf /tmp/sing-box.tar.gz -C /usr/bin --strip-components=1 --wildcards '*/sing-box' \
    && rm /tmp/sing-box.tar.gz

# alice deploys uta from her home directory with contrib/user, where the tests copy it to give it
# capabilities; bob is a user uta leaves alone.
RUN useradd -m -u 1001 -s /bin/bash alice \
    && useradd -m -u 1002 -s /bin/bash bob \
    && echo 'alice ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/alice \
    && mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/alice \
    && mkdir -p /home/alice/.local/bin /home/alice/.config/systemd/user /home/alice/.config/uta/sing-box \
    && chown -R alice:alice /home/alice

# The deployment of contrib/system, whose files the topology mounts.
RUN mkdir -p /etc/uta/sing-box && ln -s /opt/uta/uta /usr/bin/uta

# A local stub resolver like systemd-resolved's, forwarding to the resolver on origin.
COPY stub.conf /etc/dnsmasq.d/stub.conf

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
