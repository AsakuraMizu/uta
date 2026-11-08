#!/bin/sh
# Echoes the client address back over TCP and UDP, so a test sees whether a connection came
# directly or through the relay, and answers DNS with the direct answer.
socat TCP4-LISTEN:80,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' &
socat TCP6-LISTEN:80,ipv6only=1,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' &
socat UDP4-RECVFROM:9,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' &
socat UDP6-RECVFROM:9,ipv6only=1,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' &
# Without a listen address, dnsmasq answers only directly connected networks.
exec dnsmasq --keep-in-foreground --listen-address=10.0.4.2,fd00:4::2 --no-resolv --no-hosts --address=/probe.test/198.18.0.1 --address=/probe.test/fc00::1
