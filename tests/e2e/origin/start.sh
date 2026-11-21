#!/bin/sh
# Echoes the client address back over TCP and UDP, so a test sees whether a connection came
# directly or through the relay, and answers DNS with the direct answer.
socat TCP4-LISTEN:80,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' &
socat TCP6-LISTEN:80,ipv6only=1,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' &
socat UDP4-RECVFROM:9,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' &
socat UDP6-RECVFROM:9,ipv6only=1,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' &
# Answers a datagram to UDP port 10 with one from port 11, as a peer behind a NAT that maps each
# destination to its own port would, and a datagram to port 11 with the sender's address.
python3 -c '
import select, socket
port10, port11 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
port10.bind(("0.0.0.0", 10))
port11.bind(("0.0.0.0", 11))
while True:
    for sock in select.select([port10, port11], [], [])[0]:
        _, sender = sock.recvfrom(64)
        port11.sendto(b"x" if sock is port10 else sender[0].encode(), sender)
' &
# Without a listen address, dnsmasq answers only directly connected networks.
exec dnsmasq --keep-in-foreground --listen-address=10.0.4.2,fd00:4::2 --no-resolv --no-hosts --address=/probe.test/198.18.0.1 --address=/probe.test/fc00::1
