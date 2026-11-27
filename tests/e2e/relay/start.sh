#!/bin/sh
# A SOCKS5 proxy, and a resolver only reachable through it that gives different answers from the
# one on origin.
dnsmasq --listen-address=127.0.0.1 --bind-interfaces --no-resolv --no-hosts \
    --address=/probe.test/192.0.2.2 --address=/probe.test/2001:db8::2
exec sing-box run -c /etc/relay/config.json
