#!/bin/sh
# Deploys (`up`) or destroys (`down`) the topology for `cargo test --test e2e`. containerlab runs
# from its container image, so access to Docker is all this needs. Build uta first: the nodes run
# target/debug/uta.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)

containerlab() {
    # containerlab hands paths in the topology to the Docker daemon, so the checkout is mounted at
    # the same path; its lab directory goes under target/.
    docker run --rm --privileged --network host --pid host \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v /var/run/netns:/var/run/netns \
        -v /var/lib/docker/containers:/var/lib/docker/containers \
        -v "$root:$root" -w "$root" \
        -e CLAB_LABDIR_BASE="$root/target" \
        ghcr.io/srl-labs/clab:0.83.0 containerlab "$@" --topo tests/e2e/uta.clab.yml
}

case "${1-}" in
up)
    for image in ubuntu alpine; do
        docker build -t "uta-e2e/$image" "$root/tests/e2e/images/$image"
    done
    containerlab deploy --reconfigure
    ;;
down)
    containerlab destroy --cleanup
    ;;
*)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
