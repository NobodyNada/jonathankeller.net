#!/bin/bash

set -euo pipefail

mount -o remount,rw /

echo "Downloading manifest..."
wget -O- https://jonathankeller.net/mister/manifest.json | jq -r '.[] | [.src, .dst] | join(" ")' | while read src dst; do
    echo "Downloading" $src
    wget -SL $src -O /tmp/download
    mv /tmp/download $dst
done

echo "Done, rebooting..."
sleep 3
reboot
