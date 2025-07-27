#!/bin/bash

set -e

echo "Downloading manifest..."
curl https://jonathankeller.net/mister/manifest.json | jq -r '.[] | [.src, .dst] | join(" ")' | while read src dst; do
    echo "Downloading" $src
    curl -SL $src -o /tmp/download
    mv /tmp/download $dst
done

echo "Done, rebooting..."
sleep 3
reboot
