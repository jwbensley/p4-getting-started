#!/bin/bash

set -e
set -u

# Delete all existing namespaces
if [ ! "$(ip netns list)" ]; then exit 0; fi

echo "Deleting net namespaces: $(ip netns list)"
for ns in $(ip netns list | awk '{print $1}')
do
    echo "Deleting namespace: $ns"
    ip netns del "$ns"
done
echo "Namespaces deleted"
