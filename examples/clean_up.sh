#!/bin/bash

set -e
set -u

# Delete all existing namespaces
namespaces=$(ip netns list | awk '{print $1}' | tr "\n" " ")
if [ -n "$namespaces" ]
then
    echo "Deleting net namespaces: $namespaces"
    for ns in $namespaces
    do
        echo "Deleting namespace: $ns"
        ip netns del "$ns"
    done
    echo "Namespaces deleted"
fi

interfaces=$(ip -o link show | awk -F ": " '{print $2}' | grep -vE "^lo$|^eth0" | tr "\n" " ")
if [ -n "$interfaces" ]
then
    echo "Deleting interfaces: $interfaces"
    for intf in $interfaces
    do
        i=$(echo "$intf" | awk -F "@" '{print $1}')
        echo "Deleting interface: $i"
        ip link del "$i" || true
    done
    echo "Interfaces deleted"
fi
