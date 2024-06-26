#!/bin/bash

# Create the following topology with two interfaces, in different name spaces,
# in the same IP subnet, using the software switch to forward layer 2 frames
# between them:
#
#    Software Switch      |                          Linux Kernel
#                         |
#                         |
#                         |   -------------------------      -------------------------
#                         |   -                       -      -                       -
#                         |   - Namespace: None       -      - Namespace: l2_0       -
#                         |   -                       -      -                       -
# ┌───────────────────┐   |   - ┌───────────────────┐ -      - ┌───────────────────┐ -
# │                   │   |   - │                   │ -      - │                   │ -
# │ intf: 0           │   |   - │ intf: l2_r0       │ -      - │ intf: l2_0        │ -
# │                   ├───────-─┤                   ├──────────┤ 10.0.0.1/24       │ -
# │                   │   |   - │ 00:00:00:00:00:02 │ -      - │ 00:00:00:00:00:01 │ -
# │                   │   |   - │                   │ -      - │                   │ -
# └────────┬──────────┘   |   - └───────────────────┘ -      - └───────────────────┘ -
#          │              |   -                       -      -                       -
#          │              |   -                       -      -------------------------
#          │              |   -                       -
#          │              |   -                       -
#          │              |   -                       -
#          │              |   -                       -
#          │              |   -                       -      -------------------------
#          │              |   -                       -      -                       -
# ┌────────┴──────────┐   |   - ┌───────────────────┐ -      - ┌───────────────────┐ -
# │                   │   |   - │                   │ -      - │                   │ -
# │ intf: 1           │   |   - │ intf: l2_r1       │ -      - │ intf: l2_1        │ -
# │                   ├─────────┤                   ├──────────┤ 10.0.0.4/24       │ -
# │                   │   |   - │ 00:00:00:00:00:03 │ -      - │ 00:00:00:00:00:04 │ -
# │                   │   |   - │                   │ -      - │                   │ -
# └───────────────────┘   |   - └───────────────────┘ -      - └───────────────────┘ -
#                         |   -                       -      -                       -
#                         |   -                       -      - Namespace: l2_1       -
#                         |   -                       -      -                       -
#                         |   -------------------------      -------------------------
#

set -e
set -u

ip netns add l2_0
ip netns add l2_1
ip link add l2_r0 type veth peer name l2_0
ip link add l2_r1 type veth peer name l2_1
ip link set l2_0 netns l2_0
ip link set l2_1 netns l2_1

ip netns exec l2_0 ip link set dev l2_0 address 00:00:00:00:00:01
ip link set dev l2_r0 address 00:00:00:00:00:02
ip link set dev l2_r1 address 00:00:00:00:00:03
ip netns exec l2_1 ip link set dev l2_1 address 00:00:00:00:00:04

ip link set up dev l2_r0
sysctl -w net.ipv6.conf.l2_r0.disable_ipv6=1
ip netns exec l2_0 ip link set up dev l2_0
ip netns exec l2_0 ip addr add 10.0.0.1/24 dev l2_0
ip netns exec l2_0 sysctl -w net.ipv6.conf.l2_0.disable_ipv6=1

ip link set up dev l2_r1
sysctl -w net.ipv6.conf.l2_r1.disable_ipv6=1
ip netns exec l2_1 ip link set up dev l2_1
ip netns exec l2_1 ip addr add 10.0.0.4/24 dev l2_1
ip netns exec l2_1 sysctl -w net.ipv6.conf.l2_1.disable_ipv6=1

ip netns exec l2_0 ip a
ip netns exec l2_0 ip r
echo ""
ip a 
ip r
echo ""
ip netns exec l2_1 ip a
ip netns exec l2_1 ip r


SCRIPT_DIR=$(dirname "$0")
p4c --target bmv2 --arch v1model --std p4-16 -o "$SCRIPT_DIR" --p4runtime-files "${SCRIPT_DIR}/p4app.p4.txt" "${SCRIPT_DIR}/p4app.p4"
simple_switch -i 0@l2_r0 -i 1@l2_r1 -L debug --log-console --dump-packet-data 64 "${SCRIPT_DIR}/p4app.json" &
# Wait for the switch to start before trying to access the control plane (thrift) via simple_switch_CLI
sleep 2
# Program some static MAC entries.
# Note that broadcast sends to port 1, meaning interface l2_0 in namespace l2_0 can ARP for 10.0.0.4, but 10.0.0.4 can't ARP for 10.0.0.1.
# This means that in this simple demo, 10.0.0.1 MUST ping 10.0.0.4, otherwise MAC resolution will fail:
simple_switch_CLI << EOF
table_add MyIngress.mac_addresses MyIngress.l2_forward 00:00:00:00:00:01 => 0
table_add MyIngress.mac_addresses MyIngress.l2_forward 00:00:00:00:00:04 => 1
table_add MyIngress.mac_addresses MyIngress.l2_forward FF:FF:FF:FF:FF:FF => 1
EOF
read -r
