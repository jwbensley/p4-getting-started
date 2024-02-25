#!/bin/bash

# Create the following topology with two interfaces, in different name spaces,
# in different IP subnets, using the software switch to route layer 3 packets
# between them:
#
#    Software Switch      |                          Linux Kernel
#                         |
#                         |
#                         |   -------------------------      -------------------------
#                         |   -                       -      -                       -
#                         |   - Namespace: None       -      - Namespace: 1          -
#                         |   -                       -      -                       -
# ┌───────────────────┐   |   - ┌───────────────────┐ -      - ┌───────────────────┐ -
# │                   │   |   - │                   │ -      - │                   │ -
# │ intf: 0           │   |   - │ intf: 1_1         │ -      - │ intf: 1_2         │ -
# │                   ├───────-─┤ 10.0.1.1/24       ├──────────┤ 10.0.1.2/24       │ -
# │                   │   |   - │ 00:00:00:00:01:01 │ -      - │ 00:00:00:00:01:02 │ -
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
# │ intf: 1           │   |   - │ intf: 2_1         │ -      - │ intf: 2_2         │ -
# │                   ├─────────┤ 10.0.2.1/24       ├──────────┤ 10.0.2.2/24       │ -
# │                   │   |   - │ 00:00:00:00:02:01 │ -      - │ 00:00:00:00:02:02 │ -
# │                   │   |   - │                   │ -      - │                   │ -
# └───────────────────┘   |   - └───────────────────┘ -      - └───────────────────┘ -
#                         |   -                       -      -                       -
#                         |   -                       -      - Namespace: 2          -
#                         |   -                       -      -                       -
#                         |   -------------------------      -------------------------
#

set -e
set -u

ip netns add 1
ip netns add 2
ip link add 1_1 type veth peer name 1_2
ip link add 2_1 type veth peer name 2_2
ip link set 1_2 netns 1
ip link set 2_2 netns 2

ip netns exec 1 ip link set dev 1_2 address 00:00:00:00:01:02
ip link set dev 1_1 address 00:00:00:00:01:01
ip link set dev 2_1 address 00:00:00:00:02:01
ip netns exec 2 ip link set dev 2_2 address 00:00:00:00:02:02

ip link set up dev 1_1
ip addr add 10.0.1.1/24 dev 1_1
ip netns exec 1 ip link set up dev 1_2
ip netns exec 1 ip addr add 10.0.1.2/24 dev 1_2

ip link set up dev 2_1
ip addr add 10.0.2.1/24 dev 2_1
ip netns exec 2 ip link set up dev 2_2
ip netns exec 2 ip addr add 10.0.2.2/24 dev 2_2

ip netns exec 1 ip a
ip netns exec 1 ip r
echo ""
ip a 
ip r
echo ""
ip netns exec 2 ip a
ip netns exec 2 ip r

exit

ROOT_DIR=/l3_fwd
PROG=l3_fwd
p4c --target bmv2 --arch v1model --std p4-16 -o "$ROOT_DIR" --p4runtime-files "${ROOT_DIR}/${PROG}.p4.txt" "${ROOT_DIR}/${PROG}.p4"
simple_switch -i 0@l2_r0 -i 1@l2_r1 -L debug --log-console --dump-packet-data 64 "${ROOT_DIR}/${PROG}.json" &
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
read

# Debugging commands:
# 
#tcpdump -nlASXevvv -s 0 -i l2_r1
