#!/bin/bash

# Create the following topology with two routers. Each has a local subnet,
# and there is a route programmed by the control-plane between the local
# subnets:
#
#     Software Switch 1                             Linux Kernel
# ------------------------   -------------------------      -------------------------
# |                      |   - Namespace: None       -      - Namespace: l3_0       -
# |┌───────────────────┐ |   - ┌───────────────────┐ -      - ┌───────────────────┐ -
# |│ intf: 0           │ |   - │ intf: l3_r0       │ -      - │ intf: l3_0        │ -
# |│ fd::1/64          ├─|───-─┤                   ├─-──────-─┤ fd::2/64          │ -
# |│                   │ |   - │ 00:00:00:00:00:01 │ -      - │ 00:00:00:00:00:02 │ -
# |└────────┬──────────┘ |   - └───────────────────┘ -      - └───────────────────┘ -
# |         │            |   -                       -      -------------------------
# |         │            |   -                       -      -------------------------
# |┌────────┴──────────┐ |   - ┌───────────────────┐ -      - ┌───────────────────┐ -
# |│ intf: 1           │ |   - │ intf: l3_r1       │ -      - │ intf: l3_1        │ -
# |│ fd:0:0:1::1/64    ├─|───-─┤                   ├─-──────-─┤ fd:0:0:1::2/64    │ -
# |│                   │ |   - │ 00:00:00:00:01:01 │ -      - │ 00:00:00:00:01:02 │ -
# |└────────┬──────────┘ |   - └───────────────────┘ -      - └───────────────────┘ -
# |         |            |   - ┌───────────────────┐ -      - Namespace: l3_1       -
# |┌────────┴──────────┐ |   - │ intf: isl1        │ -      -------------------------
# |│ intf: 2           | |   - │                   │ -
# |│ fd:0:0:ff::1/64   ├─|───-─┤ 00:00:00:00:FF:01 │ -
# |└───────────────────┘ |   - └────────┬──────────┘ -
# |----------------------|   -          |            -
#                            -          |            -
#   Software Switch 2        -          |            -
# |----------------------|   -          |            -
# |┌───────────────────┐ |   - ┌────────┴──────────┐ -
# |│ intf: 0           | |   - │ intf: isl2        │ -
# |│ fd:0:0:ff::2/64   ├─|───-─|                   │ -
# |└────────┬──────────┘ |   - | 00:00:00:00:FF:02 │ -      -------------------------
# |         |            |   - └───────────────────┘ -      - Namespace: l3_2       -
# |┌────────┴──────────┐ |   - ┌───────────────────┐ -      - ┌───────────────────┐ -
# |│ intf: 1           │ |   - │ intf: l3_r2       │ -      - │ intf: l3_2        │ -
# |│ fd:0:0:2::1/64    ├─|───-─┤                   ├─-──────-─┤ fd:0:0:2::2/64    │ -
# |│                   │ |   - │ 00:00:00:00:02:01 │ -      - │ 00:00:00:00:02:02 │ -
# |└────────┬──────────┘ |   - └───────────────────┘ -      - └───────────────────┘ -
# |┌────────┴──────────┐ |   -------------------------      -------------------------
# |│ intf: 2           │ |
# |└───────────────────┘ |
# |----------------------|

set -e
set -u

if [ ! "$(ip netns ls | awk '{print $1}' | sort | tr '\n' ' ')" == "l3_0 l3_1 l3_2 " ]
then
    ip netns add l3_0
    ip netns add l3_1
    ip netns add l3_2
    ip link add l3_r0 type veth peer name l3_0
    ip link add l3_r1 type veth peer name l3_1
    ip link add l3_r2 type veth peer name l3_2
    ip link add isl1 type veth peer name isl2
    ip link set l3_0 netns l3_0
    ip link set l3_1 netns l3_1
    ip link set l3_2 netns l3_2

    ip link set dev l3_r0 address 00:00:00:00:00:01
    ip link set up dev l3_r0
    ip addr flush dev l3_r0
    sysctl -w net.ipv6.conf.l3_r0.disable_ipv6=1
    ip netns exec l3_0 ip link set dev l3_0 address 00:00:00:00:00:02
    ip netns exec l3_0 ip link set up dev l3_0
    ip netns exec l3_0 ip addr flush dev l3_0
    ip netns exec l3_0 sysctl -w net.ipv6.conf.l3_0.disable_ipv6=0
    ip netns exec l3_0 ip -6 addr add fd::2/64 dev l3_0
    ip netns exec l3_0 ip -6 route add default via fd::1 dev l3_0

    ip link set dev l3_r1 address 00:00:00:00:01:01
    ip link set up dev l3_r1
    ip addr flush dev l3_r1
    sysctl -w net.ipv6.conf.l3_r1.disable_ipv6=1
    ip netns exec l3_1 ip link set dev l3_1 address 00:00:00:00:01:02
    ip netns exec l3_1 ip link set up dev l3_1
    ip netns exec l3_1 ip addr flush dev l3_1
    ip netns exec l3_1 sysctl -w net.ipv6.conf.l3_1.disable_ipv6=0
    ip netns exec l3_1 ip -6 addr add fd:0:0:1::2/64 dev l3_1
    ip netns exec l3_1 ip -6 route add default via fd:0:0:1::1 dev l3_1

    ip link set dev l3_r2 address 00:00:00:00:02:01
    ip link set up dev l3_r2
    ip addr flush dev l3_r2
    sysctl -w net.ipv6.conf.l3_r2.disable_ipv6=1
    ip netns exec l3_2 ip link set dev l3_2 address 00:00:00:00:02:02
    ip netns exec l3_2 ip link set up dev l3_2
    ip netns exec l3_2 ip addr flush dev l3_2
    ip netns exec l3_2 sysctl -w net.ipv6.conf.l3_2.disable_ipv6=0
    ip netns exec l3_2 ip -6 addr add fd:0:0:2::2/64 dev l3_2
    ip netns exec l3_2 ip -6 route add default via fd:0:0:2::1 dev l3_2

    ip link set dev isl1 address 00:00:00:00:FF:01
    ip link set up dev isl1
    ip addr flush dev isl1
    sysctl -w net.ipv6.conf.isl1.disable_ipv6=1
    ip link set dev isl2 address 00:00:00:00:FF:02
    ip link set up dev isl2
    ip addr flush dev isl2
    sysctl -w net.ipv6.conf.isl2.disable_ipv6=1

    ip netns exec l3_0 ip a
    ip netns exec l3_0 ip r
    echo ""
    ip netns exec l3_1 ip a
    ip netns exec l3_1 ip r
    echo ""
    ip netns exec l3_2 ip a
    ip netns exec l3_2 ip r
    echo ""
    ip a 
    ip r
    echo ""
fi

SCRIPT_DIR=$(dirname "$0")
p4c --target bmv2 --arch v1model --std p4-16 -o "$SCRIPT_DIR" --p4runtime-files "${SCRIPT_DIR}/p4app.p4.txt" "${SCRIPT_DIR}/p4app.p4"
# ^ this is basically the same as:
# p4c-bm2-ss --target bmv2 --arch v1model --std p4-16 -o "${SCRIPT_DIR}/p4app.p4i" --p4runtime-files "${SCRIPT_DIR}/p4app.p4.txt" "${SCRIPT_DIR}/p4app.p4"
simple_switch --thrift-port 9090 -i 0@l3_r0 -i 1@l3_r1 -i 2@isl1 -L debug --log-console --dump-packet-data 64 "${SCRIPT_DIR}/p4app.json"
#simple_switch --thrift-port 9091 -i 0@l3_r0 -i 1@l3_r1 -i 2@isl1 -L debug --log-console --dump-packet-data 64 "${SCRIPT_DIR}/p4app.json"
