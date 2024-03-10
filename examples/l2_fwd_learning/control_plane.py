#!/usr/bin/env python3

import sys
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16)]

CPU_MIRROR_PORT = "lo" # Interface on the Linux host to bind to simple switch port ID $CPU_MIRROR_PORT_ID
CPU_MIRROR_PORT_ID = 100 # Port ID for CPU punted frames
THRIFT_PORT = 9090
THRIFT_IP = "localhost"
SWITCH_PORTS = [0, 1]
MAC_TABLE="dmac"
ACTION_CONE_BROADCAST = "learn_mac_via_clone_and_broadcast"


def parse_args(args: list) -> bool:
    digest: bool
    if args[1] == "-d":
        digest = True
    elif args[1] == "-c":
        digest = False
    else:
        print(f"Unrecognised CLI arg: {args[1]}")
        print_help()
    return digest


def print_help() -> None:
    print(
        "\n"
        "The CPU punt mechanism must be specified.\n\n"
        f"{sys.argv[0]} -d    to use digest messages\n"
        "or\n"
        f"{sys.argv[0]} -c    to clone packets\n"
    )
    sys.exit(1)

def recv_frame_cpu(pkt):
    packet = Ether(raw(pkt))
    print(f"Received packet {packet}")
    if packet.type == 0x1234:
        cpu_header = CpuHeader(bytes(packet.load))
        print(f"Learning MAC {cpu_header.macAddr:%012X} via port {cpu_header.ingress_port}")
        controller.table_add(MAC_TABLE, "learn_mac_via_clone_and_forward", [str(cpu_header.macAddr)], [str(cpu_header.ingress_port)])

if __name__ == "__main__":
    # Parse CLI args
    if len(sys.argv) != 2:
        print_help()
    digest = parse_args(sys.argv)

    controller = SimpleSwitchThriftAPI(thrift_port=THRIFT_PORT, thrift_ip=THRIFT_IP)

    # Resets all state in the switch (table entries, registers, ...), but P4 config is preserved.
    controller.reset_state()

    """
    In order to implement broadcast we'll use multicast groups.
    Create a multicast group for each ingress port on the switch,
    which contains all port IDs except the ingress port ID.
    """
    """
    mc_grp_id = 1 # 0 means no multicast, 1 to 2**16 are valid group IDs
    rid = 0 # Only valid in the egress pipeline and read only. Used to uniquely identify multicast copies of the same ingress packet.
    for ingress_port in SWITCH_PORTS:
        port_list = SWITCH_PORTS[:]
        # Delete ingress port from list of all switch ports
        del(port_list[port_list.index(ingress_port)])
        # Add a new multicast group
        controller.mc_mgrp_create(mc_grp_id)
        # Add multicast node group
        handle = controller.mc_node_create(rid, port_list)
        # Associate with mc grp
        controller.mc_node_associate(mc_grp_id, handle)
        # Fill broadcast table
        controller.table_add("broadcast", "set_mcast_grp", [str(ingress_port)], [str(mc_grp_id)])
        mc_grp_id +=1
        rid +=1
    """

    if not digest:
        print(f"Creating mirror port with ID {CPU_MIRROR_PORT_ID} on interface {CPU_MIRROR_PORT}")
        controller.mirroring_add(mirror_id=CPU_MIRROR_PORT_ID, egress_port=CPU_MIRROR_PORT_ID)

        print(f"Setting default action on table {MAC_TABLE} to {ACTION_CONE_BROADCAST}")
        controller.table_set_default(table_name=MAC_TABLE, action_name=ACTION_CONE_BROADCAST, action_params=["1"])

        print(f"Going to sniff for CPU punted frames of {CPU_MIRROR_PORT}")
        sniff(iface=CPU_MIRROR_PORT, prn=recv_frame_cpu)
