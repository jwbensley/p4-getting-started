#!/usr/bin/env python3

import argparse
import sys
from typing import Any
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16)]

CPU_MIRROR_PORT = "lo" # Interface on the Linux host to bind to simple switch port ID $CPU_MIRROR_PORT_ID
CPU_MIRROR_PORT_ID = 100 # Port ID for CPU punted frames
THRIFT_PORT = 9090
THRIFT_IP = "localhost"
SWITCH_PORTS = [0, 1] # List of forwarding plane ports - must not include control-plane port
MAC_TABLE="dmac"
ACTION_CLONE_BROADCAST = "learn_mac_via_clone_and_broadcast"

def create_multicast_groups() -> None:
    """
    Multicast group 0 means no multicast.
    Group IDs 1 to 2**16 are valid multicast group IDs.
    Port indexes start at 0 meaning the multicast group for a port is always
    PortID + 1
    """
    mc_grp_id = 1

    """
    Only valid in the egress pipeline and read only.
    Used to uniquely identify multicast copies of the same ingress packet.
    """
    rid = 0

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
        controller.table_add("dmac", "set_mcast_grp", [str(ingress_port)], [str(mc_grp_id)])
        mc_grp_id +=1
        rid +=1

    print(f"Multicast data: {controller.mc_dump()}")

def parse_args() ->  dict[str, Any]:
    parser = argparse.ArgumentParser(
        description="P4 Control Plane",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--digest",
        help="Use digest messages to punt packet information to the "
        "control-plane. The default mode is to clone and punt whole packets.",
        default=False,
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--id",
        help="P4 switch interface ID of punted frames.",
        type=int,
        required=True,
        default=CPU_MIRROR_PORT_ID,
    )
    parser.add_argument(
        "--int",
        help="Linux interface to listen for CPU punted packets.",
        type=str,
        required=True,
        default=CPU_MIRROR_PORT,
    )
    return vars(parser.parse_args())

def process_cpu_frame(frame):
    print(f"Received type {type(frame)}")
    packet = Ether(raw(frame))
    print(f"Received packet {packet}")
    if packet.type == 0x1234:
        cpu_header = CpuHeader(bytes(packet.load))
        print(f"Learning MAC {cpu_header.macAddr:%012X} via port {cpu_header.ingress_port}")
        controller.table_add(MAC_TABLE, "learn_mac_via_clone_and_forward", [str(cpu_header.macAddr)], [str(cpu_header.ingress_port)])

if __name__ == "__main__":
    # Parse CLI args
    args = parse_args()

    controller = SimpleSwitchThriftAPI(thrift_port=THRIFT_PORT, thrift_ip=THRIFT_IP)

    # Resets all state in the switch (table entries, registers, ...), but P4 config is preserved.
    controller.reset_state()

    """
    Broadcast can be implemented by using multicast groups.
    Create a multicast group for each ingress port on the switch,
    which contains all port IDs except the ingress port ID.
    """
    create_multicast_groups()

    if not args["digest"]:
        print(f"Creating mirror port with ID {CPU_MIRROR_PORT_ID} on interface {CPU_MIRROR_PORT}")
        controller.mirroring_add(mirror_id=CPU_MIRROR_PORT_ID, egress_port=CPU_MIRROR_PORT_ID)

        print(f"Setting default action on table {MAC_TABLE} to {ACTION_CLONE_BROADCAST}")
        controller.table_set_default(table_name=MAC_TABLE, action_name=ACTION_CLONE_BROADCAST, action_params=["1"])

        print(f"Going to sniff for CPU punted frames on interface {CPU_MIRROR_PORT}")
        sniff(iface=CPU_MIRROR_PORT, prn=process_cpu_frame)
