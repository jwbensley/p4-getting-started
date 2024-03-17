#!/usr/bin/env python3

import argparse
from typing import Any
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.layers.l2 import Ether  # type: ignore
from scapy.sendrecv import sniff  # type: ignore

class Settings:
    ACTION_FORWARD = "forward"
    ACTION_LEARN_VIA_CLONE = "learn_via_clone"
    ACTION_LEARN_VIA_DIGEST = "learn_via_digest"
    ACTION_NO_ACTION = "NoAction"
    CPU_MIRROR_PORT = "lo" # Interface on the Linux host to bind to simple switch port ID $CPU_MIRROR_PORT_ID
    CPU_MIRROR_PORT_ID = 100 # Port ID for CPU punted frames
    SWITCH_PORTS = [0, 1] # List of forwarding plane ports - must not include control-plane port, or drop port
    TABLE_SRC_MACS="src_macs"
    TABLE_DST_MACS="dst_macs"
    THRIFT_PORT = 9090
    THRIFT_IP = "localhost"


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

    for ingress_port in Settings.SWITCH_PORTS:
        port_list = Settings.SWITCH_PORTS[:]
        # Delete ingress port from list of all switch ports
        del(port_list[port_list.index(ingress_port)])
        # Add a new multicast group
        controller.mc_mgrp_create(mc_grp_id)
        # Add multicast node group
        handle = controller.mc_node_create(rid, port_list)
        # Associate with mc grp
        controller.mc_node_associate(mc_grp_id, handle)
        mc_grp_id +=1
        rid +=1

def learn_via_clone_loop() -> None:
    print(f"Creating mirror port with ID {Settings.CPU_MIRROR_PORT_ID} on interface {Settings.CPU_MIRROR_PORT}")
    controller.mirroring_add(mirror_id=Settings.CPU_MIRROR_PORT_ID, egress_port=Settings.CPU_MIRROR_PORT_ID)

    print(f"Setting default action on table {Settings.TABLE_SRC_MACS} to {Settings.ACTION_LEARN_VIA_CLONE}")
    controller.table_set_default(table_name=Settings.TABLE_SRC_MACS, action_name=Settings.ACTION_LEARN_VIA_CLONE)

    print(f"Going to sniff for CPU punted frames on interface {Settings.CPU_MIRROR_PORT}")
    sniff(iface=Settings.CPU_MIRROR_PORT, prn=process_cpu_frame)

def learn_via_digest_loop() -> None:
    print(f"Setting default action on table {Settings.TABLE_SRC_MACS} to {Settings.ACTION_LEARN_VIA_DIGEST}")
    controller.table_set_default(table_name=Settings.TABLE_SRC_MACS, action_name=Settings.ACTION_LEARN_VIA_DIGEST)

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
        required=False,
        default=Settings.CPU_MIRROR_PORT_ID,
    )
    parser.add_argument(
        "--int",
        help="Linux interface to listen for CPU punted packets.",
        type=str,
        required=False,
        default=Settings.CPU_MIRROR_PORT,
    )
    args = vars(parser.parse_args())

    if args["id"] != Settings.CPU_MIRROR_PORT_ID:
        Settings.CPU_MIRROR_PORT_ID = args["id"]
    if args["int"] != Settings.CPU_MIRROR_PORT:
        Settings.CPU_MIRROR_PORT = args["int"]

    return args

def process_cpu_frame(frame: Ether):
    src_mac = int.from_bytes(bytes(frame)[6:12], "big")
    ingress_port = int.from_bytes(bytes(frame)[12:15], "big")

    if ingress_port > 2**16:
        return ##################################################### What are these packets? CPU punting is using same interface as Thrift!

    handle = controller.get_handle_from_match(table_name=Settings.TABLE_SRC_MACS, match_keys=[str(ingress_port), str(src_mac)])
    if handle != None:
        print(f"Table entry already exists for ({ingress_port},{src_mac}) at handle {handle}")
    else:
        controller.table_add(table_name=Settings.TABLE_SRC_MACS, action_name=Settings.ACTION_NO_ACTION, match_keys=[str(ingress_port), str(src_mac)])
        controller.table_add(table_name=Settings.TABLE_DST_MACS, action_name=Settings.ACTION_FORWARD, match_keys=[str(src_mac)], action_params=[str(ingress_port)])
        print(f"Created table entry for MAC {src_mac} via port {ingress_port}")

if __name__ == "__main__":
    # Parse CLI args
    args = parse_args()

    controller = SimpleSwitchThriftAPI(thrift_port=Settings.THRIFT_PORT, thrift_ip=Settings.THRIFT_IP)

    # Resets all state in the switch
    controller.reset_state()

    """
    Broadcast can be implemented by using multicast groups.
    Create a multicast group for each ingress port on the switch,
    which contains all port IDs except the ingress port ID.
    """
    create_multicast_groups()

    if not args["digest"]:
        learn_via_clone_loop()
    else:
        learn_via_digest_loop()

