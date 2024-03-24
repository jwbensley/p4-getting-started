#!/usr/bin/env python3

import argparse
import logging
import sys
from typing import Any
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.layers.l2 import Ether  # type: ignore
from scapy.sendrecv import sniff  # type: ignore

class Settings:
    ACTION_FORWARD = "forward"
    ACTION_LEARN_VIA_CLONE = "learn_via_clone"
    ACTION_LEARN_VIA_DIGEST = "learn_via_digest"
    ACTION_NO_ACTION = "NoAction"
    CONTROLLER: SimpleSwitchThriftAPI
    COUNTER_INGRESS = "ingressFrames"
    COUNTER_EGRESS = "egressFrames"
    CPU_MIRROR_PORT = "cpu" # Interface on the Linux host to bind to simple switch port ID $CPU_MIRROR_PORT_ID
    CPU_MIRROR_PORT_ID = 100 # Port ID for CPU punted frames
    LOGGING_FORMAT = "%(asctime)s|%(levelname)s|%(process)d|%(funcName)s|%(message)s"
    READ_COUNTERS = False
    SWITCH_PORTS = [0, 1] # List of forwarding plane ports - must not include control-plane port, or drop port
    TABLE_SRC_MACS="src_macs"
    TABLE_DST_MACS="dst_macs"
    THRIFT_PORT = 9090
    THRIFT_IP = "localhost"

logging.basicConfig(
    format=Settings.LOGGING_FORMAT,
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)


def create_multicast_groups() -> None:
    """
    Broadcast can be implemented by using multicast groups.
    Create a multicast group for each ingress port on the switch,
    which contains all port IDs except the ingress port ID.

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
        Settings.CONTROLLER.mc_mgrp_create(mc_grp_id)
        # Add multicast node group
        handle = Settings.CONTROLLER.mc_node_create(rid, port_list)
        # Associate with mc grp
        Settings.CONTROLLER.mc_node_associate(mc_grp_id, handle)
        mc_grp_id +=1
        rid +=1
    
    logger.info(f"Dumping switch multicast tables...")
    Settings.CONTROLLER.mc_dump()

def learn_via_clone_loop() -> None:
    logger.info(f"Creating mirror port with ID {Settings.CPU_MIRROR_PORT_ID} on interface {Settings.CPU_MIRROR_PORT}")
    Settings.CONTROLLER.mirroring_add(mirror_id=Settings.CPU_MIRROR_PORT_ID, egress_port=Settings.CPU_MIRROR_PORT_ID)

    logger.info(f"Setting default action on table {Settings.TABLE_SRC_MACS} to {Settings.ACTION_LEARN_VIA_CLONE}")
    Settings.CONTROLLER.table_set_default(table_name=Settings.TABLE_SRC_MACS, action_name=Settings.ACTION_LEARN_VIA_CLONE)

    logger.info(f"Going to sniff for CPU punted frames on interface {Settings.CPU_MIRROR_PORT}")
    sniff(iface=Settings.CPU_MIRROR_PORT, prn=process_cpu_frame)

def learn_via_digest_loop() -> None:
    logger.info(f"Setting default action on table {Settings.TABLE_SRC_MACS} to {Settings.ACTION_LEARN_VIA_DIGEST}")
    Settings.CONTROLLER.table_set_default(table_name=Settings.TABLE_SRC_MACS, action_name=Settings.ACTION_LEARN_VIA_DIGEST)

def parse_args() ->  dict[str, Any]:
    parser = argparse.ArgumentParser(
        description="P4 Control Plane",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--counters",
        help="Print ingress and egress frame counters",
        default=False,
        action="store_true",
        required=False,
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

    if args["counters"]:
        Settings.READ_COUNTERS = True
    if args["id"] != Settings.CPU_MIRROR_PORT_ID:
        Settings.CPU_MIRROR_PORT_ID = args["id"]
    if args["int"] != Settings.CPU_MIRROR_PORT:
        Settings.CPU_MIRROR_PORT = args["int"]

    return args

def process_cpu_frame(frame: Ether):
    src_mac = int.from_bytes(bytes(frame)[6:12], "big")
    ingress_port = int.from_bytes(bytes(frame)[12:15], "big")

    logger.info(
        f"New CPU punted frame with source MAC {src_mac}, ingress port "
        f"{ingress_port}: {bytes(frame)}"
    )

    update_mac_tables(ingress_port, src_mac)

def update_mac_tables(ingress_port: int, src_mac: int) -> None:
    """
    A frame is punted because the source MAC wasn't matched in Settings.TABLE_SRC_MACS.
    This will happen for one of two reasons:
    * This source MAC hasn't been seen before
    * The MAC has moved to a different port
    
    Check if this MAC is known via any port at all
    """
    for port_id in Settings.SWITCH_PORTS:
        src_handle = Settings.CONTROLLER.get_handle_from_match(table_name=Settings.TABLE_SRC_MACS, match_keys=[str(port_id), str(src_mac)])
        dst_handle = Settings.CONTROLLER.get_handle_from_match(table_name=Settings.TABLE_DST_MACS, match_keys=[str(src_mac)])
        if src_handle != None:
            # This is a MAC move so delete the existing entry
            logger.info(f"Table entry already exists for ({ingress_port},{src_mac}) "
                        f"at handle {src_handle} in {Settings.TABLE_SRC_MACS}")
            Settings.CONTROLLER.table_delete(table_name=Settings.TABLE_SRC_MACS, entry_handle=src_handle)
            logger.info(f"Deleted entry {src_handle} from table {Settings.TABLE_SRC_MACS}")

        if dst_handle != None:
            logger.info(f"Table entry already exists for ({src_mac}) at handle "
                        f"{dst_handle} in {Settings.TABLE_DST_MACS}")
            Settings.CONTROLLER.table_delete(table_name=Settings.TABLE_DST_MACS, entry_handle=dst_handle)
            logger.info(f"Deleted entry {dst_handle} from table {Settings.TABLE_DST_MACS}")

    # Add an entry for this MAC via the ingress port to the source MAC table, to stop any further CPU punting
    Settings.CONTROLLER.table_add(table_name=Settings.TABLE_SRC_MACS, action_name=Settings.ACTION_NO_ACTION, match_keys=[str(ingress_port), str(src_mac)])
    # Add an entry for this MAC via the ingress port to the destination MAC table, for normal forwarding
    Settings.CONTROLLER.table_add(table_name=Settings.TABLE_DST_MACS, action_name=Settings.ACTION_FORWARD, match_keys=[str(src_mac)], action_params=[str(ingress_port)])
    logger.info(f"Created table entries for MAC {src_mac} via port {ingress_port}")

def read_counters() -> None:
    for port_id in Settings.SWITCH_PORTS:
        Settings.CONTROLLER.counter_read(counter_name=Settings.COUNTER_INGRESS, index=port_id)
        Settings.CONTROLLER.counter_read(counter_name=Settings.COUNTER_EGRESS, index=port_id)
    sys.exit(0)

if __name__ == "__main__":
    # Parse CLI args
    args = parse_args()

    Settings.CONTROLLER = SimpleSwitchThriftAPI(thrift_port=Settings.THRIFT_PORT, thrift_ip=Settings.THRIFT_IP)

    if Settings.READ_COUNTERS:
        read_counters()

    # Resets all state in the switch
    Settings.CONTROLLER.reset_state()

    # Create the multicast groups used for broadcast
    create_multicast_groups()

    if not args["digest"]:
        logger.info(f"Initiating MAC address learning via clone method...")
        learn_via_clone_loop()
    else:
        logger.info(f"Initiating MAC address learning via digest method...")
        learn_via_digest_loop()
