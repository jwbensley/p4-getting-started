#!/usr/bin/env python3

import argparse
import logging
import pynng
import struct
import sys
import time
from typing import Any
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

class Settings:
    ACTION_SET_ADJ = "set_adj"
    ACTION_SET_NEXT_HOP = "set_next_hop"
    CONTROLLER: SimpleSwitchThriftAPI
    COUNTER_INGRESS = "ingressPackets"
    COUNTER_EGRESS = "egressPackets"
    LOGGING_FORMAT = "%(asctime)s|%(levelname)s|%(process)d|%(funcName)s|%(message)s"
    SWITCH_PORTS = {
        1: {
            0: {
                "subnet": "fd::/64",
                "ip": "fd::1",
                "mac": "00:00:00:00:00:01",
            },
            1: {
                "subnet": "fd:0:0:1::/64",
                "ip": "fd:0:0:1::1",
                "mac": "00:00:00:00:01:01"
            },
            2: {
                "subnet": "fd:0:0:ff::/64",
                "ip": "fd:0:0:ff::1",
                "mac": "00:00:00:00:FF:01"
            }
        },
        2: {
            0: {
                "subnet": "fd:0:0:ff::/64",
                "ip": "fd:0:0:ff::2",
                "mac": "00:00:00:00:FF:02"
            },
            1: {
                "subnet": "fd:0:0:2::/64",
                "ip": "fd:0:0:2::1",
                "mac": "00:00:00:00:02:01"
            },
        }
    }
    READ_COUNTERS = False
    SWITCH = 1
    TABLE_ROUTES="ipv6_routes"
    TABLE_ADJ="adjacencies"
    THRIFT_PORT = "909"
    THRIFT_IP = "localhost"

logging.basicConfig(
    format=Settings.LOGGING_FORMAT,
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)

def learn_via_digest_loop() -> None:
    logger.info(f"Setting default action on table {Settings.TABLE_SRC_MACS} to {Settings.ACTION_LEARN_VIA_DIGEST}")
    Settings.CONTROLLER.table_set_default(table_name=Settings.TABLE_SRC_MACS, action_name=Settings.ACTION_LEARN_VIA_DIGEST)

    logger.info(f"Going to listen for CPU digest messages")
    """
    Settings.CONTROLLER.client has type "bm_runtime.standard.Standard.Client"
    Settings.CONTROLLER.client.bm_mgmt_get_info() returns type "bm_runtime.standard.ttypes.BmConfig".

    bm_runtime are C bindings: https://github.com/p4lang/behavioral-model/blob/main/include/bm/bm_runtime/
    """
    socket_address: str = Settings.CONTROLLER.client.bm_mgmt_get_info().notifications_socket

    # Open a nano message subscription (the P4 device is the publisher)
    with pynng.Sub0() as socket:
        socket.subscribe("")
        socket.dial(socket_address)
        while True:
            """
            block=False prevents CTRL+C from caught and the program can't
            be stopped.
            Time.sleep(0) helps to create an infinite loop which doesn't pin
            one of the CPU cores at 100%.
            """
            try:
                msg: bytes = socket.recv(block=False)
            except pynng.TryAgain:
                time.sleep(0)
                continue
                
            """
            Binary messages are received which have to be unpacked.
            Multiple P4 "digest" messages can be grouped into a single nano message.
            The "headers" of the nano message are 32 bytes long.
            """
            starting_index = 32
            topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi", msg[:starting_index])
            logger.info(f"New digest nano message received with {num} digest message(s): {msg}")

            for idx in range(num):
                """
                A 6 byte MAC + 2 byte port ID are sent in from the data plane in the digest message.
                unpack() can't unpack that so we'll have to do it manually.
                """
                src_mac = int.from_bytes(msg[starting_index:starting_index+6], "big")
                starting_index += 6
                ingress_port = int.from_bytes(msg[starting_index:starting_index+2], "big")
                starting_index += 2

                print(f"Digest message {idx} contains src_mac: {src_mac}, ingress_port: {ingress_port}")
                update_mac_tables(ingress_port, src_mac)

            # Acknowledge digest
            Settings.CONTROLLER.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

def parse_args() ->  dict[str, Any]:
    parser = argparse.ArgumentParser(
        description="P4 Control Plane",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--counters",
        help="Print ingress and egress packet counters.",
        default=False,
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--switch2",
        help="The control plane shall connect to switch2. "
        "By default it connects to switch1.",
        default=False,
        action="store_true",
        required=False,
    )
    args = vars(parser.parse_args())

    if args["counters"]:
        Settings.READ_COUNTERS = True
    if args["switch2"]:
        Settings.SWITCH = 2

    return args

def populate_tables() -> None:
    Settings.CONTROLLER.table_add()

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

    thrift_port = int(Settings.THRIFT_PORT + str(Settings.SWITCH))
    Settings.CONTROLLER = SimpleSwitchThriftAPI(thrift_port=thrift_port, thrift_ip=Settings.THRIFT_IP)

    if Settings.READ_COUNTERS:
        read_counters()

    # Resets all state in the switch
    Settings.CONTROLLER.reset_state()

    logger.info(f"Going to populate route and adjacency tables...")
    populate_tables()
    learn_via_digest_loop()
