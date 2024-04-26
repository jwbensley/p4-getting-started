#!/usr/bin/env python3

import argparse
import logging
import ipaddress
import pynng
import struct
import sys
import time
from typing import Any
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.data import ETH_P_IPV6
from scapy.layers.l2 import Ether  # type: ignore
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS  # type: ignore
from scapy.sendrecv import sendp  # type: ignore

class Settings:
    ACTION_SET_ADJ = "set_adj"
    ACTION_SET_NEXT_HOP = "set_next_hop"
    CONTROLLER: SimpleSwitchThriftAPI
    COUNTER_INGRESS = "ingressPackets"
    COUNTER_EGRESS = "egressPackets"
    CPU_INJECT_INTT = "cpu" # Linux interface control-plane inject packets are sent on
    LOGGING_FORMAT = "%(asctime)s|%(levelname)s|%(process)d|%(funcName)s|%(message)s"
    READ_COUNTERS = False
    SWITCH = 0 # Default switch the contron plane connects to, 0-indexed
    SWITCH_PORTS = { # { switch_id: { port_id: { port_data } }
        0: {
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
        1: {
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
    TABLE_ROUTES="ipv6_routes"
    TABLE_ADJ="ipv6_adj"
    THRIFT_PORT = "909" # Switch ID is appended to this
    THRIFT_IP = "127.0.0.1"

logging.basicConfig(
    format=Settings.LOGGING_FORMAT,
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)

def learn_via_digest_loop() -> None:
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
            block=False prevents CTRL+C from being caught and the program can't
            be stopped.

            time.sleep(0) is a hack to create an infinite loop which doesn't pin
            one of the CPU cores at 100% and allows CTRL+C to work.
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
                A 6 byte MAC + 2 byte port ID + 8 byte IPv6 address are sent
                from the data plane in the digest message.
                unpack() can't unpack on boundtries like 6 bytes, so we'll have
                to do it manually.
                """
                src_mac = int.from_bytes(msg[starting_index:starting_index+6], "big")
                starting_index += 6
                ingress_port = int.from_bytes(msg[starting_index:starting_index+2], "big")
                starting_index += 2
                ip = int.from_bytes(msg[starting_index:starting_index+8], "big")
                starting_index += 8
                ipv6_addr = str(ipaddress.ip_address(ip))

                logger.info(f"Digest message {idx} contains src_mac: {src_mac}, ingress_port: {ingress_port}, ip: {ipv6_addr}")
                if src_mac == 0 and ingress_port == 511:
                    logger.info(f"Going to send neighbour discovery solicitation")
                    send_nei_disc_sol(ipv6_addr)
                else:
                    logger.info(f"Going to process neighbour discovery advertisement")
                    process_nei_disc_adv(src_mac, ingress_port, ipv6_addr)

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
        Settings.SWITCH = 1 # Zero indexed

    return args

def port_id_from_ip(ipv6_addr: str) -> int:
    for port_id, port_config in Settings.SWITCH_PORTS[Settings.SWITCH].items():
        if ipv6_addr in ipaddress.ip_network(port_config["subnet"]):
            logger.info(f"Returning port ID {port_id} for IP address {ipv6_addr}")
            return port_id
    else:
        """
        The forwarding plane should drop packets to unknown destination IPs.
        This means this function should never be called for an unknown dest IP.
        If there is a chance the forwarding plane and control plane routing tables
        can be out of sync, this check needs to be made in the control plane too.
        """
        logger.error(f"No local subnet found for IP address {ipv6_addr}")
    return -1

def port_ip_from_id(port_id: int) -> str:
    return Settings.SWITCH_PORTS[Settings.SWITCH][port_id]["ip"]

def port_mac_from_id(port_id: int) -> str:
    return Settings.SWITCH_PORTS[Settings.SWITCH][port_id]["mac"]

def port_subnet_from_id(port_id: int) -> str:
    return Settings.SWITCH_PORTS[Settings.SWITCH][port_id]["subnet"]

def populate_tables() -> None:
    """
    Add the local subnets and egress interface ID, the switch is directly
    connected to, to the IPv6 RIB
    """
    for port_id in Settings.SWITCH_PORTS[Settings.SWITCH].keys():
        # For some mad reason we have to provide the IPv6 prefix as a decimal integer with CIDR mask, as a string :D
        subnet = port_subnet_from_id(port_id)
        ip = port_ip_from_id(port_id)
        prefix = str(int(ipaddress.ip_address(ip))) + "/" + subnet.split("/")[-1]

        # Insert local subnet -> (next_hop_ip(0), egress_port_id(port_id))
        logger.info(f"Addeding local subnet {prefix} to switch {Settings.SWITCH} via port {port_id}")
        Settings.CONTROLLER.table_add(table_name=Settings.TABLE_ROUTES, action_name=Settings.ACTION_SET_ADJ, match_keys=[prefix], action_params=["0", str(port_id)])

def process_nei_disc_adv(src_mac: int, ingress_port: int, ipv6_addr: str) -> None:
    ...

def send_nei_disc_sol(ipv6_addr: str) -> None:
    last_32_bits = hex(int(ipv6_addr) & 0xffffffff).strip("0x")

    egr_port_id = port_id_from_ip(ipv6_addr)
    if egr_port_id == -1:
        logger.error(f"Unable to send neighbor solicitation to {ipv6_addr}, no local subnet")
        return

    src_mac = port_mac_from_id(egr_port_id)
    dst_mac = "33:33:"  +  last_32_bits[0:2] + ":" + last_32_bits[2:4] + ":" + last_32_bits[4:6] + ":" + last_32_bits[6:8]

    src_ip = port_ip_from_id(egr_port_id)
    dst_ip = "ff02::1:ff" + last_32_bits[2:4] + ":" + last_32_bits[4:8]

    pkt = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IPV6) / IPv6(src=src_ip, dst=dst_ip) / ICMPv6ND_NS(tgt="")
    logger.info(f"Injecting packet: {pkt}")
    sendp(pkt, iface=Settings.CPU_INJECT_INTT)

def read_counters() -> None:
    for port_id in Settings.SWITCH_PORTS:
        Settings.CONTROLLER.counter_read(counter_name=Settings.COUNTER_INGRESS, index=port_id)
        Settings.CONTROLLER.counter_read(counter_name=Settings.COUNTER_EGRESS, index=port_id)

if __name__ == "__main__":
    # Parse CLI args
    args = parse_args()

    thrift_port = int(Settings.THRIFT_PORT + str(Settings.SWITCH))
    logger.info(f"Connecting to switch {Settings.SWITCH} at {Settings.THRIFT_IP}:{thrift_port}")
    Settings.CONTROLLER = SimpleSwitchThriftAPI(thrift_port=thrift_port, thrift_ip=Settings.THRIFT_IP)

    if Settings.READ_COUNTERS:
        read_counters()
        sys.exit(0)

    # Resets all state in the switch
    Settings.CONTROLLER.reset_state()

    logger.info(f"Going to populate route and adjacency tables...")
    populate_tables()
    #learn_via_digest_loop()