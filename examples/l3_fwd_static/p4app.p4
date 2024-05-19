#include <core.p4>
#include <v1model.p4>

typedef bit<9>   PortId_t;
typedef bit<48>  MacAddr_t;
typedef bit<128> IpV6Addr;

header ethernet_t {
    MacAddr_t    dstMac;
    MacAddr_t    srcMac;
    bit<16>      etherType;
}

const bit<16> ETHERTYPE_IPV6  = 0x86dd;

header ipv6_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_length;
    bit<8>   next_header;
    bit<8>   hop_limit;
    IpV6Addr srcAddr;
    IpV6Addr dstAddr;
}

const bit<8>  IP_PROTO_ICMPV6 = 58;

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
    bit<32>  reserved;
    bit<128> target;
}

const bit<8> ICMPV6_CODE_ECHO_REQ = 0;
const bit<8> ICMPV6_TYPE_ECHO_REQ = 128;
const bit<8> ICMPV6_CODE_ECHO_REP = 0;
const bit<8> ICMPV6_TYPE_ECHO_REP = 129;
const bit<8> ICMPV6_TYPE_NEI_SOL = 135;
const bit<8> ICMPV6_CODE_NEI_SOL = 0;
const bit<8> ICMPV6_TYPE_NEI_ADV = 136;
const bit<8> ICMPV6_CODE_NEI_ADV = 0;

struct headers {
    ethernet_t ethernet;
    ipv6_t     ipv6;
    icmpv6_t   icmpv6;
}

struct metadata {
    IpV6Addr adj_ip;
    PortId_t egress_port;
}

error {
    NotIpV6
}

const bit<8> T_SEND_NEI_SOL = 0;
const bit<8> T_RECV_NEI_ADV = 1;
const bit<8> T_RECV_NEI_SOL = 2;

struct digest_t {
    bit<8>    type;
    MacAddr_t mac;
    PortId_t  ingressPort;
    IpV6Addr  addr;
}

const bit<9> DROP_PORT = 511;

counter(256, CounterType.packets) ingressPackets;
counter(256, CounterType.packets) egressPackets;

parser IngressParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        log_msg("Parsed Ethernet header {}", {hdr.ethernet});
        transition select (hdr.ethernet.etherType) {
            ETHERTYPE_IPV6: parse_ipv6;
            default: parse_bad;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        log_msg("Parsed IPv6 header {}", {hdr.ipv6});

        transition select (hdr.ipv6.next_header) {
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }

    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        log_msg("Parsed ICMPv6 header {}", {hdr.icmpv6});
        transition accept;
    }

    state parse_bad {
        /* verify() comes from core.p4 */
        verify(false, error.NotIpV6);
        /* log_msg() comes from BMV2/v1model.py */
        log_msg("Dropping non-IPv6 payload frame");
        /*
          Explicit transition to reject not supported on BMv2.
          If the code reaches this point we hit implicit reject anyway.
        */
        //transition reject;
    }
}

control IngressChecksum(inout headers hdr, inout metadata meta) {
    apply {
        /*
        verify_checksum() is BMV2/v1model.p4 specific.

        This example is IPv6 only. IPv6 has no checksum.
        We could implement a checksum for Ethernet instead but that isn't
        supported either because BMV2 doesn't suppport performing CRC32 for
        Ethernet. This is because verify_checksum() needs the expected value
        to check it calculates the same value as the expected value.
        BMV2 doesn't have visibility of the original CRC from the ingress frame,
        so we can't give that as the expected value, therefor checksuming not
        possible with BMV2.
        */

        /*
        verify_checksum(
            true,
            { hdr.ethernet.dstMac, hdr.ethernet.srcMac, hdr.ethernet.etherType, hdr.ethernet.payload },
            ????,
            HashAlgorithm.crc32
        );
        */
    }
}

control IngressProcess(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {    
        /*
        Set the egress port ID to a reserved DROP_PORT ID, this is the last
        port ID on BMV2 511 (BMV2 supports ports 0-511):
        https://github.com/p4lang/behavioral-model/blob/8e183a39b372cb9dc563e9d0cf593323249cd88b/targets/simple_switch/bm/simple_switch/runner.h#L39
        */
        mark_to_drop(standard_metadata);
    }

    action send_nei_sol() {
        /*
        Signal the control-plane to send send a neigh disc solicit for this IP
        address, data-plane is missing the MAC address.

        If the dst IP is a directly connected subnet, we need to send a neighbor
        solicit for the dest IP in the packet, if it is indirectly connected
        (via a next-hop), we need to solicit for the next-hop IP MAC address.

        During route lookup, meta.adj_ip was set to either the dst IP if it is
        a locally connected subnet, or the next-hop IP if it is a remote subnet.
        */
        digest<digest_t>(0, {T_SEND_NEI_SOL, 0, 511, meta.adj_ip});
    }

    action recv_nei_sol() {
        /*
        Signal the control-plane to process the data from a received neigh disc
        solicit message.
        */
        digest<digest_t>(0, {T_RECV_NEI_SOL, hdr.ethernet.srcMac, standard_metadata.ingress_port, hdr.ipv6.srcAddr});
        // Drop the packet so that it is not forwarded.
        standard_metadata.egress_spec = DROP_PORT;
    }

    action recv_nei_adv() {
        /*
        Signal the control-plane to process the data from a received neigh disc
        adv message.
        */
        digest<digest_t>(0, {T_RECV_NEI_ADV, hdr.ethernet.srcMac, standard_metadata.ingress_port, hdr.ipv6.srcAddr});
        // Drop the packet so that it is not forwarded.
        standard_metadata.egress_spec = DROP_PORT;
    }

    action set_adj(IpV6Addr nextHop, PortId_t egress_port) {
        if (nextHop == 0) {
            // Destination is reachable via locally connected subnet/interface
            meta.adj_ip = hdr.ipv6.dstAddr;
            meta.egress_port = egress_port;
        } else {
            // Destination is reachable via a next-hop IP/device
            meta.adj_ip = nextHop;
        }
    }

    action egress_l2_rewrite(PortId_t egress_port, MacAddr_t dstMac, MacAddr_t srcMac) {
        standard_metadata.egress_spec = egress_port;
        hdr.ethernet.dstMac = dstMac;
        hdr.ethernet.srcMac = srcMac;
    }

    action set_egress_port(PortId_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    /*
    Packets which are CPU injected into the data plane with have
    a local IP, this table returns the interface ID out of which the
    packet will be forwarded. This is because it's not possible to
    inject a packet from control-plane into the data plane with metadata
    such as egress port, so data-plane lookup is requirded.

    Table miss means destination is not directly connected.
    Table hit means destination is directly connect.

    A hit returns the egress port ID to forward the packet out of.
    A miss does nothing because this wasn't a CPU injected port.
    */
    table from_local_ip {
        key = {
            hdr.ipv6.srcAddr: exact;
        }
        actions = {
            set_egress_port;
            NoAction;
        }
        default_action = NoAction();
        size = 256;
    }

    /*
    Table miss means no route to destination.
    Table hit means route to destination.

    Two types of routes are stored, those which point to a local port,
    and those which point to a next hop.

    Routes which point to a next-hop return the next-hop IP.
    Routes which point to a directly attached subnet return 0.
    In the later case, the next-hop *is* the destination IP.
    */
    table ipv6_routes {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            set_adj;
            drop;
        }
        default_action = drop();
        size = 256;
    }

    /*
    Adjacencies are stored as /128s.
    Each adjacency is an egress port ID, dst MAC, and src MAC.

    A table hit means the adjacency is known (either via a next-hop or via
    a directly attached adj).
    A miss means we need to send a neighbour solicitation for a directly
    attached subnet.
    */
    table ipv6_adj {
        key = {
            meta.adj_ip: exact;
        }
        actions = {
            egress_l2_rewrite;
            send_nei_sol;
        }
        default_action = send_nei_sol();
        size = 256;
    }

    apply {
        ingressPackets.count((bit<32>)standard_metadata.ingress_port);

        /* This would be terrible for performance in production but handy for debugging */
        if (
            hdr.icmpv6.type == ICMPV6_TYPE_ECHO_REQ &&
            hdr.icmpv6.code == ICMPV6_CODE_ECHO_REQ
        ) {
            log_msg("Packet is ICMPv6 echo request to {}", {hdr.ipv6.dstAddr});
        } else if (
            hdr.icmpv6.type == ICMPV6_TYPE_ECHO_REP &&
            hdr.icmpv6.code == ICMPV6_CODE_ECHO_REP
        ) {
            log_msg("Packet is ICMPv6 echo reply from {}", {hdr.ipv6.srcAddr});
        } else if (
            hdr.icmpv6.type == ICMPV6_TYPE_NEI_SOL &&
            hdr.icmpv6.code == ICMPV6_CODE_NEI_SOL
        ) {
            log_msg("Packet is ICMPv6 neighbour discovery soliciation for {}", {hdr.icmpv6.target});
        } else if (
            hdr.icmpv6.type == ICMPV6_TYPE_NEI_ADV &&
            hdr.icmpv6.code == ICMPV6_CODE_NEI_ADV
        ) {
            log_msg("Packet is ICMPv6 neighbour discovery advertisement from {}", {hdr.icmpv6.target});
        }


        // If forwarding a control-plane injected packet, skip further processing
        if ( from_local_ip.apply().hit) {
            exit;
        }

        if (
            hdr.icmpv6.type == ICMPV6_TYPE_NEI_SOL &&
            hdr.icmpv6.code == ICMPV6_CODE_NEI_SOL
        ) {
            /*
            If receiving a neighbour discovery solicit message, punt to control-plane
            */
            recv_nei_sol();
            exit;
        } else if (
            hdr.icmpv6.type == ICMPV6_TYPE_NEI_ADV &&
            hdr.icmpv6.code == ICMPV6_CODE_NEI_ADV
        ) {
            /*
            If receiving a neighbour advertisement, punt to control-plane
            */
            recv_nei_adv();
            exit;
        }

        /*
        For transit traffic;
        - Perform a route lookup:
        - - If result is an IP, that is a next-hop, lookup adj for next-hop IP
        - - If result is 0, dest IP is directly attached, lookup adj for dest IP
        */
        if (ipv6_routes.apply().hit) {
            if (!ipv6_adj.apply().hit) {
                // Drop if no adjacency found, otherwise packet is default forwarded out of ingress port
                drop();
            }
        }
    }
}

control EgressProcess(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        egressPackets.count((bit<32>)standard_metadata.egress_spec);
    }
}

control EgressChecksumCompute(inout headers hdr, inout metadata meta) {
     apply {
        /*
        No checksum to compute for IPv6.
        BMV2 can't compute Ethernet checksum.
        */
     }
}

control EgressDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.icmpv6);
    }
}

V1Switch(
IngressParser(),
IngressChecksum(),
IngressProcess(),
EgressProcess(),
EgressChecksumCompute(),
EgressDeparser()
) main;
