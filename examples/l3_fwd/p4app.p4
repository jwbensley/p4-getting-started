#include <core.p4>
#include <v1model.p4>

typedef bit<9>   PortId_t;
typedef bit<48>  MacAddr_t;
typedef bit<128> IpV6Addr;

header ethernet_t {
    MacAddr_t    dstMac;
    MacAddr_t    srcMac;
    bit<16>      etherType;
    // varbit<1500> payload; // Only needed for Ethernet checksum
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
}

const bit<8> ICMPV6_TYPE_NEI_ADV = 136;
const bit<8> ICMPV6_CODE_NEI_ADV = 0;

struct headers {
    ethernet_t ethernet;
    ipv6_t     ipv6;
    icmpv6_t   icmpv6;
}

struct metadata {
    IpV6Addr adj_key;
    PortId_t egress_port;
}

error {
    NotIpV6
}

struct digest_t {
    MacAddr_t mac;
    PortId_t  ingressPort;
    IpV6Addr  addr;
}

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
        transition select (hdr.ethernet.etherType) {
            ETHERTYPE_IPV6: parse_ipv6;
            default: parse_bad;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);

        transition select (hdr.ipv6.next_header) {
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }

    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition accept;
    }

    state parse_bad {
        /* verify() comes from core.p4 */
        verify(false, error.NotIpV6);
        /* log_msg() comes from BMV2/v1model.py */
        log_msg("Dropping non-IPv6 payload frame");
        transition reject;
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

    action send_nei_disc() {
        /*
        src_mac can't be 0, and ingress port can't be 511, so use these values
        to signal to the control-plane that this digest message only contains
        a IPv6 address. In this case it is the IP to send a nei disc request to.
        */
        //digest<digest_t>(0, {0, 511, hdr.ipv6.dstAddr});

        /*
        This will also set standard_metadata.instance_type to 1 on the cloned
        packet, so that it can be distinguished from the orginal packet at egress.
        */
        //standard_metadata.egress_spec = meta.egress_port
        clone_preserving_field_list(CloneType.I2E, (bit<32>)meta.egress_port, 0);
    }

    action recv_nei_adv() {
        /*
        When sending a control plane message with a value src_mac, ingress port,
        and IP addr, this combination implicitly tells the control plane this is
        a nei disc response.
        One could add a $message_type field to the digest message, to explicitly
        signal the purpose of the digest message payload to the control-plane,
        but there are many things one could do.
        */
        digest<digest_t>(0, {hdr.ethernet.srcMac, standard_metadata.ingress_port, hdr.ipv6.srcAddr});
    }

    action set_adj(IpV6Addr nextHop, PortId_t egress_port) {
        if (nextHop == 0) {
            meta.adj_key = hdr.ipv6.dstAddr;
            meta.egress_port = egress_port;
        } else {
            meta.adj_key = nextHop;
        }
    }

    action set_next_hop(PortId_t egress_port, MacAddr_t dstMac, MacAddr_t srcMac) {
        standard_metadata.egress_spec = egress_port;
        hdr.ethernet.dstMac = dstMac;
        hdr.ethernet.srcMac = srcMac;
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
            meta.adj_key: exact;
        }
        actions = {
            set_next_hop;
            send_nei_disc;
        }
        default_action = send_nei_disc();
        size = 256;
    }

    apply {
        ingressPackets.count((bit<32>)standard_metadata.ingress_port);

        /*
        If receiving a neighbour advertisement, punt to control-plane,
        then exit to avoid a fowarding plane lookup.
        */
        if (
            hdr.icmpv6.type == ICMPV6_TYPE_NEI_ADV &&
            hdr.icmpv6.code == ICMPV6_CODE_NEI_ADV
        ) {
            recv_nei_adv();
            exit;
        }

        /*
        For transit traffic;
        - Perform a route lookup:
        - - If result is an IP, that is a next-hop, lookup adj for next-hop IP
        - - If result is 0, dest IP is directly attached, lookup adj for dest IP
        */
        if (ipv6_routes.apply().hit()) {
            ipv6_adj.apply();
        }
    }

}

control EgressProcess(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // If this is a cloned packet:
        if (standard_metadata.instance_type == 1){
            // Re-write the packet to be an ICMPv6 nei disc solicit packet.
            /*
            hdr.etherne.dstMac= 
            hdr.etherne.srcMac = 
            hdr.etherne.etherType = 
            hdr.ipv6.version = 
            hdr.ipv6.traffic_class = 
            hdr.ipv6.flow_label = 
            hdr.ipv6.payload_length = 
            hdr.ipv6.next_header = 
            hdr.ipv6.hop_limit = 
            hdr.ipv6.srcAddr = 
            hdr.ipv6.dstAddr = 
            hdr.icmpv6.type = 
            hdr.icmpv6.code = 
            hdr.icmpv6.checksum =
            */ 
            truncate((bit<32>)14); // Size in bytes
            log_msg("Going to send frame with source MAC {}", {hdr.ethernet.srcAddr});
        } else {
                egressPackets.count((bit<32>)standard_metadata.egress_spec);
        }
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
