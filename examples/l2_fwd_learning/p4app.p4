#include <core.p4>
#include <v1model.p4>

/* MAC address */
typedef bit<48> MacAddr_t;
/* Multicast group (used for broadcasting) */
typedef bit<16> McastGrp_t;

/*
Define an Ethernet header as having two MAC addresses.
For the sake fo this example we don't care about the rest of the header.
*/
header ethernet_t {
    MacAddr_t dstAddr;
    MacAddr_t srcAddr;
}

/* The stack of all headers the ingress parser will need to parse */
struct headers {
    ethernet_t ethernet;
}

/*
Defining this is a hard requirement.
Per-packet user defined metadata can be defined here.
*/
struct metadata {   
}

/* Define the message payload send to the control-plane for MAC learning. */
struct digest_t {
    MacAddr_t srcAddr;
    PortId_t ingressPort;
}

/*
Count the number of packets received across all ports.

Counters can be writen to by the P4 data plane programe but only read by the control plane.
For read+write from the data plane, use P4 registers.

To do this, create an array of counters ("index counter"), one per port.
The array size is $PortId_T (indexed [0, size-1]) .
Each counter in the array is 32 bits long, and is used for storing a packet count (as opposed to a byte count).

Calling counter.count($i) increments the counter at index $i by 1.
*/
counter<PortId_t>(32, CounterType.packets) ingressFrames;

/* Count the number of packets transmitted across all ports */
counter<PortId_t>(32, CounterType.packets) egressFrames;


/* An ingress parser is required */
parser IngressParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        /*
        Extract a fixed sized header from a packet and store it in hdr,
        this is defined in core.p4.
        */
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

/* Ingress checksum verification is required */
control IngressChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/* Ingress processing is required */
control IngressProcess(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* Define a function instead of calling NoAction() to have a counter */
    action drop() {    
        mark_to_drop(standard_metadata);
    }

    /* CPU punt and learn a new MAC if it is unknown */
    action learn_mac() {
        /*
        A digest is one mechanism to send a message from the data plane to the control plane.
        This is defined by the target architecture.
        In the case of this software switch example, in v1model.p4.
        */
        digest<digest_t>(0, {hdr.ethernet.srcAddr, standard_metadata.ingress_port});
    }

    /* Forward a frame to an egress Port ID */
    /*
    Action parameters that have no direction indicate "action data."
    All such parameters must appear at the end of the parameter list.
    When used in a match-action table, these parameters will be provided by the table entries
    (e.g., as specified by the control plane, the default_action table property, or the entries table property) 
    */
    action l2_forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    /* Broadcast a frame */
    action L2_broadcast(McastGrp_t mgrp) {
        standard_metadata.mcast_grp = mgrp;
    }

    table smac {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            learn_mac;
            NoAction;
        }
        const default_action = learn_mac();
        size = 4096;
        support_timeout = true;
    }
    table dmac {
        /* key: An expression that describes how the key used for look-up is computed. */
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        /* actions: A list of all actions that may be found in the table. */
        actions = {
            fwd;
            broadcast;
        }
        /* default_action: an action to execute when the lookup in the lookup table fails to find a match for the key used. */
        default_action = drop();
        size = 4096;
    }
    apply {
        ingressFrames.count(standard_metadata.ingress_port);
        smac.apply();
        dmac.apply();
    }
}

/* Egress processing is required */
control EgressProcess(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.egress_port == standard_metadata.ingress_port) {
            mark_to_drop(standard_metadata);
        } else {
            egressFrames.count(standard_metadata.egress_port);
        }
    }
}

/* Egress checksum calculation is required */
control EgressChecksumCompute(inout headers hdr, inout metadata meta) {
     apply { }
}

/* Deparser is required */
control EgressDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

// Each of these steps are hard required by the v1 model
V1Switch(
IngressParser(),
IngressChecksum(),
IngressProcess(),
EgressProcess(),
EgressChecksumCompute(),
EgressDeparser()
) main;
