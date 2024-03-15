#include <core.p4>
#include <v1model.p4>

/* MAC address */
typedef bit<48> MacAddr_t;
/* Multicast group (used for broadcasting) */
typedef bit<16> McastGrp_t;
/* ingress or egress port ID */
typedef bit<9> PortId_t;
/*
Port ID for CPU punted frames.

The same ID has to be specified when starting the software switch,
to bind this swith port to an interface on Linux. The switch will punt frames
to this interface ID. The control-plane listens on the corresponding Linux
interface for the punted frames:

simple_switch -i 100@lo
control_plane.py -i 100

The control plane will configure a mirror port
*/
const PortId_t CPU_PORT_ID = 100;

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
    /*
    When using the clone packet punt method (as opposed to the digest method)
    the user defined meta data is also sent to the CPU, along with the frame.
    */
    @field_list(0)
    PortId_t ingress_port;
}

/* Define the message payload sent to the control-plane for MAC learning. */
struct digest_t {
    MacAddr_t srcAddr;
    PortId_t ingressPort;
}

/*
Count the number of packets received across all ports.

Counters can be writen to by the P4 data plane programe but only read by the control plane.
For read+write from the data plane, use P4 registers.

An array of counters ("indexed counter") is created, one per port.
The array size is 256 (indexed [0, size-1]) .

Each counter in the array (in this case) is used for storing a packet counter
(as opposed to a byte count or mixed packet + byte count).

Calling counter.count($i) increments the counter at index $i by 1.
*/
counter(256, CounterType.packets) ingressFrames;

/* Count the number of packets transmitted across all ports */
counter(256, CounterType.packets) egressFrames;

/*
An ingress parser is required.

packet_in is defined in core.p4.

standard_metadata_t is defined in v1model.p4 and is architecture specific.
It defined the standard metadata the BMV2 software switch will provide per-packet
such as ingress_port ID, egress_port ID, mcast_grp, etc.
*/
parser IngressParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        /*
        Extract an Ethernet header from a packet and store it in hdr,
        this is defined in core.p4.

        If we didn't match an Ethernet header, the packet is dropped.
        */
        packet.extract(hdr.ethernet);
        /*
        log_msg() is defined by the simple switch architecture v1model.p4.
        Therefore, this is a platform specific logging function.
        Debug logging/printing is not a native function of P4.

        extern void log_msg(string msg);
        */
        log_msg("Parser is accepting frame received on ingress port ID {}", {standard_metadata.ingress_port});
        transition accept;
    }
}

/* Ingress checksum verification is required */
control IngressChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

/*
Ingress processing is required

Here, one or more actions are defined to apply to incoming frames.
One or more tables are also defined here. A lookup is made in a table to see
which action should be applied to the incoming frame.

Each row in the table will contain:
* a key (a MAC address in this case, which is used as the lookup/search value)
* the action function to call
* optionally, action data which is passed to the action

Actions can be executed in two ways:
Implicitly: by tables during match-action processing.
Explicitly: either from a control block or from another action.

In either case, the values for all action parameters must be supplied
explicitly, including values for the directionless parameters. In this case,
the directionless parameters behave like in parameters.
*/
control IngressProcess(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    /*
    An action to drop the frame.
    Define an explicit drop function (action) instead of calling NoAction() in
    order to have a counter of the number of dropped-at-ingress frames.
    */
    action drop() {    
        // Set the egress port ID to a reserved DROP_PORT ID.
        mark_to_drop(standard_metadata);
    }

    /*
    Forward a frame to an egress Port ID.

    Action parameters that have no direction indicate "action data."
    All such parameters must appear at the end of the parameter list.
    When used in a match-action table, these parameters will be provided by the
    table entries e.g., as specified by the control plane, the `default_action`
    table property, or the `entries` table property.
    */
    action l2_forward(PortId_t egress_port) {
        standard_metadata.egress_port = egress_port;
    }

    action broadcast() {
        /*
        Broadcast a frame.

        There is no native broadcast function in the simple switch, instead,
        any non-zero multicast group replicates the packet to all egress port IDs
        in the multicast group. These have to be configured by the control plane.
        The v1model.p4 standard_metadata field mcast_grp specifies 1 to 65,535
        multicast group id values.

        Set multicast group to the ingress port ID.
        The control will have created this group already, as a group of ports
        which contains all ports in the switch excet the ingress port.
        */
        standard_metadata.mcast_grp = (bit<16>)standard_metadata.ingress_port;
    }

    /*
    An action to CPU punt the frame (so that the CPU can program the MAC into
    the forwarding table).
    */
    action learn_mac_via_digest() {
        /*
        A digest is one mechanism to send a message from the data plane to the control plane.
        This is defined by the target architecture.
        In the case of this software switch example, in v1model.p4.
        Other architectures might define different punt methods.

        Digest sends a "message" to the control plane the various infromation
        in it such as packet headers.
        */
        digest<digest_t>(0, {hdr.ethernet.srcAddr, standard_metadata.ingress_port});
    }

    /*
    An action to CPU punt the frame (so that the CPU can program the MAC into
    the forwarding table).
    */
    action learn_mac_via_clone() {
        /*
        clone_preserving_field_list() and clone() are defined in v1model.p4
        They both create a copy of the packet which is sent to a CPU
        "Ethernet" port, which must be "sniffed" by the control plane
        (the former preserves user-defined meta data, the later does not).
        */
        meta.ingress_port = standard_metadata.ingress_port;
        clone_preserving_field_list(CloneType.I2E, (bit<32>)CPU_PORT_ID, 0);
    }

    /*
    Define a table with for storing invalid source MACs.
    Frames from these MACs will be dropped.
    */
    table bad_macs {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        // "const" means can't be changed by the control plane
        const default_action = NoAction();

        /* Don't specify size because this table has static entries */
        //size = 1;

        /*
        We should never see a frame with a broadcast source MAC.
        Hardcode a table entry which calls the drop action.
        */
        const entries = {
            (0xFFFFFFFFFFFF): drop();
        }
    }

    /* Define a table to store srouce MAC addresses. */
    table src_mac {
        /* Set of header fields used in the table lookup */
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        /*
        Set of possible actions the table lookup will respond with.
        A table lookup can only respond (if a match is found) with a single
        action, therefor only one action can be executed. As a result,
        dual-purpose actions are defined which learn the source MAC address
        and forward the packet to the destination MAC address.
        */
        actions = {
            learn_mac_via_digest;
            learn_mac_via_clone;
            NoAction;
        }

        /*
        The default action is only applied if no match was found in the table
        (meaning, unknown destination MAC). In this case learn the MAC address.

        The control plane will set the default action to either:
        * learn source MAC via digest message, or
        * learn source MAC via packet clone
        depending on which CLI option the control plane was started with.
        */
        default_action = NoAction();

        // Max number of "key" (MAC address) entries
        size = 4096;
    }

    /* Define a table to store destination MAC addresses. */
    table dst_mac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            l2_forward;
            broadcast;
        }

        /*
        "const" means the default action can't be changed by the control plane.

        The default action is only applied if no match was found in the table
        (meaning, unknown destination MAC). In this case we broadcast.
        */
        const default_action = broadcast();

        size = 4096;
    }

    apply {
        ingressFrames.count((bit<32>)standard_metadata.ingress_port);

        /*
        Drop frames that came in via the CPU punt port,
        this should be egress only:
        */
        if (standard_metadata.ingress_port == CPU_PORT_ID) {
            mark_to_drop(standard_metadata);
            exit;
        }

        /* Drop frames with invalid source MACs */
        bad_macs.apply();

        /* Lookup source MAC */
        src_mac.apply();

        /* Lookup destination MAC */
        dst_mac.apply();
    }
}

/* Egress processing is required */
control EgressProcess(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // Implement split horizon
        if (standard_metadata.egress_port == standard_metadata.ingress_port) {
            mark_to_drop(standard_metadata);
        } else {
            egressFrames.count((bit<32>)standard_metadata.egress_port);
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
