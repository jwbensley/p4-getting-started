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

header punt_t {
    /*
    We can't use PortId_t here because BMv2 architecture only accepts headers
    which are multiples of 8 bits.
    */
    bit<16> ingress_port;
}

/* The stack of all headers the ingress parser will need to parse */
struct headers {
    ethernet_t ethernet;
    /*
    When using the clone packet punt method (as opposed to the digest method),
    any addition data which needs to be sent to the CPU (meaning, meta data in
    addition to the original frame headers) can be defined here as extra headers.
    These extra headers can then be written to the clone frame before it is sent
    to the CPU. This allows extra information to be sent to the CPU in additional
    to the orginal headers.
    */
    punt_t punt_data;
}

/*
Defining this is a hard requirement.
Per-packet user defined metadata can be defined here.
*/
struct metadata {
    /*
    During ingress processing, if the frame is going to be CPU punted,
    the ingress port of a frame will be stored here as metadata.
    This metadata is cloned in addition to the frame, and available during
    egress passing, meaning it can be sent to the CPU as the value of the custom
    punt header defined as punt_t.

    On BMv2 the ingress port is set in standard_metadata_t, but this is not
    copied for the clone packet which is being punted. This is why we need this
    user defined metadata.
    */
    @field_list(0)
    PortId_t ingress_port;
}

/* Define the message payload sent to the control-plane for MAC learning. */
struct digest_t {
    MacAddr_t srcAddr; ///////////////////////////////////////////////////////////////////////////
    PortId_t ingressPort; ///////////////////////////////////////////////////////////////////////////
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

    Action parameters that have no direction (in/out/inout) indicate "action data."
    All such parameters must appear at the end of the parameter list.
    When used in a match-action table, these parameters will be provided by the
    table entries e.g., as specified by the control plane, the `default_action`
    table property, or the `entries` table property.
    */
    action forward(PortId_t egress_port) {
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

        Set multicast group to the ingress port ID + 1 (because the first switch
        port is 0 and 0 means "no multicast").
        The controller will have created this group already, as a group of ports
        which contains all ports in the switch except the ingress port.
        */
        standard_metadata.mcast_grp = (bit<16>)standard_metadata.ingress_port + 1;
        log_msg("Muticast group set to {}", {standard_metadata.mcast_grp});
    }

    /*
    An action to CPU punt the frame (so that the CPU can program the MAC into
    the forwarding table).
    */
    action learn_via_digest() {
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
    action learn_via_clone() {
        /*
        clone_preserving_field_list() and clone() are defined in v1model.p4

        They both create a copy of the packet, in this case we will send one
        copy to a CPU port, which must be "sniffed" by the control plane
        (the former preserves user-defined meta data, the later does not).

        This will also set standard_metadata.instance_type to 1 on the cloned
        packet, so that it can be distinguished from the orginal packet.
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
    table src_macs {
        /*
          Set of header fields used in the table lookup.

          This is a tuple of source MAC + ingress port ID.
          As long as we keep seeing the MAC address via the same ingress port,
          don't punt it.

          This prevents every frame from being CPU punted which would kill the
          control plane.

          We only punt when a MAC is seen via a new ingres port ID (meaning it's
          either the first time we've seen the MAC or there was a MAC move).
        */
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ethernet.srcAddr: exact;
        }
        /*
        Set of possible actions the table lookup will respond with.
        A table lookup can only respond (if a match is found) with a single
        action, therefor only one action can be executed.
        */
        actions = {
            learn_via_digest;
            learn_via_clone;
            NoAction;
        }

        /*
        The default action is only applied if no match was found in the table
        (meaning, unknown source MAC). In this case learn the MAC address.

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
    table dst_macs {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
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

        /*
        Having two tables seem inificient at first glance however there are a
        few things to consider here:

        * P4 is an abstraction layer. Depending on the target,
          these two tables could be merged into one table when compiled,
          preventing the double storing of MAC addresses.

        * Having two tables means that depending on the target,
          both tables could be searched in parallel actually giving a performance
          boost (or atleast, no performance degredation),

        * The P4 language itself does not prohibit performing a lookup against
          the same table twice. But many targets will because of the
          match-action design paradigm, different actions should be in different
          tables. This prevents any kind of loop too, and P4 doesn't support loops.
          Therefor there shouldn't be a need to query the same table more than once.
          One way to work around this on those targets would be to recirc
          the packet but this is halving the pps rate, so it would need to be
          really worth the performance loss.
        */

        /* Lookup source MAC */
        src_macs.apply();

        /* Lookup destination MAC */
        dst_macs.apply();
    }

}

/* Egress processing is required */
control EgressProcess(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

        // If CPU punting this frame...
        if (standard_metadata.instance_type == 1){
            /*
            Add the ingress port ID to the custom header field being added
            to the frame. The custom header is unused until this point.
            Headers default to an invalid state, meaning they won't be written
            to a frame by deault on egress.

            Set the custom header to valid, set the value, and then truncate the
            frame so that only the "ethernet" and "punt_data" headers will be
            transmitted towards the CPU. No other data is needed for MAC
            learning.
            */
            hdr.punt_data.setValid();
            hdr.punt_data.ingress_port = (bit<16>)meta.ingress_port;
            truncate((bit<32>)14); // Size in bytes
            log_msg("Going to punt frame with source MAC {} and ingress port {}", {hdr.ethernet.srcAddr, hdr.punt_data.ingress_port});
        } else {
            // Implement split horizon
            if (standard_metadata.egress_port == standard_metadata.ingress_port) {
                mark_to_drop(standard_metadata);
            } else {
                egressFrames.count((bit<32>)standard_metadata.egress_port);
            }
        }
    }
}

/* Egress checksum calculation is required */
control EgressChecksumCompute(inout headers hdr, inout metadata meta) {
     apply { }
}

/* Deparser is required */
control EgressDeparser(packet_out packet, in headers hdr) {
    //This is where header changes are written to the frame before transmitting.

    apply {
        packet.emit(hdr.ethernet);
        /*
        In the case of a CPU punted frame, the unchanged Ethernet header is
        written to the egress frame.

        Next the ingress port ID meta header is written directly after the
        header Ethernet (this only happys if the custom meta header has been
        setValid() earlier in EgressProcess()).

        This means the frame is now mangled (if it's a punt frame).
        This is fine becuase it's being send to the control-plane which expects
        this mangled format.
        */
        packet.emit(hdr.punt_data);
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
