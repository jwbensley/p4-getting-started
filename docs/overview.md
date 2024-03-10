# P4 Definitions and Architecture

**P4**: A language (DSL) for writing packet processing code. It has a style similar to C but doesn't support loops.

**P4 Program**: A program written in the P4 language.

**P4-14**: This is the old version of the P4 language.

**P4-16**: This is the current version of the language.

**P4-14 Spec**: The current specification for the P4-16 language is <https://staging.p4.org/p4-spec/docs/P4-16-v1.2.4.html>.

**Target**: This is the packet processing “device” which will run the P4 program (it could be a software switch or router, or an FPGA, a switch, or a NIC, or anything really).

**Target Architecture**: This describes the capabilities of the Target and is used by the P4 Compiler. The P4 architecture identifies the P4-programmable blocks (e.g., parser, ingress control flow, egress control flow, deparser, etc.) and their data plane interfaces. The P4 architecture can be thought of as a contract between the program and the target. Each manufacturer must therefore provide both a P4 compiler as well as an accompanying architecture definition for their target.

**The Portable NIC Architecture (PNA)**: A target architecture that describes the common capabilities of network NIC devices that process and forward packets between one or more network interfaces and a host system.

**The Portable Switch Architecture (PSA)**: A target architecture that describes the common capabilities of network switch devices to process and forward packets.

**PSA Spec** The current version of the PSA specification is <https://staging.p4.org/p4-spec/docs/PSA-v1.2.html>.

**V1model Architecture**: This is a target architecture this is older and more generic that PSA and PNA.

**P4 Compiler**: The compiler takes a P4 Program and generates two main things. It generates the data plane processing code by reading in the target architecture and the P4 Program, and compiling the program for that specific architecture. It also uses P4Runtime to generate the API definitions (Protobuf files) for communication between the control-plane and data-plane (how the control-plane can update the data-plane, because depends on the table sand structures defined in the P4 Program) but, it does not generate or define the control-plane itself.

**P4Runtime**: Takes in a P4Program and generates Protobuf files which specify how the control-plane can interact with the data-plane.

**P4Info file**: Running the P4Compiler produces the P4Info file, which describes all the tables, counters, keys, etc, the P4 Program is interacting with. This is used as the input to P4Runtime to generate the control-plane to data-plane API definitions.

**Bmv2** (P4 reference software switch): This is a target which is a software switch. It allows for easy testing of P4 programs. The bmv2 switch supports the V1model target architecture and the PSA target architecture. When compiling P4 code with the P4 Compile for the V1model architecture, a JSON file can be produced which the bmv2 will consume and simulate the target architecture, allowing it to mimic any target and run any P4 code.
