# Learnings and Experiences Working with P4

* P4 is purely forwarding-plane focused, there are no constructs in the language for handling control or management plane protocol concepts (i.e. parsing routing updates), only forwarding plane concepts (i.e. parsing packets headers).
* P4 is unable to update the forwarding tables (this can't be don't from the data plane, it must be done by the control plane).
* P4 is unable to search a specific table more than once e.g., search table X with key Y, if no match is found then search table X again but now with key Z. This is not possible. Each table can be searched only once (it might be achievable using packet recirc and using meta data fields as the search key but this halves the pps rate).
* Managing state is hard in P4. A P4 data plane can't read counters (only write to them), but the control plane can read them. Data plane (P4) and control plane can both read and write to registers, but a lot of P4 code is required to store and access any sizeable amount of state in registers. This really needs to be done by a control-plane.
* P4 is unable to buffer packet whilst performing an additional task e.g., packet enters interface 1, router needs to ARP our interface 2 to get MAC address for destination IP, P4 can't buffer the IP packet until the ARP completes.
* P4 can't manipulate or modify a string in anyway. It is not possible to perform any action on a string.
