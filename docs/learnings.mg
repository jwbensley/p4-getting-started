# Learnings and Experiences Working with P4

* P4 is purely forwarding-plane focused, there are no constructs in the language for handling control or management plane protocol concepts, only forwarding plane concepts (i.e. parsing packets headers).
* P4 is unable to search a specific table more than one i.e., search table X with key Y, if not match search table X with key Z. This is not possible. Each table can be searched only once.
* Managing state is hard in P4. P4 has registers but a lot of code is required to store and access any sizeable amount of state in registers. This really needs to be done by a control-plane.
* P4 is unable to buffer packet whilst performing an additional task e.g. packet enters interface 1, router needs to ARP our interface 2 to get MAC address for destination IP, P4 can't buffer the ICMP echo request until the ARP completes.
