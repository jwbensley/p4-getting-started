# Examples

### l2_fwd

Perform a MAC look-up and forward packets out of the interface which matchs the entry in the MAC table.

Static MAC entryies are programmed pointing to 10.0.0.1 and 10.0.0.4 i.e., no MAC learning is implemented. Because there is no MAC learning in this example, we must ping from 10.0.0.1 to 10.0.0.4 because the MAC table entry for FF:FF:FF:FF:FF:FF points to the port 10.0.0.4 is connected to. This means that when 10.0.0.1 can send an ARP request to the broadcast address which will reach 10.0.0.4, and 10.0.0.4 can respond which 10.0.0.1 will receive, but any broadcast frames from 10.0.0.4 will be reflected back at 10.0.0.4 by the simple switch.

It is possible to implement MAC learning in P4 ([example](https://github.com/nsg-ethz/p4-learning/blob/master/examples/l2_learning/p4src/l2_learning_copy_to_cpu.p4)) however it is not possible to implement a full ARP implementation. For clients resolving the P4 router IP, P4 can match incoming ARP packets, perform an IP lookup of the IP in the ARP request, match it to a local interface IP, and respond with the MAC of the P4 router interface. However, when a P4 router receives a packet for a different L3 subnet than the subnet used on the interface the packet received from (meaning the packet needs to be L3 routed), and the P4 switch has a local interface in the destination L3 subnet but no MAC entry for the destination IP address, P4 is unable to buffer the packet and wait for an action to complete (send an ARP request and watch for an ARP response). In [this example](https://github.com/hesam4g/p4-arp) the P4 switch is programe with the MAC and IP entries, and the P4 switch responds to ARP requests (this only works because the example is a single L2 broadcast domain).

```shell
# Start the container
docker compose up -d
# Set up the topology and start the P4 switch running
docker compose exec p4 /l2_fwd/init.sh
# In another terminal, ping between the two interfaces in the same IP subnet, with the P4 switch providing L2 forwarding between the interfaces
docker compose exec p4 ip netns exec l2_0 ping 10.0.0.4
# Clean-up
docker compose down
```
