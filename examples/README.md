# Examples

All of these examples are run in docker, therefor, before running any of them you need to start the container:

```shell
# Start the container
docker compose up -d
```

To clear up just tear down the container again:

```shell
# Stop the container
docker compose down
```

## l2_fwd_static

Perform a MAC look-up and forward packets out of the interface which matches the entry in the MAC table.

Static MAC entries are programmed pointing to 10.0.0.1 and 10.0.0.4 i.e., no MAC learning is implemented. Because there is no MAC learning in this example, we must ping from 10.0.0.1 to 10.0.0.4 because the MAC table entry for FF:FF:FF:FF:FF:FF points to the port which 10.0.0.4 is connected to. This means that 10.0.0.1 can send an ARP request to the broadcast address which will reach 10.0.0.4, and 10.0.0.4 can unicast respond which 10.0.0.1 will receive, but any broadcast frames from 10.0.0.4 will be reflected back at 10.0.0.4 by the simple switch.

```shell
# Set up the topology and start the P4 switch running
docker compose exec p4 /examples/l2_fwd_static/init.sh

# Optional in another window, tcpdump to verify:
#tcpdump -nnlASXevv -s 0 -i l2_r1

# In another terminal, ping between the two interfaces in the same IP subnet, with the P4 switch providing L2 forwarding between the interfaces
docker compose exec p4 ip netns exec l2_0 ping 10.0.0.4

# Clean up
docker compose exec p4 /examples/clean_up.sh
```

## l2_fwd_learning

Is it not possible to implement MAC learning in P4 natively. It can be implemented using CPU punting though:

* [example 1](https://github.com/nsg-ethz/p4-learning/blob/master/examples/l2_learning/p4src/l2_learning_copy_to_cpu.p4)
* [example 2](https://github.com/antoninbas/p4runtime-go-client/blob/main/cmd/l2_switch/l2_switch.p4)

In this example we perform a lookup of the incoming frame...................????????????

```shell
# Set up the topology and start the P4 switch running
docker compose exec p4 /examples/l2_fwd_learning/init.sh

# In another terminal, ping between the two interfaces in the same IP subnet, with the P4 switch providing L2 forwarding between the interfaces
docker compose exec p4 ip netns exec l2_0 ping 10.0.0.4
```

## l3_fwd_static

It is not possible to implement a full ARP implementation directly in P4. For clients resolving the P4 router IP, P4 can be hard coded to match incoming ARP packets, perform an IP lookup of the IP in the ARP request, match it to a local interface IP, and respond with the MAC of the P4 router interface. However, when a P4 router receives a packet for an IP address on a different L3 subnet than the subnet used on the interface the packet was received from (meaning the packet needs to be L3 routed), and the P4 switch has a local interface in the destination L3 subnet but no MAC entry for the destination IP address, P4 is unable to buffer the packet and wait for an action to complete (send an ARP request and watch for an ARP response). In [this example](https://github.com/hesam4g/p4-arp) the P4 switch is programmed with the MAC and IP entries, and the P4 switch responds to ARP requests (this only works because the example is a single L2 broadcast domain).
