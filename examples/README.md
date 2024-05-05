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

Install the requirements in a virtual-env if you want to edit the examples locally in your IDE:

```shell
python3 -m venv --without-pip --system-site-packages .venv && source .venv/bin/activate
python3 -m pip install -r examples/requirements.txt
```

## l2_fwd_static

Perform a MAC look-up and forward packets out of the interface which matches the entry in the MAC table.

Static MAC entries are programmed pointing to 10.0.0.1 and 10.0.0.4 i.e., no MAC learning is implemented. Because there is no MAC learning in this example, we must ping from 10.0.0.1 to 10.0.0.4 because the MAC table entry for FF:FF:FF:FF:FF:FF points to the port which 10.0.0.4 is connected to. This means that 10.0.0.1 can send an ARP request to the broadcast address which will reach 10.0.0.4, and 10.0.0.4 can unicast respond which 10.0.0.1 will receive, but any broadcast frames from 10.0.0.4 will be reflected back at 10.0.0.4 by the simple switch.

```shell
# Set up the topology and start the P4 switch running
docker compose exec p4 /examples/l2_fwd_static/init.sh

# Optional, tcpdump to verify
docker compose exec p4 tcpdump -nnlASXevv -s 0 -i l2_r1

# In another terminal, ping between the two interfaces in the same IP subnet, with the P4 switch providing L2 forwarding between the interfaces
docker compose exec p4 ip netns exec l2_0 ping 10.0.0.4

# Optional, inspect the switch tables manually
docker compose exec p4 simple_switch_CLI

# Clean up
docker compose exec p4 /examples/clean_up.sh
```

## l2_fwd_learning

It is not possible to implement MAC learning in P4 natively. It can be implemented using CPU punting though:

* [example 1](https://github.com/nsg-ethz/p4-learning/blob/master/examples/l2_learning/p4src/l2_learning_copy_to_cpu.p4)
* [example 2](https://github.com/antoninbas/p4runtime-go-client/blob/main/cmd/l2_switch/l2_switch.p4)

In this example we expand on these existing examples to account for MAC moves and invalid source MAC addresses.

```shell
# Set up the topology and start the P4 switch running
docker compose exec p4 /examples/l2_fwd_learning/init.sh

# In another terminal, start the control-plane
docker compose exec p4 /examples/l2_fwd_learning/control_plane.py
# docker compose exec p4 /examples/l2_fwd_learning/control_plane.py --digest

# Optional, see packet counters on P4 device:
docker compose exec p4 /examples/l2_fwd_learning/control_plane.py --counters

# Optional, tcpdump to verify
docker compose exec p4 tcpdump -nnlASXevv -s 0 -i l2_r1

# In another terminal, ping between the two interfaces in the same IP subnet, with the P4 switch providing L2 forwarding between the interfaces
docker compose exec p4 ip netns exec l2_0 ping -c 1 10.0.0.4
docker compose exec p4 ip netns exec l2_1 ping -c 1 10.0.0.1
# docker compose exec p4 ip netns exec l2_0 ip nei del 10.0.0.4 dev l2_0
# docker compose exec p4 ip netns exec l2_1 ip nei del 10.0.0.1 dev l2_1

# Optional, inspect the switch tables manually
docker compose exec p4 simple_switch_CLI

# Clean up
docker compose exec p4 /examples/clean_up.sh
```

Example output:

```text
$ docker compose exec p4 /examples/l2_fwd_learning/control_plane.py --counters
ingressFrames[0]= (0 bytes, 0 packets)
egressFrames[0]= (0 bytes, 0 packets)
ingressFrames[1]= (0 bytes, 0 packets)
egressFrames[1]= (0 bytes, 0 packets)

$ docker compose exec p4 ip netns exec l2_0 ping -c 1 10.0.0.4
PING 10.0.0.4 (10.0.0.4): 56 data bytes
64 bytes from 10.0.0.4: icmp_seq=0 ttl=64 time=1.189 ms
--- 10.0.0.4 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 1.189/1.189/1.189/0.000 ms

$ docker compose exec p4 /examples/l2_fwd_learning/control_plane.py --counters
ingressFrames[0]= (140 bytes, 2 packets)
egressFrames[0]= (140 bytes, 2 packets)
ingressFrames[1]= (140 bytes, 2 packets)
egressFrames[1]= (140 bytes, 2 packets)

$ docker compose exec p4 tcpdump -nnlASXevv -s 0 -i l2_r1
tcpdump: listening on l2_r1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
11:03:35.166911 00:00:00:00:00:01 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Request who-has 10.0.0.4 tell 10.0.0.1, length 28
	0x0000:  0001 0800 0604 0001 0000 0000 0001 0a00  ................
	0x0010:  0001 0000 0000 0000 0a00 0004            ............
11:03:35.166922 00:00:00:00:00:04 > 00:00:00:00:00:01, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Reply 10.0.0.4 is-at 00:00:00:00:00:04, length 28
	0x0000:  0001 0800 0604 0002 0000 0000 0004 0a00  ................
	0x0010:  0004 0000 0000 0001 0a00 0001            ............
11:03:35.167346 00:00:00:00:00:01 > 00:00:00:00:00:04, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 64293, offset 0, flags [DF], proto ICMP (1), length 84)
    10.0.0.1 > 10.0.0.4: ICMP echo request, id 574, seq 0, length 64
	0x0000:  4500 0054 fb25 4000 4001 2b7f 0a00 0001  E..T.%@.@.+.....
	0x0010:  0a00 0004 0800 ea37 023e 0000 8708 0066  .......7.>.....f
	0x0020:  0000 0000 048a 0200 0000 0000 0001 0203  ................
	0x0030:  0405 0607 0809 0a0b 0c0d 0e0f 1011 1213  ................
	0x0040:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
	0x0050:  2425 2627                                $%&'
11:03:35.167362 00:00:00:00:00:04 > 00:00:00:00:00:01, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 43947, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.0.4 > 10.0.0.1: ICMP echo reply, id 574, seq 0, length 64
	0x0000:  4500 0054 abab 0000 4001 baf9 0a00 0004  E..T....@.......
	0x0010:  0a00 0001 0000 f237 023e 0000 8708 0066  .......7.>.....f
	0x0020:  0000 0000 048a 0200 0000 0000 0001 0203  ................
	0x0030:  0405 0607 0809 0a0b 0c0d 0e0f 1011 1213  ................
	0x0040:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
	0x0050:  2425 2627                                $%&'
```

## l3_fwd_static

It is not possible to implement a full ARP or NDP implementation directly in P4. For clients trying to resolve the P4 router interface IP, P4 can be hard coded to match incoming ARP or NDP packets, perform an IP lookup of the IP in the request, match it to a local interface IP, and respond with the MAC of the P4 router interface. However, this is a bit of a hack, because most of the values would need to be hard coded at compile time.

In addition, that only solves L3 resolution of the P4 router IP. When a P4 router receives a packet with an IP address in a subnet which configured on a different L3 interface than the subnet configured on the interface the packet was received on (meaning the packet needs to be L3 routed), if the P4 switch has no L2 entry for the destination IP address, P4 is unable to buffer the packet and wait for an action to complete (send an ARP/ND request and watch for a response, also updating forwarding tables at run time by using P4 forwarding plane code is only support on specific targets, Bmv2 is not one of those targets!).

In the following example the P4 device will receive IPv6 packets and either route them locally or forward to another P4 device which has a route to the destination subnet. Both devices are capable of responding to ND solicitations for their own interface IPs, as well as soliciting for IPs of devices on locally connected subnets. This requires a control-plane app to transmit ND solicitations and update the adjacency table when a ND advertisement is received.

```shell
# Set up the topology and start the P4 switch running
docker compose exec p4 /examples/l3_fwd_static/init.sh

# In two more terminal windows, start the control-plane for each switch
docker compose exec p4 /examples/l3_fwd_static/control_plane.py
docker compose exec p4 /examples/l3_fwd_static/control_plane.py --switch2

# Optional, tcpdump to verify
docker compose exec p4 tcpdump -nnlASXevv -s 0 -i l3_r0

# In another terminal, ping between the two subnets on the same switch, and between subnets on different switches
docker compose exec p4 ip netns exec l3_0 ping -c 1 fd:0:0:1::2
docker compose exec p4 ip netns exec l3_0 ping -c 1 fd:0:0:2::2

# Optional, see packet counters on P4 device:
docker compose exec p4 /examples/l3_fwd_static/control_plane.py --counters
docker compose exec p4 /examples/l3_fwd_static/control_plane.py --counters --switch2

# Optional, inspect the switch tables manually
docker compose exec p4 simple_switch_CLI

# Clean up
docker compose exec p4 /examples/clean_up.sh
```
