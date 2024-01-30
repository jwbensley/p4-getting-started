# P4 Getting Started

This repo contains various materials which have been compiled in a single location. This collection of resources provides everything you need in one place, in order to work through some P4 "hello world" exercises.

### l2_fwd

Perform a MAC look-up and forward packets out of the interface which matchs the entry in the MAC table.

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
