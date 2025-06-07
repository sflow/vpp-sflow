# The following creates two veth pairs p1-p2 and p3-p4,
# then bridges p1 and p3 together in vpp,
# then assigns IP addresses to p2 and p4 and puts
# one of them in a separate namespace so that when
# they ping each other the ICMP packets go through VPP.

ip link add dev p1 type veth peer name p2
ip link add dev p3 type veth peer name p4
ip link set dev p1 up
ip link set dev p3 up
ip link set dev p4 up
ip netns add ns2
ip link set p2 netns ns2
ip -n ns2 link set dev p2 up
ip -n ns2 addr add 172.16.111.2/24 dev p2
ip addr add 172.16.111.4/24 dev p4

vppctl create host-interface name p1
vppctl create host-interface name p3
vppctl set interface state host-p1 up
vppctl set interface state host-p3 up
vppctl set interface l2 bridge host-p1 1
vppctl set interface l2 bridge host-p3 1
vppctl sflow enable host-p1
vppctl sflow enable host-p3
vppctl sflow sampling 10

# then test with "sudo ip netns exec ns2 ping -i 0.01 172.16.111.4"
