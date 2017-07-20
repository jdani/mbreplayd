# mbreplayd

Multicast &amp; Broadcast traffic replay daemon for pseudo-bridges (Layer 3 bridges) 

## What is this about?
mbreplayd is a multicast & Broadcast traffic replay daemon for pseudo-bridges (aka Layer 3 bridges).


## How does it work?
The idea is quite simple. What mbreplay does is:
1. sniff for traffic in iface_in
1. choose the packets matcheing BPF filter
1. change the source mac with the iface_out hwaddr
1. send the packet to iface_out

The only point is that, in order to be useful, mbreplayd has to replay packets
received in the iface_out to the iface_in. Every packet but those ones which
src ip is the same that the IP generating this traffic. This filter is setted
up automatically from the bpf_filter


## Ideal scenario
mbreplayd is usefull to forward broadcast and multicast traffic from iface_in
to iface_out, both of them part of a pseudo-bridge. This is a layer 3 bridge.
For sure, pseudo-bridges is not the best or event the default option to bridge
two interfaces but, sometimes, it needed. For example when a wireles interface
is a bridge member. In that case, is pretty common to need pseudo-bridges. In
my case, the upstream interface in my virtualization server was wireless, so
I decided to solve the problem with unicast traffic using parprouted but I
couldn't do the same with any other software or configuration I tried. So I
decided to write mbreplayd!.


## Known downsides
The main downside of mbreplayd is related to performance. Using python + scapy
to sniff packets, modify and replay them in realtime maybe is not the best way
to go. However, mbreplayd is not intended to be production grade software but
a way to investigate, learn, study and code and, by the way, solve a problem
with my lab environment, which is the ideal scenario for mbreplayd.


## How to contribute
Just take a look at the opened issues!

