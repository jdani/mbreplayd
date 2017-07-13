#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- author: JDaniel Jimenez
- email:  jdjp83@gmail.com


- What is this about:
mbreplayd is a multicast & Broadcast traffic replay daemon for pseudo-bridges
(aka Layer 3 bridges).


- How it works:
The idea is quite simple. What mbreplay does is:
    - sniff for traffic in in_iface
    - choose the packets matcheing BPF filter
    - change the source mac with the out_iface hwaddr
    - send the packet to out_iface

The only point is that, in order to be useful, mbreplayd has to replay packets
received in the out_iface to the in_iface. Every packet but those ones which
src ip is the same that the IP generating this traffic. This filter is setted
up automatically from the bpf_filter


- Ideal scenario:
mbreplayd is usefull to forward broadcast and multicast traffic from in_iface
to out_iface, both of them part of a pseudo-bridge. This is a layer 3 bridge.
For sure, pseudo-bridges is not the best or event the default option to bridge
two interfaces but, sometimes, it needed. For example when a wireles interface
is a bridge member. In that case, is pretty common to need pseudo-bridges. In
my case, the upstream interface in my virtualization server was wireless, so
I decided to solve the problem with unicast traffic using parprouted but I
couldn't do the same with any other software or configuration I tried. So I
decided to write mbreplayd!.


- Known issues:
The main downside of mbreplayd is related to performance. Using python + scapy
to sniff packets, modify and replay them in realtime maybe is not the best way
to go. However, mbreplayd is not intended to be production grade software but
a way to investigate, learn, study and code and, by the way, solve a problem
with my lab environment, which is the ideal scenario for mbreplayd.

"""

import signal
import sys
from scapy.all import get_if_hwaddr, sniff, sendp
from pprint import pprint
from threading import Thread
from datetime import datetime


class BCReplay:
    """
    Main bcreplayd class
    """
    pass


class fwd_inbound(forward):
    pass


class fwd_outbound(forward):
    pass


class forward():
    """
    Class to create a traffic forward. It stats listening in inbound inface and
    replay traffic matching bpf filter to the outbound iface.
    """

    def __init__(self, iface_in, iface_out, bpf_filter):
        """
        iface_in: interface to sniff traffic in
        iface_out: interface to replay sniffed packages
        bpf_filter: filter to process only the matching traffic
        """

        # Creating instance vars from init params
        self.iface_in = iface_in
        self.iface_out = iface_out
        self.bpf_filter = bpf_filter

        # Outbound address MAC is needed to use as src in th replayed traffic
        self.iface_out_hwaddr = get_if_hwaddr(iface_out)

        # var to check sniff status
        self.replaying = False

        # Private var to use as stop flag for sniff method
        self.__stop_sniffing = False


    def __sniff(self):
        """
        Sniff method.

        Callback: __replay
        Stop condition: __stop_sniffing
        """
        sniff(  iface=self.iface_in,
                prn=self.__replay,
                filter=self.bpf_filter,
                store=0,
                stop_filter=self.__stop_sniffing)


    def __replay(self, pkt):
        """
        Replay packet to out_iface changing src_mac with outbout iface mac

        pkt: packet to replay
        """
        pkt[0][0].src = self.iface_out_hwaddr
        sendp(pkt, iface=self.iface_out, verbose=False)


    def start(self):
        """
        Start replaying traffic
        """
        # makes sure sniff flag is set to true
        self.__stop_sniffing = False

        # Create sniff thread and start it
        self.__sniff_thread = Thread(target=self.__sniff)
        self.__sniff_thread.start()

        # Set replaying status to true
        self.replaying = True


    def stop(self):
        """
        Stop replaying traffic
        """
        # makes sure sniff flag is set to true
        self.__stop_sniffing = True

        # Set replaying status to true
        self.replaying = False




sigterm = False

# Control de SIGTERM
def signal_term_handler():
    global sigterm
    print 'got SIGTERM'
    sigterm = True
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_term_handler)

def stop_condition(pkt):
    global sigterm
    return sigterm


def print_pkt_info(pkt, iface_in, iface_out):
    now_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    print "%s: [%s] %s -> [%s] %s" % (
        now_time,
        iface_in,
        pkt[0][1].src,
        iface_out,
        pkt[0][1].dst,
    )


# inbound sniff + replay
def inbound_sniff():
    sniff(iface="wlan0", prn=inbound_replayer, filter=in_bpf_filter, store=0, stop_filter=stop_condition)

def inbound_replayer(pkt):
    pkt[0][0].src = rpl_hwaddr
    pkt[0][0].dst = dst_hwaddr
    print_pkt_info(pkt, 'wlan0', 'vmbr0')
    sendp(pkt, iface='vmbr0', verbose=False)


# outbound sniff + replay
def outbound_sniff():
    sniff(iface="vmbr0", prn=outbound_replayer, filter=out_bpf_filter, store=0, stop_filter=stop_condition)

def outbound_replayer(pkt):
    pkt[0][0].src = src_hwaddr
    pkt[0][0].dst = dst_hwaddr
    print_pkt_info(pkt, 'vmbr0', 'wlan0')
    sendp(pkt, iface='wlan0', verbose=False)




src_hwaddr = get_if_hwaddr('wlan0')
rpl_hwaddr = get_if_hwaddr('vmbr0')
# Broadcast Address
dst_hwaddr = '01:00:5e:7f:ff:fa'

# Outbound BPF Filter
out_bpf_filter = "src host 192.168.1.11"
out_bpf_filter += " and dst port 1900"
out_bpf_filter += " and udp"
out_bpf_filter += " and dst host 239.255.255.250"
# out_bpf_filter = "ip multicast or ip broadcast"


# Inbound BPF Filter
in_bpf_filter = "not src host 192.168.1.11"
in_bpf_filter += " and dst port 1900"
in_bpf_filter += " and udp"
in_bpf_filter += " and dst host 239.255.255.250"
# in_bpf_filter = "not src host 192.168.1.11 and (ip multicast or ip broadcast)"


t_outbound = Thread(target=outbound_sniff)
t_outbound.start()

t_inbound = Thread(target=inbound_sniff)
t_inbound.start()
