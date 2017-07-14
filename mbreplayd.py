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
from time import sleep
from threading import Thread
from datetime import datetime
from scapy.all import get_if_hwaddr, sniff, sendp



class BCReplay(object):
    """
    Main bcreplayd class
    """
    def __init__(   self,
                    iface_in,
                    iface_out,
                    src_ip,
                    bm_ip,
                    bm_port,
                    bm_proto='udp'):
        """
        iface_in: interface listening for original traffic
        iface_out: interface where traffic will be replayed
        src_ip: Source IP of original traffic
        bm_ip: Broadcast or multicast dest IP
        bm_port: Broadcast or multicast dest port
        bm_proto: If you need to change this, mail me!
        """

        self.fordarders = {}
        self.fordarders['inbound'] = FWDInbound(
                                                    iface_in,
                                                    iface_out,
                                                    src_ip,
                                                    bm_ip,
                                                    bm_port)
        # In and Out iface are switched!
        self.fordarders['outbound'] = FWDOutbound(  iface_out,
                                                    iface_in,
                                                    src_ip,
                                                    bm_ip,
                                                    bm_port)

    def start(self):
        """
        start replaying
        """
        for fwd in self.fordarders:
            self.fordarders[fwd].start()

    def stop(self):
        """
        start replaying
        """
        for fwd in self.fordarders:
            self.fordarders[fwd].stop()




class Forward(object):
    """
    Class to create a traffic forward. It stats listening in inbound inface and
    replay traffic matching bpf filter to the outbound iface.
    """

    # Base BPF filter
    # Not will be only used in inbound traffic in order to prevent
    # replaying already replayed traffic. If not is not defined, it will
    # create a broadcast or multicast storm. You can trust me :P
    BASE_BPF_FILTER = "%(not)s src host %(src_ip)s"
    BASE_BPF_FILTER += " and dst port %(bm_port)s"
    BASE_BPF_FILTER += " and %(bm_proto)s"
    BASE_BPF_FILTER += " and dst host %(bm_ip)s"

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
        self.__stop_flag = False

    def __stop_sniffing(self, pkt):
        """
        Returns stop flag
        """
        return self.__stop_flag

    def __sniff(self):
        """
        Sniff method.

        Callback: __replay
        Stop condition: __stop_flag
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
        self.__stop_flag = False

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
        self.__stop_flag = True

        # Set replaying status to true
        self.replaying = False



class FWDInbound(Forward):
    """
    class managing inbound traffic (replies to src)
    """
    def __init__(   self,
                    iface_in,
                    iface_out,
                    src_ip,
                    bm_ip,
                    bm_port,
                    bm_proto='udp'):
        """
        iface_in: interface to sniff traffic in
        iface_out: interface to replay sniffed packages
        src_ip: IP generating broadcast or multicast traffic
        bm_ip: broadcast or multicast IP
        bm_port: broadcast or multicast dst port
        bm_proto: Changing this won't be needed (will it? jdjp83@gmail.com)
        """

        bpf_filter_args = {
            "not": "not",
            "src_ip": src_ip,
            "bm_proto": bm_proto,
            "bm_ip": bm_ip,
            "bm_port": bm_port
        }

        # BPF Filter created!!
        self.bpf_filter = self.BASE_BPF_FILTER % bpf_filter_args
        
        # Init super class with right params
        super(FWDInbound, self).__init__(iface_in, iface_out, self.bpf_filter)




class FWDOutbound(Forward):
    """
    class managing outbound traffic (from src)
    """
    def __init__(   self,
                    iface_in,
                    iface_out,
                    src_ip,
                    bm_ip,
                    bm_port,
                    bm_proto='udp'):
        """
        iface_in: interface to sniff traffic in
        iface_out: interface to replay sniffed packages
        src_ip: IP generating broadcast or multicast traffic
        bm_ip: broadcast or multicast IP
        bm_port: broadcast or multicast dst port
        bm_proto: Changing this won't be needed (will it? jdjp83@gmail.com)
        """

        bpf_filter_args = {
            "not": "",
            "src_ip": src_ip,
            "bm_proto": bm_proto,
            "bm_ip": bm_ip,
            "bm_port": bm_port
        }

        # BPF Filter created!!
        self.bpf_filter = self.BASE_BPF_FILTER % bpf_filter_args
        
        # Init super class with right params
        super(FWDOutbound, self).__init__(iface_in, iface_out, self.bpf_filter)




iface_in = "vmbr0"
iface_out = "wlan0"
src_ip = "192.168.1.11"
bm_ip = "239.255.255.250"
bm_port = "1900"

bcreplay = BCReplay(iface_in, iface_out, src_ip, bm_ip, bm_port)

secs = 120
bcreplay.start()
for i in range(0, secs):
    sleep(1)
    print i
bcreplay.stop()

