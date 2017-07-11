#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- author: JDaniel Jimenez
- email:  jdjp83@gmail.com

- What is this about:
mbreplayd is a multicast & Broadcast traffic replay daemon for pseudo-bridges
(aka Layer 3 bridges). The ideal scenario to use

- Ideal scenario:


- Known issues:
The main downside of mbreplayd is related to performance. Using python + scapy
to sniff packets, modify and replay them in realtime maybe is not the best way
to go. However, mbreplayd is not intended to be production grade software but
a way to investigate, learn, study and code and, by the way, solve a problem
with my lab environment, which is the ideal scenario for mbreplayd.

"""

import signal
import sys
from scapy.all import *
from pprint import pprint
from threading import Thread
from datetime import datetime


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


