## ARP-Request-based spoofing attacks

The first kind of attack we will discuss is the request-based attack which
takes advantage of the lack of authentication of the ARP protocol mentioned in
the previous section. Albeit simple, this attack is powerful. It enables an
attacker to forge the IP address of the network gateway (or any other host on
the network) without giving themselves up to other posibly vigilant machines
that might be on the LAN. On the other hand, this attack is not suitable for
infecting machines as they join the network because it requires the attacker to
initiate communication. This shortcomming might be solved by listening for DHCP
traffic if there is any but in most cases it is easier to use the ARPResponse
based attack that will be discussed later.

Implementation of this attack is straighforward: craft an ARP packet with the
protocol and ethernet addresses of the host that is being spoofed as the origin
parameters. Optionally, set the destination parameters to be the addresses of
the victim and send it to just the victim's Ethernet address instead of the
network's broadcast address to remain stealthy.

There are plenty of tools capable of crafting this packets that are widely
available (Nemesis, Ethercap, ...). For demonstration purposes we develop a
python script utilising the `scapy` library that is capable of detecting the
local network's gateway and poison a target host's ARP tables so that it
believes that the gateway is the attacker. This tool and its documentation can
be found in the suplementary material to this paper.

Analyses were carried out both on a controlled environment, on a home network
and on a university network with varying degrees of success.

Inside the controlled environment (a virtualbox-based host-only network with
three virtual machines acting as a router, attacker and victim) success was
close to 100%. Although victims sometimes did not react to a single malicious
ARP packet, replaing the attack two or three times resulted in a successful
infection. Infection was verified by using the `arp -n` command line tool
availalbe in most Linux hosts. The `-n` option disables reverse DNS lookups
that might fail because we do not forward IP traffic so the DNS queries cannot
be resolved. These hosts were runing Linux kernel version 4.15. Although this
attack had already been reported for versions 2.x and 3.x our research shows
that hosts running 4.x are still vulnerable. Here *vulnerable* is a term that
must be used with care. Later we will discuss the whitehat applications of this
technique and the most widely deployed countermeasures and see that mitigation
at the host level is not always desirable.

Infection is usually short-lived. On most linux hosts ARP cache expiration
times are around 60s. In any case, a router will regularly send ARP requests to
all of the members in a LAN to keep its ARP tables updated. A workaround for
this is to spoof both the victim's and the router's ARP tables by sending two
separate ARP requests when setting up the attack. However, this might not
always be desired to remain stealthy by avoiding monitoring tools that may be
set up in the router.

Inside the home network...

Inside the university network no host was susceptible to being attacked because
of the network policy of blocking all ARP traffic not directed to the gateway.
We understand this is standard practice on (semi-)open networks given the large
attack surface exposed by modern operating systems. As mentioned previously,
blocking ARP traffic between clients in a public network is a suitable
mitigation that has advantages with respect to host-based mitigations that will
be discussed later.
