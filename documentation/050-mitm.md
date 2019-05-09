## Man-in-the-middle attacks

Upon successful poisioning of a victim's ARP tables all trafic bound to a
particular host inside the LAN or the outside world can be routed through the
attacker. This, together with unauthenticated protocols makes an impersonation
or Man-in-the-Middle attack straightfoward. To demonstrate it we procceed in
the following manner:

1. Save network configuration including both the attacker machine's local
   network configuration (IPv4 forwarding policies...) and LAN parameters that
   will be spoofed (gateway IP and MAC address...). This is necessary to
   restore the configuration after we choose to end our attack.

1. Enable IPv4 forwarding on the attacker machine so that when the victim
   becomes infected all traffic is forwarded to the gateway normaly. The goal
   of this is to remain stealthy until we are ready to intercept traffic and to
   remain stealthy if we choose not to intercept all traffic (the traffic we do
   not intercept will be forwarded normally).

1. Continiously send maliciously crafted ARP-Request packets to the victim
   attempting to replace the hardware address of the gateway entry in the
   victim's ARP table with our hardware address (the hardware address of the
   attacker). This is needed as ARP cache entries are normally short lived
   (around 60s on Linux machines). We have found that one or two malicious
   ARP-Request packets are sufficient to convince a Linux host that the gateway
   IP has changed.

1. Set up a proxy server on the attacker machine listening for traffic that
   will be intercepted when the target machine initiates a connection of our
   interest.

1. Set up network rules (as with `iptables`) that forward desired traffic to
   ourselves for further analysis and/or modification. In our case, for
   demonstration purposes we chose to sniff unencrypted HTTP traffic and
   replace all responses with a webpage warning about the spoofing. To achieve
   this we insert a rule that captures all incoming traffic to TCP port 80 and
   forwards it to another port on our machine. An `iptables` rule that does
   that is

   ```
   iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
   ```

1. From this point on the attack is taking place. All traffic is intercepted.

1. When we choose to end the attack we restore both our network configuration
   (for example, disabling IPv4 forwarding) and the LAN network that we
   spoofed. The latter consists of sending a couple of ARP-Request packets to
   the victim but this time with the legitimate gateway addresses. Again, we
   find that when one packet does not suffice usually two packets will be
   enough to restore the configuration. In any case, as ARP cache entries are
   short lived, if we did not perform this restoration step, the victim would
   recover a legitimate ARP table when the ARP gateway entry expired (in less
   than 60s on most Linux hosts).



### On impersonation attacks with secure protocols

Impersonation when dealing with application protocols that run over TLS is more
complicated because the attacker must convince the victim to trust them as the
legitimate endpoint of the connection. In controlled environments where the
goal is to monitor traffic for security purposes this can be achieved by
installing a root certificate on all machines whose traffic will be
intercepted. There are existing tools capable of automating this process
readily available for system administrators such as `mitm-proxy`. However, as
this required modifying configuration on the target machines, we consider it
beyond the scope of this project whose goal is mainly to demonstrate stealthy
ARP spoofing techniques.
