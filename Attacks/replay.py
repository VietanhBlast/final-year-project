# replay_attack.py
from scapy.all import *

# Define the file containing the captured packets (pcap file)
pcap_file = "capture.pcap"  # Replace with your actual pcap file

def replay_attack():
    print("Starting Replay Attack...")
    
    # Read packets from pcap file
    packets = rdpcap(pcap_file)
    
    # Replay each packet
    for packet in packets:
        send(packet, verbose=0)
        print(f"Replaying packet: {packet.summary()}")

if __name__ == "__main__":
    replay_attack()
