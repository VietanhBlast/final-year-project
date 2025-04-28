#!/usr/bin/env python3

import nmap

def is_host_up(ip):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-sn -T3')
    return ip in scanner.all_hosts() and scanner[ip].state() == 'up'

def nmap_host_discovery(network):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=network, arguments='-sn -T3')
    hosts = []
    for host in scanner.all_hosts():
        host_info = {
            'host': host,
            'state': scanner[host].state(),
            'mac': scanner[host]['addresses'].get('mac', 'Unknown')
        }
        hosts.append(host_info)
    return hosts

def nmap_portscan(ip_address):
    if not is_host_up(ip_address):
        print(f"[!] {ip_address} is down — skipping port scan.")
        return []

    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments='-sV -T3')
    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                results.append({
                    'host': host,
                    'port': port,
                    'state': scanner[host][proto][port]['state'],
                    'service': scanner[host][proto][port]['name'],
                    'mac': scanner[host]['addresses'].get('mac', 'N/A')
                })
    return results

def nmap_os_scan(target):
    if not is_host_up(target):
        print(f"[!] {target} is down — skipping OS scan.")
        return {}

    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-O -T3')
    os_results = {}
    for host in scanner.all_hosts():
        host_info = {
            'osmatch': scanner[host].get('osmatch', []),
            'mac': scanner[host]['addresses'].get('mac', 'N/A')
        }
        os_results[host] = host_info
    return os_results

# ---------------- Interactive Menu ---------------- #

def main():
    while True:
        print("\n=== Network Recon Tool ===")
        print("1. Host Discovery (Ping Sweep)")
        print("2. Port Scan a Host")
        print("3. OS Fingerprinting")
        print("4. Exit")
        choice = input("Select an option (1–4): ")

        if choice == '1':
            net = input("Enter target network (e.g., 192.168.200.0/24): ")
            hosts = nmap_host_discovery(net)
            print("\n[+] Discovered Hosts:")
            for h in hosts:
                print(f" - {h['host']} | State: {h['state']} | MAC: {h['mac']}")
        elif choice == '2':
            ip = input("Enter target IP (e.g., 192.168.200.10): ")
            results = nmap_portscan(ip)
            print(f"\n[+] Port Scan Results for {ip}:")
            for r in results:
                print(f" - Port {r['port']}/tcp | {r['service']} | State: {r['state']}")
        elif choice == '3':
            ip = input("Enter target IP for OS detection: ")
            results = nmap_os_scan(ip)
            for host, data in results.items():
                print(f"\n[+] OS Fingerprint for {host}:")
                if data['osmatch']:
                    for os in data['osmatch']:
                        print(f" - OS Guess: {os['name']} ({os['accuracy']}%)")
                else:
                    print(" - No OS match found.")
        elif choice == '4':
            print("Exiting. Goodbye! 👋")
            break
        else:
            print("❌ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
