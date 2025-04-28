#!/usr/bin/env python3

import nmap

def nmap_host_discovery(network):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=network, arguments='-sn -T3')  # Ping Scan
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
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments='-sV -T3')  # Service version detection
    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                result = {
                    'host': host,
                    'port': port,
                    'state': scanner[host][proto][port]['state'],
                    'service': scanner[host][proto][port]['name'],
                    'mac': scanner[host]['addresses'].get('mac', 'N/A')
                }
                results.append(result)
    return results

def nmap_os_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-O -T3')  # OS fingerprinting
    os_results = {}
    for host in scanner.all_hosts():
        host_info = {
            'osmatch': scanner[host].get('osmatch', []),
            'mac': scanner[host]['addresses'].get('mac', 'N/A')
        }
        os_results[host] = host_info
    return os_results

# ------------------- Example Usage --------------------

if __name__ == "__main__":
    target_network = "192.168.200.0/24"

    print("\n[*] Host Discovery:")
    live_hosts = nmap_host_discovery(target_network)
    for host in live_hosts:
        print(f" - {host['host']} | State: {host['state']} | MAC: {host['mac']}")

    print("\n[*] Port Scan Results:")
    for host in live_hosts:
        ports = nmap_portscan(host['host'])
        for p in ports:
            print(f" - {p['host']}:{p['port']} | {p['service']} | {p['state']}")

    print("\n[*] OS Fingerprinting:")
    for host in live_hosts:
        os_info = nmap_os_scan(host['host'])
        for h, data in os_info.items():
            print(f" - {h} | MAC: {data['mac']}")
            if data['osmatch']:
                for os in data['osmatch']:
                    print(f"    OS Guess: {os['name']} ({os['accuracy']}%)")
            else:
                print("    OS Guess: Not Available")
