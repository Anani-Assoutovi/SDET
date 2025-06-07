
import time
import json
import os
import netifaces
from datetime import datetime
from scapy.all import (
    Ether, ARP, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr,
    srp, get_if_hwaddr, AsyncSniffer
)
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

DEVICE_DB_FILE = "devices_combined.json"
EVENT_LOG_FILE = "network_events_combined.log"
SCAN_INTERVAL = 60
ip_mac_map = {}
known_devices = {}

def get_active_interfaces():
    interfaces = []
    for iface in netifaces.interfaces():
        if iface.startswith("lo"):
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs:
            interfaces.append(iface)
    return interfaces

def load_known_devices():
    try:
        with open(DEVICE_DB_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_known_devices(devices):
    try:
        with open(DEVICE_DB_FILE, "w") as f:
            json.dump(devices, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to save device DB: {e}")

def log_event(event_type, src_ip, mac, detail):
    entry = {
        "time": datetime.now().isoformat(),
        "type": event_type,
        "src_ip": src_ip,
        "mac": mac,
        "detail": detail
    }
    try:
        with open(EVENT_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[!] Failed to write event log: {e}")

def scan_ipv4_devices():
    discovered = []
    for iface in get_active_interfaces():
        try:
            ipv4_info = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0]
            if 'addr' not in ipv4_info:
                continue
            ip = ipv4_info['addr']
            subnet = '.'.join(ip.split('.')[:-1]) + '.1/24'
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            ans, _ = srp(pkt, iface=iface, timeout=3, verbose=0)
            for _, r in ans:
                discovered.append({
                    "iface": iface,
                    "ip": r.psrc,
                    "mac": r.hwsrc,
                    "version": 4
                })
                ip_mac_map[r.psrc] = r.hwsrc
        except Exception as e:
            print(f"[!] IPv4 scan failed on {iface}: {e}")
    return discovered

def scan_ipv6_devices():
    discovered = []
    for iface in get_active_interfaces():
        try:
            if netifaces.AF_INET6 not in netifaces.ifaddresses(iface):
                continue
            src_mac = get_if_hwaddr(iface)
            dst = f"ff02::1%{iface}"
            pkt = Ether(dst="33:33:00:00:00:01") /                   IPv6(dst=dst) /                   ICMPv6ND_NS() /                   ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
            ans, _ = srp(pkt, iface=iface, timeout=5, multi=True, verbose=0)
            for _, r in ans:
                ip6 = r[IPv6].src
                mac = r.src
                discovered.append({
                    "iface": iface,
                    "ip": ip6,
                    "mac": mac,
                    "version": 6
                })
                ip_mac_map[ip6] = mac
        except Exception as e:
            print(f"[!] IPv6 scan failed on {iface}: {e}")
    if not discovered:
        print("[i] No IPv6 scan responses received (sniffer may still detect activity).")
    return discovered

def handle_packet(pkt):
    try:
        if IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            mac = pkt.src  # Use MAC from Layer 2
            ip_mac_map[src] = mac
            if mac not in known_devices:
                known_devices[mac] = {
                    "ip": src,
                    "mac": mac,
                    "version": 6,
                    "iface": "unknown",
                    "status": "online",
                    "first_seen": datetime.now().isoformat()
                }
                log_event("NEW (sniffed)", src, mac, "Detected via IPv6 sniffing")
            known_devices[mac]["last_seen"] = datetime.now().isoformat()
            known_devices[mac]["status"] = "online"
            log_event("IPv6", src, mac, f"→ {dst}")
        elif ARP in pkt:
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            mac = pkt[ARP].hwsrc
            log_event("IPv4", src, mac, f"→ {dst}")
    except Exception as e:
        print(f"[!] Packet handling error: {e}")

def reconstruct_known_devices_from_log():
    try:
        with open(EVENT_LOG_FILE, "r") as f:
            for line in f:
                if "New device detected" in line:
                    parts = line.strip().split(" - New device detected: ")
                    if len(parts) != 2:
                        continue
                    payload = parts[1]
                    mac, raw_data = payload.split(" - ", 1)
                    device = json.loads(raw_data.replace("'", '"'))  # crude but works

                    mac = mac.strip()
                    if mac not in known_devices:
                        known_devices[mac] = device
                        known_devices[mac]["first_seen"] = parts[0]
                    known_devices[mac]["last_seen"] = parts[0]
    except FileNotFoundError:
        print("Log file not found.")
    with open(DEVICE_DB_FILE, "w") as f:
        json.dump(known_devices, f, indent=2)
    print(f"[✓] Reconstructed {len(known_devices)} devices from log")


def start_monitoring(socketio=None):
    global known_devices
    print("[*] Starting dual-stack network monitor with sniffer-assisted discovery...")
    #known_devices = load_known_devices()
    known_devices.update(load_known_devices())
    AsyncSniffer(filter="ip or ip6 or arp", prn=handle_packet, store=0).start()
    reconstruct_known_devices_from_log()

    while True:
        ipv4_devices = scan_ipv4_devices()
        ipv6_devices = scan_ipv6_devices()
        seen_now = {d["mac"]: d for d in ipv4_devices + ipv6_devices}

        for mac, device in known_devices.items():
            if mac in seen_now:
                if device.get("status") != "online":
                    device["status"] = "online"
                    device["last_seen"] = datetime.now().isoformat()
                    log_event("ONLINE", device["ip"], mac, "Device back online")
            else:
                if device.get("status") != "offline":
                    device["status"] = "offline"
                    log_event("OFFLINE", device["ip"], mac, "Device went offline")

        for mac, device in seen_now.items():
            if mac not in known_devices:
                print(f'The Mac "{mac}" was NOT found in the known devices.')
                device["first_seen"] = datetime.now().isoformat()
                device["last_seen"] = datetime.now().isoformat()
                device["status"] = "online"
                log_event("NEW", device["ip"], mac, "New device discovered")
            else:
                known_devices[mac].update(device)
                print(f'The Mac "{mac}" WAS found in the known devices.')

        save_known_devices(known_devices)

        if socketio:
            online = [d for d in known_devices.values() if d["status"] == "online"]
            ipv4_online = [d for d in online if d["version"] == 4]
            ipv6_online = [d for d in online if d["version"] == 6]
            # Inject a fallback device if lists are empty
            print("[Emit] Sending known devices:", json.dumps(known_devices, indent=2))
            socketio.emit("devices", ipv4_online)
            socketio.emit("ipv6_devices", ipv6_online)
        print(f"[✓] Devices - IPv4: {len(ipv4_devices)} | IPv6: {len(ipv6_devices)} | Total Known: {len(known_devices)}")
        time.sleep(SCAN_INTERVAL)

