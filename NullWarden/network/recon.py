from __future__ import annotations

import socket
from typing import Dict, List, Optional

import psutil
import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    import nmap
    from scapy.all import ARP, Ether, sniff, srp
except Exception:
    nmap = None
    ARP = Ether = sniff = srp = None


console = Console()


def get_local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip_address = sock.getsockname()[0]
    except Exception:
        ip_address = "127.0.0.1"
    finally:
        sock.close()
    return ip_address


def get_public_ip() -> str:
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except Exception:
        return "Unavailable"


def show_host_info() -> None:
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    hostname = socket.gethostname()
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent

    table = Table(title="Host System Information", box=box.ROUNDED, style="bold cyan")
    table.add_column("Property", style="yellow")
    table.add_column("Value", style="green")
    table.add_row("Hostname", hostname)
    table.add_row("Local IP", local_ip)
    table.add_row("Public IP", public_ip)
    table.add_row("CPU Usage", f"{cpu_percent}%")
    table.add_row("Memory Usage", f"{memory_percent}%")
    console.print(table)


def discover_devices(network: Optional[str] = None) -> List[Dict[str, str]]:
    if ARP is None or Ether is None or srp is None:
        console.print("ARP discovery requires scapy. Please install scapy and run as admin.")
        return []

    if not network:
        octets = get_local_ip().split(".")
        network = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"

    console.print(f"Scanning network: {network} ...")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices: List[Dict[str, str]] = []
    for _sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    table = Table(title="Discovered Devices", box=box.DOUBLE_EDGE, style="bold cyan")
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="yellow")
    for device in devices:
        table.add_row(device["ip"], device["mac"])

    console.print(table)
    return devices


def scan_ports(target_ip: str) -> None:
    if nmap is None:
        console.print("Port scanning requires python-nmap. Please install it.")
        return

    console.print(f"Scanning ports on {target_ip} ...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-T4 -F")

    table = Table(title=f"Open Ports for {target_ip}", box=box.ROUNDED, style="bold cyan")
    table.add_column("Port", style="yellow")
    table.add_column("Protocol", style="green")
    table.add_column("Service", style="magenta")

    if target_ip not in nm.all_hosts():
        console.print(f"Host {target_ip} is unreachable or down")
        return

    for proto in nm[target_ip].all_protocols():
        for port in nm[target_ip][proto].keys():
            service = nm[target_ip][proto][port]["name"]
            table.add_row(str(port), proto, service)

    console.print(table)


def capture_traffic(interface: Optional[str] = None, packet_count: int = 50) -> None:
    if sniff is None:
        console.print("Traffic capture requires scapy. Please install scapy and run as admin.")
        return

    console.print(f"Capturing {packet_count} packets...")

    def packet_callback(pkt):
        try:
            if ARP is not None and pkt.haslayer(ARP):
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst
            elif Ether is not None and pkt.haslayer(Ether):
                src = pkt[Ether].src
                dst = pkt[Ether].dst
            else:
                src = getattr(pkt, "src", "?")
                dst = getattr(pkt, "dst", "?")
            console.print(f"{src} -> {dst}")
        except Exception as exc:
            console.print(f"[warn] parse error: {exc}")

    sniff(count=packet_count, prn=packet_callback, iface=interface)


def run_cli_loop() -> None:
    console.print(Panel.fit("CyberRecon - Ethical Network Recon Tool", style="bold magenta"))

    while True:
        try:
            command = console.input("CyberRecon> ").strip()
            if command.lower() in ["exit", "quit"]:
                console.print("Exiting CyberRecon...")
                break
            if command.lower() == "/host":
                show_host_info()
                continue
            if command.lower() == "/scan":
                discover_devices()
                continue
            if command.startswith("/ports"):
                parts = command.split()
                if len(parts) != 2:
                    console.print("Usage: /ports <IP>")
                else:
                    scan_ports(parts[1])
                continue
            if command.startswith("/geo"):
                parts = command.split()
                if len(parts) != 2:
                    console.print("Usage: /geo <IP>")
                else:
                    ip = parts[1]
                    ip_geolocation(ip)
                continue
            if command.startswith("/traffic"):
                capture_traffic()
                continue

            console.print("Unknown command")
            console.print("Commands: /host, /scan, /ports <IP>, /geo <IP>, /traffic, exit")
        except KeyboardInterrupt:
            console.print("\nExiting CyberRecon...")
            break


def ip_geolocation(ip: str) -> None:
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if response.get("status") == "success":
            panel = Panel.fit(
                f"IP: {ip}\n"
                f"Country: {response.get('country')}\n"
                f"Region: {response.get('regionName')}\n"
                f"City: {response.get('city')}\n"
                f"ISP: {response.get('isp')}\n"
                f"Org: {response.get('org')}",
                title="IP Geolocation",
                style="bold green",
            )
            console.print(panel)
        else:
            console.print(f"Failed to retrieve geolocation for {ip}")
    except Exception as exc:
        console.print(f"Error: {exc}")


