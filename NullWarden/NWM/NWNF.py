import socket
import requests
import psutil
from scapy.all import ARP, Ether, srp, sniff
import nmap
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except Exception:
        return "Unavailable"

def show_host_info():
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    hostname = socket.gethostname()
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent

    table = Table(title="Host System Information", box=box.ROUNDED, style="bold cyan")
    table.add_column("Property", style="yellow")
    table.add_column("Value", style="green")
    table.add_row("Hostname", hostname)
    table.add_row("Local IP", local_ip)
    table.add_row("Public IP", public_ip)
    table.add_row("CPU Usage", f"{cpu}%")
    table.add_row("Memory Usage", f"{mem}%")
    console.print(table)

def discover_devices(network=None):
    if not network:
        ip_parts = get_local_ip().split(".")
        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    console.print(f"Scanning network: {network} ...")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    table = Table(title="Discovered Devices", box=box.DOUBLE_EDGE, style="bold cyan")
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="yellow")
    for device in devices:
        table.add_row(device['ip'], device['mac'])

    console.print(table)
    return devices

def scan_ports(target_ip):
    console.print(f"Scanning ports on {target_ip} ...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-T4 -F')

    table = Table(title=f"Open Ports for {target_ip}", box=box.ROUNDED, style="bold cyan")
    table.add_column("Port", style="yellow")
    table.add_column("Protocol", style="green")
    table.add_column("Service", style="magenta")

    if target_ip not in nm.all_hosts():
        console.print(f"Host {target_ip} is unreachable or down")
        return

    for proto in nm[target_ip].all_protocols():
        lport = nm[target_ip][proto].keys()
        for port in lport:
            service = nm[target_ip][proto][port]['name']
            table.add_row(str(port), proto, service)

    console.print(table)

def capture_traffic(interface=None, packet_count=50):
    console.print(f"Capturing {packet_count} packets...")

    def packet_callback(pkt):
        if pkt.haslayer(ARP):
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
        elif pkt.haslayer(Ether):
            src = pkt[Ether].src
            dst = pkt[Ether].dst
        else:
            src = getattr(pkt, 'src', '?')
            dst = getattr(pkt, 'dst', '?')
        console.print(f"{src} -> {dst}")

    sniff(count=packet_count, prn=packet_callback, iface=interface)

def ip_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        if response['status'] == 'success':
            panel = Panel.fit(
                f"IP: {ip}\n"
                f"Country: {response['country']}\n"
                f"Region: {response['regionName']}\n"
                f"City: {response['city']}\n"
                f"ISP: {response['isp']}\n"
                f"Org: {response['org']}",
                title="IP Geolocation", style="bold green"
            )
            console.print(panel)
        else:
            console.print(f"Failed to retrieve geolocation for {ip}")
    except Exception as e:
        console.print(f"Error: {e}")

def main():
    console.print(Panel.fit("CyberRecon - Ethical Network Recon Tool", style="bold magenta"))

    while True:
        try:
            command = console.input("CyberRecon> ").strip()
            if command.lower() in ['exit', 'quit']:
                console.print("Exiting CyberRecon...")
                break
            elif command.lower() == '/host':
                show_host_info()
            elif command.lower() == '/scan':
                discover_devices()
            elif command.startswith('/ports'):
                parts = command.split()
                if len(parts) != 2:
                    console.print("Usage: /ports <IP>")
                else:
                    scan_ports(parts[1])
            elif command.startswith('/geo'):
                parts = command.split()
                if len(parts) != 2:
                    console.print("Usage: /geo <IP>")
                else:
                    ip_geolocation(parts[1])
            elif command.startswith('/traffic'):
                capture_traffic()
            else:
                console.print("Unknown command")
                console.print("Commands: /host, /scan, /ports <IP>, /geo <IP>, /traffic, exit")
        except KeyboardInterrupt:
            console.print("\nExiting CyberRecon...")
            break

if __name__ == "__main__":
    main()
