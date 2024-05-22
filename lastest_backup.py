import argparse
import subprocess
import manuf
import requests
import socket
import ipaddress
from scapy.all import ARP, Ether, srp
 
def ping_broadcast():
    subprocess.call(['ping', '-c', '1', '-b', '255.255.255.255'])
 
def arp_scan(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
 
    devices = []
    for element in answered_list:
        mac_address = element[1].hwsrc
        if element[1].psrc != subprocess.getoutput("hostname -I").split()[0]:
            vendor = manuf.MacParser().get_manuf(mac_address)
            devices.append({"ip": element[1].psrc, "mac": mac_address, "vendor": vendor})
    return devices
 
def scan(ip_range):
    if '/' in ip_range: # IP aralığı girilmişse
        ip_block = ipaddress.ip_network(ip_range, strict=False)
        ip_addresses = [str(ip) for ip in ip_block.hosts()]
    else: # Tek IP aralığı girilmişse
        ip_addresses = [ip_range]
 
    connected_devices = []
    for ip_address in ip_addresses:
        arp_request = ARP(pdst=ip_address)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = ether / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
 
        for element in answered_list:
            local_ip = subprocess.getoutput("hostname -I").split()[0]
            if element[1].psrc != local_ip:
                connected_devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
 
    return connected_devices
 
def get_vendor(mac_address):
    try:
        return manuf.MacParser().get_manuf(mac_address)
    except:
        return "Unknown"
 
def get_http_banner(ip_address):
    try:
        response = requests.get(f"http://{ip_address}")
        return response.headers.get('Server', 'Unknown')
    except:
        return "Unknown"
 
def port_scan(ip_address, all_ports=False, verbose=False):
    if all_ports:
        port_range = range(1, 65536) # tüm portları tara
    else:
        port_range = range(1, 1025) # top portları tara
 
    open_ports = []
    services = {}
 
    # servis port sözlüğü
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        123: 'NTP',
        179: 'BGP',
        443: 'HTTPS',
        # istenilen port ve servisler listenin devamına eklenebilir.
    }
 
    for port in port_range:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
                    # Açık bağlantı noktasının herhangi bir ortak bağlantı noktasıyla eşleşip eşleşmediğini kontrol edin
                    if port in common_ports:
                        services[port] = common_ports[port]
                        # servis bilgisi için banner grabbing methodu
                        banner = get_banner(ip_address, port)
                        if banner != "Unknown":
                            services[port] += f" ({banner})"
                    elif verbose:
                        banner = get_banner(ip_address, port)
                        services[port] = banner
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
 
    return open_ports, services
 
def get_banner(ip_address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip_address, port))
            s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            banner = s.recv(1024)
            return banner.decode().strip()
    except Exception as e:
        return "Unknown"
 
def main():
    parser = argparse.ArgumentParser(description='Scan for connected entities and open ports.')
    parser.add_argument('ip_range', metavar='IP_RANGE', type=str, help='IP address or IP address range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode, display running services')
    parser.add_argument('-p', '--all-ports', action='store_true', help='Scan all ports')
    parser.add_argument('-a', '--arp-scan', action='store_true', help='Perform ARP scan to find devices in the network')
    args = parser.parse_args()
 
    if args.arp_scan:
        print("Scanning for devices in the network using ARP...")
        connected_entities = arp_scan(args.ip_range)
 
        print("\n Devices in the network:")
        print("IP Address\t\tMAC Address\t\t\tMAC Vendor")
        print("------------------------------------------------------------------")
        for entity in connected_entities:
            print(f"{entity['ip']}\t\t{entity['mac']}\t\t{entity['vendor']}")
    else:
        ip_range = args.ip_range
        if '/' not in ip_range: 
            ip_range = f"{ip_range}/32"
 
        # tüm cihazlara broadcast adresine ping at cihazları bulmak için
        ping_broadcast()
        print("Scanning for connected entities...")
        connected_entities = scan(ip_range)
 
        print("Connected entities within the given IP block:")
        print("IP Address\t\tMAC Address\t\tVendor\t\tHTTP Server\t\tOpen Ports")
        print("--------------------------------------------------------------------------------------------------")
        for entity in connected_entities:
            vendor = get_vendor(entity['mac'])
            http_banner = get_http_banner(entity['ip'])
            open_ports, services = port_scan(entity['ip'], args.all_ports, args.verbose)
            print(f"{entity['ip']}\t\t{entity['mac']}\t\t\t{vendor}\t\t\t{http_banner}\t\t\t{services}")
            if args.verbose:
                if open_ports:
                    print("Open Ports:")
                    for port in open_ports:
                        print(f"Port {port}: {services.get(port, 'Unknown')}")
 
if __name__ == "__main__":
    main()
