import argparse
import subprocess
import nmap
import ipaddress
import manuf # MAC ve MAC sağlayıcısını bulmak için
from scapy.all import ARP, Ether, srp

def ping_broadcast():
    subprocess.call(['ping', '-c', '1', '-b', '255.255.255.255'])

# Verilen IP aralığında ARP taraması yapan fonksiyon
def arp_scan(ip_range):
    arp_request = ARP(pdst=ip_range) # ARP istek paketi oluştur
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        mac_address = element[1].hwsrc #Yanıttan MAC adresini al
        ip_address = element[1].psrc  # Yanıttan IP adresini al
        vendor = manuf.MacParser().get_manuf(mac_address) # MAC adresinden üreticiyi al
        devices.append({"ip": ip_address, "mac": mac_address, "vendor": vendor})
    return devices

# Bir MAC adresinden ARP kullanarak üreticiyi alan fonksiyon
def get_vendor(mac_address):
    try:
        output = subprocess.check_output(['arp', '-n', mac_address]).decode('utf-8').strip()
        vendor = output.split()[2]
        return vendor
    except Exception as e:
        return "Unknown"

# Ağdaki bağlı cihazları ARP kullanarak tarayan fonksiyon
def scan(ip_range, all_ports=False):
    if '/' in ip_range:
        ip_block = ipaddress.ip_network(ip_range, strict=False)
        ip_addresses = [str(ip) for ip in ip_block.hosts()]
    else:
        ip_addresses = [ip_range]

    connected_devices = []
    for ip_address in ip_addresses:
        arp_request = ARP(pdst=ip_address) # ARP istek paketi oluştur
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = ether / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        for element in answered_list:
            local_ip = subprocess.getoutput("hostname -I").split()[0]
            if element[1].psrc != local_ip:
                connected_devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return connected_devices

def service_scan(ip_address, all_ports=False, version_scan=False):
    nm = nmap.PortScanner()
    arguments = '-Pn'
    if all_ports:
        arguments += ' -p-'
    if version_scan:
        arguments += ' -sV'
    nm.scan(ip_address, arguments=arguments)

    open_services = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                service_name = nm[host][proto][port]['name']
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                if product and version:
                    service_version = f"{product} {version}"
                elif product:
                    service_version = f"{product}"
                else:
                    service_version = f"{service_name}"
                port_type = "TCP" if proto == 'tcp' else "UDP"
                open_services[port] = {'port_type': port_type, 'state': state, 'service': service_name, 'version': service_version}

    return open_services


# Komut satırı argümanlarını çözümleyip uygun tarama fonksiyonlarını çalıştıran ana fonksiyon
def main():
    parser = argparse.ArgumentParser(description='Scan for connected entities and open ports.')
    parser.add_argument('ip_range', metavar='IP_RANGE', type=str, help='IP address or IP address range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-v', '--version-scan', action='store_true', help='Perform version detection for open services')
    parser.add_argument('-p', '--all-ports', action='store_true', help='Scan all ports (1-65535)')
    parser.add_argument('-a', '--arp-scan', action='store_true', help='Perform ARP scan to find devices in the network')
    args = parser.parse_args()

    if args.arp_scan:
        print("Scanning for devices in the network using ARP...")
        connected_entities = arp_scan(args.ip_range)

        print("\nDevices in the network:")
        print("IP Address\t\tMAC Address\t\t\tMAC Vendor")
        print("------------------------------------------------------------------")
        for entity in connected_entities:
            mac_address = entity['mac']
            vendor = manuf.MacParser().get_manuf(mac_address) if mac_address else "Unknown"
            print(f"{entity['ip']}\t\t{entity['mac']}\t\t{vendor}")
    else:
        ip_range = args.ip_range
        if '/' not in ip_range:
            ip_range = f"{ip_range}/32"

        ping_broadcast()

        print("Scanning for connected entities...")
        connected_entities = scan(ip_range, args.all_ports)

        print("Open Services:")
        print("Port\t\tType\t\tState\t\tService", end="")
        if args.version_scan:
            print("\t\tVersion")
        else:
            print("")

        print("-----------------------------------------------------------")
        for entity in connected_entities:
            open_services = service_scan(entity['ip'], args.all_ports, args.version_scan)
            for port, service_info in open_services.items():
                port_type = service_info['port_type']
                state = service_info['state']
                service = service_info['service']
                version = service_info['version']
                if args.version_scan:
                    print(f"{port}\t\t{port_type}\t\t{state}\t\t{service}\t\t{version}")
                else:
                    print(f"{port}\t\t{port_type}\t\t{state}\t\t{service}")

if __name__ == "__main__":
    main()
