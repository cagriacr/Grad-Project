import manuf
from scapy.all import ARP, Ether, srp

def arp_scan(ip_range):
    arp_request = ARP(pdst=ip_range) # ARP istek paketi oluştur
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        mac_address = element[1].hwsrc #Yanıttan MAC adresini al
        vendor = manuf.MacParser().get_manuf(mac_address) # MAC adresinden üreticiyi al manuf lib kullanarak
        devices.append({"ip": element[1].psrc, "mac": mac_address, "vendor": vendor})
    return devices

if __name__ == "__main__":
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    
    print("Scanning for devices in the network...")
    devices = arp_scan(ip_range)
    
    print("\nDevices found in the network:")
    print("IP Address\t\tMAC Address\t\tMAC Vendor")
    print("-------------------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t{device['vendor']}")
