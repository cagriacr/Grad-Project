import socket

def get_service_version(port):
    if port == 80:  # HTTP servisi için örnek tarama
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, port))
            s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            response = s.recv(1024)
            # Apache HTTP Sunucusu'nun versiyonu "Server" başlığında bulunabilir
            version_index = response.find(b"Server: ") + len(b"Server: ")
            version = response[version_index:].split(b"\r\n")[0].decode()
            s.close()
            return version
        except Exception as e:
            return "Unknown"
    else:
        return "N/A"

def get_service(port):
    try:
        # soket oluşur
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target_ip, port))
        # servis ismi alınır
        service = socket.getservbyport(port)
        # soket kapanır
        s.close()
        return service
    except Exception as e:
        return "Unknown"

def port_scan(target_ip):
    open_ports = []

    start_port = 0
    end_port = 65535

    for port in range(start_port, end_port + 1):
        try:
            # soket oluşur
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target_ip, port))
            # dönen cevap 0 ise port açık demektir
            if result == 0:
                service = get_service(port)
                service_version = get_service_version(port)
                open_ports.append((port, service, service_version))
                print(f"Port {port} is open (TCP) - Service: {service} - Version: {service_version}")
            # soket kapanır
            s.close()
        except Exception as e:
            print(f"Error occurred while scanning port {port}: {e}")

    return open_ports

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")

    open_ports = port_scan(target_ip)
    print("Open ports:", open_ports)
