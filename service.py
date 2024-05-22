import socket

def get_service(port):
    try:
        # soket objesi oluşur
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
            # dönen cevap  ise port açık demektir
            if result == 0:
                service = get_service(port)
                open_ports.append((port, service))
                print(f"Port {port} is open (TCP) - Service: {service}")
            # soket kapanır
            s.close()
        except Exception as e:
            print(f"Error occurred while scanning port {port}: {e}")

    return open_ports

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")

    open_ports = port_scan(target_ip)
    print("Open ports:", open_ports)
