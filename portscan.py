import socket

def port_scan(target_ip):
    open_ports = []

    # tarama için portlar (0 to 65535)
    start_port = 0
    end_port = 65535

    for port in range(start_port, end_port + 1):
        try:
            # soket objesi oluşturulur
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Bağlantı girişimi için zaman aşımını 1 saniyeye ayarla
            s.settimeout(1)
            # Bağlantı noktasına bağlanmayı dene
            result = s.connect_ex((target_ip, port))
            # dönen cevap  ise port açık demektir
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} is open (TCP)")
            # soketi kapat
            s.close()
        except Exception as e:
            print(f"Error occurred while scanning port {port}: {e}")

    return open_ports

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")

    open_ports = port_scan(target_ip)
    print("Open ports:", open_ports)
