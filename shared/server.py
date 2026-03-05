import socket
import fcntl
import struct
import threading

def get_ip_address(ifname='eth0'):
    """Fetches the IP address associated with a specific network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Use fcntl to extract the interface's IP address
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except OSError:
        print("Failed to get IP address for eth0")
        return "127.0.0.1" # Fallback if eth0 isn't up

def handle_client(conn, addr, host):
    """Handles a single client connection in a separate thread."""
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break 
            print(f"Received: {data.decode()} from ipaddress {conn.getpeername()}")
            
            msg = f"It really is! And answered by server {host}"
            conn.sendall(msg.encode())
    print(f"Connection closed by {addr}")

def start_server(port=65432):
    # Dynamically grab the IP
    host = get_ip_address('eth0')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set socket option to reuse address (prevents 'Address already in use' errors)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        s.bind((host, port))
        s.listen()
        print(f"Server listening on eth0 ({host}):{port}...")
        
        while True:
            conn, addr = s.accept()
            # Spawn a new thread for each client connection
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, host), daemon=True)
            client_thread.start()

if __name__ == "__main__":
    start_server()