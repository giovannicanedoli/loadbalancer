import socket
import threading
import argparse
from time import sleep

# Basic TCP client
GATEWAY_IP = "10.0.0.1"
BASE_MESSAGE = "Pox is awesome!"


def build_payload(payload_size):
    """
    Build a payload of exactly `payload_size` bytes.
    The payload starts with BASE_MESSAGE and is padded to reach the desired size.
    If payload_size <= len(BASE_MESSAGE), the base message is returned as-is.
    """
    base_len = len(BASE_MESSAGE)
    if payload_size <= base_len:
        return BASE_MESSAGE
    padding = "X" * (payload_size - base_len)
    return BASE_MESSAGE + padding


def start_client(host=GATEWAY_IP, port=65432, payload_size=0, thread_id=0):
    """Single client connection loop."""
    message = build_payload(payload_size) if payload_size > 0 else BASE_MESSAGE
    tag = f"[Thread-{thread_id}]"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"{tag} Connecting to {host}:{port}...")
        s.connect((host, port))

        while True:
            s.sendall(message.encode())
            print(f"{tag} Sent ({len(message)} bytes): {message[:60]}{'...' if len(message) > 60 else ''}")

            data = s.recv(4096)
            print(f"{tag} Received: {data.decode()}")
            sleep(1)


def main():
    parser = argparse.ArgumentParser(description="Multithreaded TCP client")
    parser.add_argument("--threads", type=int, default=1, help="Number of concurrent client threads")
    parser.add_argument("--payload-size", type=int, default=0,
                        help="Total payload size in bytes (0 = just the base message)")
    args = parser.parse_args()

    threads = []
    for i in range(args.threads):
        t = threading.Thread(
            target=start_client,
            args=(GATEWAY_IP, 65432, args.payload_size, i),
            daemon=True,
        )
        threads.append(t)
        t.start()

    # Keep the main thread alive until Ctrl-C
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
