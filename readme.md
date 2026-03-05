# SDN Load Balancer with POX and Kathará

This project implements a Software-Defined Networking (SDN) Load Balancer using the **POX** controller and the **Kathará** network emulation tool. The load balancer dynamically distributes traffic from multiple clients to multiple servers based on their current load.

## 🌐 Network Topology

The network consists of:
- **4 Clients**: Located in the `10.0.0.0/24` subnet.
- **3 Servers**: Located in the `10.0.1.0/24` subnet.
- **1 OpenFlow Switch (s1)**: Connects all hosts and the controller.
- **1 POX Controller**: Manages the switch and implements the load balancing logic.

All clients communicate with a virtual gateway IP (`10.0.0.1`), which the controller transparently maps to one of the backend servers.

## 🧠 Key Components

The controller logic is split into three main modules located in `controller/pox/ext/`:

### 1. `Discovery.py`
Automatically discovers hosts (clients and servers) in the network by sending proactive ARP requests when the switch connects. It categorizes hosts based on their subnet.

### 2. `ArpResolver.py`
Handles ARP requests from clients and servers. 
- When a client requests the MAC for the gateway (`10.0.0.1`), it replies with a virtual MAC.
- It ensures that clients only ever see the gateway IP, hiding the actual server IPs.

### 3. `LoadBalancer.py`
The core logic of the project. It selects the server having the **least ratio**: `current_load / max_capacity`:
- **Load Monitoring**: Periodically requests flow statistics from the switch to calculate the byte rate (B/s) for each server.
- **Decision Making**: When a new connection arrives, it selects the server with the lowest `current_load / max_capacity` ratio.
- **Capacity**: Each server has a defined `max_capacity`. If a server is overloaded, it is skipped.
- **Flow Installation**: Installs OpenFlow rules to rewrite packet headers (Destination IP/MAC for requests, Source IP/MAC for replies) to ensure seamless communication.

## 🚀 How to Run

### Prerequisites
- [Kathará](https://www.kathara.org/) installed.
- Docker installed and running.

### Starting the Lab
1. Navigate to the project root directory.
2. Start the Kathará lab:
   ```bash
   kathara lstart
   ```
   This will open terminals for all nodes. The controller will automatically start POX with the required extensions.

### Testing
You can use the provided scripts in the `shared/` directory to test the load balancer:
- **Servers**: Run `python3 /shared/server.py` on `server1`, `server2`, and `server3`.
- **Clients**: Run `python3 /shared/client.py` on any client node to send traffic. Use the `-h` flag to see the available options.

## 🛠 Project Structure
- `controller/`: POX controller configuration and custom extensions.
- `shared/`: Utility scripts for clients and servers.
- `lab.conf`: Kathará network configuration.
- `*.startup`: Startup scripts for each node.
