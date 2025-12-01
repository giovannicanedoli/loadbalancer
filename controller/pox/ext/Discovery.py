import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.recoco import Timer
from pox.lib.util import dpidToStr

log = core.getLogger()

MAX_CLIENT = 3
MAX_SERVER = 3
MIN_SWITCH = 1

class Discovery:
    def __init__(self):

        # adds the hostDiscovery instance as a listener to OpenFlow-related events
        core.openflow.addListeners(self)

        # dictionary to store information about discovered hosts
        self.clients = {}
        self.servers = {}

        # dictionary to store information about switches
        self.switches = {}

        self.prev_traffic = {}

        # dictionary to map switch identifiers to switch datapath IDs
        self.sw_id = {}

        # list for all rememeber all connections
        self.connections_list = []
        self.switch_connection = None # save switch connection

        # id to count connections_list
        self.id = 1

        # initializes fake MAC address for the gateway.
        self.fake_mac_gw = EthAddr("00:00:00:00:11:11")

        self.time_period = 5

        # Start a single timer that handles both Probes and Stats Requests
        Timer(self.time_period, self._timer_func, recurring=True)

    def _handle_ConnectionUp(self, event):
        # Event handler method that is called when a new OpenFlow connection is established

        # Associates the current connection ID with the switch ID
        self.sw_id[self.id] = event.dpid

        # # Stores information about switch
        self.switches[event.dpid] = event.ofp.ports

        # adds the new connection to the list of connections
        self.connections_list.append(event.connection)
        self.switch_connection = event.connection
        print("Connection Up: " + dpidToStr(event.dpid) + ", " + str(self.id))

        print("Installing flow for current switch...", end=" ")
        self.install_flow_rule(event.dpid)
        print("done.")

        # run the search of the host, when all switches have been found
        if self.id >= MIN_SWITCH:
            log.info("Launching, LI MORTACCI TUA!")
            self.search_host()

        # increment connection ID
        self.id += 1

    def search_host(self):

        print("host discovering")

        # calls the hostDiscovery method for each connection
        for connection in self.connections_list:

            # Iterates through a max number of clients
            for h in range(1, MAX_CLIENT + 1):
                # Constructs an ARP request packet with a fake MAC address, and ARP request opcode
                arp_req = arp()
                arp_req.hwsrc = self.fake_mac_gw
                arp_req.opcode = arp.REQUEST
                arp_req.protosrc = IPAddr("10.0.0.100") #protocol associated with fake mac addess


                arp_req.protodst = IPAddr(f"10.0.0.1{h}")

                # Constructs an Ethernet frame containing the ARP request packet
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = EthAddr.BROADCAST
                ether.src = self.fake_mac_gw
                ether.payload = arp_req

                # Constructs an OpenFlow packet-out message
                msg = of.ofp_packet_out()
                msg.data = ether.pack()

                # Adds action to flood the ARP message to all ports and sends the message
                msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
                connection.send(msg)
            
            # Iterates through a max number of servers
            for h in range(1, MAX_SERVER + 1):
                # Constructs an ARP request packet with a fake MAC address, and ARP request opcode
                arp_req = arp()
                arp_req.hwsrc = self.fake_mac_gw
                arp_req.opcode = arp.REQUEST
                arp_req.protosrc = IPAddr("10.0.0.100") #protocol associated with fake mac addess


                arp_req.protodst = IPAddr(f"10.0.0.{h}")

                # Constructs an Ethernet frame containing the ARP request packet
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = EthAddr.BROADCAST
                ether.src = self.fake_mac_gw
                ether.payload = arp_req

                # Constructs an OpenFlow packet-out message
                msg = of.ofp_packet_out()
                msg.data = ether.pack()

                # Adds action to flood the ARP message to all ports and sends the message
                msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
                connection.send(msg)

    def _handle_PacketIn(self, event):
        # Extracts the parsed Ethernet frame from the incoming packet
        eth_frame = event.parsed

        # Checks if the frame type is ARP and the destination MAC address is the fake mac
        if eth_frame.type == ethernet.ARP_TYPE and eth_frame.dst == self.fake_mac_gw:

            arp_message = eth_frame.payload

            # Checks if the ARP packet is a reply
            if arp_message.opcode == arp.REPLY:

                ip_host = arp_message.protosrc
                mac_host = arp_message.hwsrc
                stringified_ip_host = str(ip_host)
                if stringified_ip_host[-2] == '1' and ip_host not in self.servers: #case we have a server
                    self.servers[ip_host] = {"switch": event.dpid, "port": event.port, "mac": mac_host}

                    # take the switch ID from linkDiscovery
                    dict_sw_id = self.sw_id
                    sw_id = [key for key, value in dict_sw_id.items() if value == event.dpid]

                    # convert sw_dpid in string type
                    sw_dpid = dpidToStr(self.servers[ip_host]["switch"])
                    port = self.servers[ip_host]["port"]
                    
                    log.info(f"  ->  server {ip_host} is connected to switch {sw_id, sw_dpid} through switch port {port}")

                elif ip_host not in self.clients:
                    self.clients[ip_host] = {"switch": event.dpid, "port": event.port, "mac": mac_host}

                    # take the switch ID from linkDiscovery
                    dict_sw_id = self.sw_id
                    sw_id = [key for key, value in dict_sw_id.items() if value == event.dpid]

                    # convert sw_dpid in string type
                    sw_dpid = dpidToStr(self.clients[ip_host]["switch"])
                    port = self.clients[ip_host]["port"]
                    
                    log.info(f"  ->  client {ip_host} is connected to switch {sw_id, sw_dpid} through switch port {port}")
        #should I compute this for any pair of nw_src and nw_dst?
    
    def _handle_FlowStatsReceived(self, event):
        dpid = event.dpid
        
        # Dictionary to store total bytes for each unique (src, dst) pair in this current batch
        # Key: (src_ip, dst_ip), Value: total_bytes
        current_flow_totals = {}

        # 1. Iterate through ALL flows and aggregate bytes by Src/Dst pair
        for f in event.stats:
            # Check if flow has IP addresses (avoids crashes on ARP/LLDP or wildcard flows)
            if f.match.nw_src and f.match.nw_dst:
                key = (f.match.nw_src, f.match.nw_dst)
                
                # Add to total (handles cases where you have multiple flows for same IPs but different Ports)
                current_flow_totals[key] = current_flow_totals.get(key, 0) + f.byte_count
        
        # 2. Initialize history for this switch if it doesn't exist
        # New Structure of self.prev_traffic: { dpid: { (src, dst): prev_bytes } }
        if dpid not in self.prev_traffic:
            self.prev_traffic[dpid] = {}
        
        switch_history = self.prev_traffic[dpid]
        
        print(f"--- Traffic Report for Switch {dpidToStr(dpid)} ---")

        # 3. Calculate Rate for each pair found
        for (src, dst), rec_bytes in current_flow_totals.items():
            
            # Retrieve previous byte count for this specific IP pair
            prev_bytes = switch_history.get((src, dst), 0)
            
            # Handle potential counter resets
            if rec_bytes < prev_bytes:
                diff = rec_bytes 
            else:
                diff = rec_bytes - prev_bytes
                
            rate = diff / self.time_period
            
            # Update history for this specific pair
            switch_history[(src, dst)] = rec_bytes
            
            # Output result
            print(f"  {src} -> {dst} : {rate} bytes/sec")

    def _timer_func(self):
        self.send_stat_req()

    def send_stat_req(self):
        connection = self.switch_connection
        #print(self.sw_id)
        dpid = self.sw_id[1]
        try:
            msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
            connection.send(msg)
        except Exception as e:
            print(f"Error sending stats request to {dpidToStr(dpid)}: {e}")

        
    @staticmethod
    def install_flow_rule(dpid):
        # Install proactive rule to catch discovery probes
        msg = of.ofp_flow_mod()
        msg.priority = 50000
        match = of.ofp_match(dl_src=EthAddr("00:11:22:33:44:55"))
        msg.match = match
        msg.actions = [of.ofp_action_output(port=of.OFPP_CONTROLLER)]
        core.openflow.sendToDPID(dpid, msg)

def launch():
    core.registerNew(Discovery)