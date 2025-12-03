import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.recoco import Timer
from pox.lib.util import dpidToStr

log = core.getLogger()


class LoadBalancer:

    def __init__(self):

        # Listener for OpenFlow
        core.openflow.addListeners(self)

        # Dictionary to store flows
        self.dict_flows = {}

        # Store all flow stats
        self.flow_stats = {}

        self.max_capacity = 10000 #bytes

        self.time = 7

        # Timer to see flows situation in the network
        Timer(self.time, self.ask_FlowStats, recurring=True)

    def _handle_PacketIn(self, event):
        # event handler that extracts the parsed packet from it (the event)
        packet = event.parsed

        # Checks if the packet is an IPv4 packet
        if packet.find('ipv4'):
            # extracts the source and destination IP addresses from the IPv4 payload
            ip_packet = packet.payload
            source_ip = ip_packet.srcip
            destination_ip = ip_packet.dstip

            # call routing method
            self.routing_flows(source_ip, destination_ip)

            # creates a new ofp_packet_out message
            msg = of.ofp_packet_out()

            # sets data with the received packet
            msg.data = packet

            # adds an output action to send the packet to the table
            msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))

            # sends the message to the switch
            event.connection.send(msg)

    def routing_flows(self, src_host_ip, dst_host_ip):
        # greedy -> vai al primo server meno occupato
        switch_dpid = core.Discovery.switch_dpid
        #first handle clients
        if src_host_ip in core.Discovery.clients.keys():

            # pick best server
            chosen_server_ip = self.extract_min_ratio_server()
            
            if chosen_server_ip is None:
                print("No server available to handle request.")
                return
            
            server_mac = core.Discovery.servers[chosen_server_ip]["mac"]
            server_port = core.Discovery.servers[chosen_server_ip]["port"]
            
            print(f"Routing Client {src_host_ip} -> Selected Server {chosen_server_ip}")

            msg = of.ofp_flow_mod()
            msg.idle_timeout = 25
            msg.flags = of.OFPFF_SEND_FLOW_REM
            
            # Match traffic from Client to the gateway
            msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=src_host_ip, nw_dst=dst_host_ip)
            
            # set dest port, change destIP, destMAC
            msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
            msg.actions.append(of.ofp_action_nw_addr.set_dst(chosen_server_ip))
            msg.actions.append(of.ofp_action_output(port=server_port))

            # Save flow info
            self.dict_flows[(src_host_ip, dst_host_ip)] = msg
            
            core.openflow.sendToDPID(core.Discovery.switch_dpid, msg)

            # send the message to the destination switch
            core.openflow.sendToDPID(switch_dpid, msg)

        # Case 2: Traffic from Server -> Client (The Return path)
        elif src_host_ip in core.Discovery.servers:
            # Simple forwarding back to client port
            client_port = core.Discovery.clients[dst_host_ip]["port"]
            msg = of.ofp_flow_mod()
            msg.idle_timeout = 25
            msg.flags = of.OFPFF_SEND_FLOW_REM
            
            msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=src_host_ip, nw_dst=dst_host_ip)
            
            #client must see the packet arrive from 10.0.0.1, not from the server's ip
            msg.actions.append(of.ofp_action_nw_addr.set_src(core.ARP.gateway_IP))
            #set also the mac address to the gateway's one
            msg.actions.append(of.ofp_action_dl_addr.set_src(core.ARP.gateway_MAC))
            
            # send to the client's port
            msg.actions.append(of.ofp_action_output(port=client_port))
            
            core.openflow.sendToDPID(switch_dpid, msg)

        return 

    def _handle_FlowRemoved(self, event):
        # Checks if the flow removal is due to an idle timeout (it has been idle for too long)
        if event.idleTimeout:
            flow_match = event.ofp.match
            switch_dpid = core.Discovery.switch_dpid
            # tell that the flow has been removed
            log.warn(f"  ->  switch {switch_dpid} removed flow from {flow_match.nw_src} to {flow_match.nw_dst}")
            flow_key = (flow_match.nw_src, flow_match.nw_dst)
            if flow_key in self.dict_flows.keys():
                self.dict_flows.pop(flow_key)

    def extract_min_ratio_server(self):
        min_ratio = float('inf')
        best_server_ip = None

        #iterate through the servers
        for server_ip in core.Discovery.servers.keys():

            current_server_load = 0
            
            #check if server is receiving flow
            for (src_ip, dst_ip), byte_count in self.flow_stats.items():
                if str(src_ip) == str(server_ip):
                    current_server_load += byte_count
            

            ratio = current_server_load / self.max_capacity
            if ratio < min_ratio:
                min_ratio = ratio
                best_server_ip = server_ip
            print(f"[Server Analysis] IP: {server_ip} | Load: {current_server_load} | Ratio: {ratio:.4f}[{current_server_load}/{self.max_capacity}]")

        if best_server_ip:
            return best_server_ip
        else:
            print("No servers found or valid.")
            return None

    def ask_FlowStats(self):

        #  For each connection, it sends an OpenFlow statistics request message (flow statistics)
        for connection in core.openflow.connections:
            # This triggers the switch to respond with flow statistics.
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_FlowStatsReceived(self, event):
        # dictionary to store keys (src_ip, dest_ip) and values (total_bytes)

        # iterates over the flow statistics received in the event
        for f in event.stats:
            # checks if it is IP_TYPE, indicating an IPv4 flow
            if f.match.dl_type == ethernet.IP_TYPE:
                
                # Extract Source and Destination IP from the match object
                # In POX, these are usually accessible via nw_src and nw_dst
                src_ip = f.match.nw_src
                dst_ip = f.match.nw_dst
                
                # Create a key pair
                key = (src_ip, dst_ip)
                
                # Aggregate the bytes
                # If key exists, add to it. If not, initialize it to 0 then add.
                if key not in self.flow_stats:
                    self.flow_stats[key] = 0
                
                total_bytes = f.byte_count

                self.flow_stats[key] = total_bytes
                
        # STATS PRINTING
        print(f"Stats received from switch: {event.connection.dpid}, {self.flow_stats}")

        self.extract_min_ratio_server()

        

def launch():
    core.registerNew(LoadBalancer)
