import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.recoco import Timer
from pox.lib.util import dpidToStr

log = core.getLogger()


class LoadBalancer:

    def __init__(self):
        core.openflow.addListeners(self)

        # Store flows, flows statistics and previous flows statistics
        self.dict_flows = {}
        self.flow_stats = {}
        self.prev_flow_stats = {}
        # Maps (client_ip, gateway_ip) -> server_ip for load attribution
        self.flow_to_server = {}
        # Tracks servers that currently have drop rules installed
        self.dropped_servers = set()
        # Capacity of a client-to-server flow
        self.max_capacity = 700
        # Time to ask for flow statistics
        self.time = 7
        # Timer to see flows situation in the network
        Timer(self.time, self.ask_FlowStats, recurring=True)

    def _handle_PacketIn(self, event):
        """
        event -> OpenFlow PacketIn event
        Handles incoming IPv4 packets: extracts src/dst IPs, triggers routing, and
        re-injects the packet into the switch pipeline.
        """
        packet = event.parsed
        if packet.find('ipv4'):
            ip_packet = packet.payload
            source_ip = ip_packet.srcip
            destination_ip = ip_packet.dstip

            # call routing method
            self.routing_flows(source_ip, destination_ip)

            msg = of.ofp_packet_out()
            msg.data = packet
            msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
            event.connection.send(msg)

    def routing_flows(self, src_host_ip, dst_host_ip):
        """
        src_host_ip -> source IP of the packet
        dst_host_ip -> destination IP of the packet
        Installs flow rules on the switch: client->server traffic is redirected to
        the least loaded server; server->client traffic is NATed back through the gateway.
        """
        
        switch_dpid = core.Discovery.switch_dpid
        # Traffic from Client -> Server
        if src_host_ip in core.Discovery.clients.keys():

            # Pick best server
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

            # Save flow info and map this flow to the chosen server
            self.dict_flows[(src_host_ip, dst_host_ip)] = msg
            self.flow_to_server[(src_host_ip, dst_host_ip)] = chosen_server_ip
            
            core.openflow.sendToDPID(core.Discovery.switch_dpid, msg)

            # send the message to the destination switch
            core.openflow.sendToDPID(switch_dpid, msg)

        # CTraffic from Server -> Client
        elif src_host_ip in core.Discovery.servers:
            # Simple forwarding back to client port
            client_port = core.Discovery.clients[dst_host_ip]["port"]
            client_mac = core.Discovery.clients[dst_host_ip]["mac"]
            msg = of.ofp_flow_mod()
            msg.idle_timeout = 25
            msg.flags = of.OFPFF_SEND_FLOW_REM
            
            msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=src_host_ip, nw_dst=dst_host_ip)
            
            # The traffic from the servers must go to the client gateway, clients must see 
            # the packet arrive from the client gateway IP, not from the server's IP
            # The same applies for the mac address of course
            msg.actions.append(of.ofp_action_nw_addr.set_src(core.ARP.client_gateway_IP))
            msg.actions.append(of.ofp_action_dl_addr.set_src(core.ARP.client_gateway_MAC))
            # Set destination mac to the client's actual mac
            msg.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
            # Send to the client's port
            msg.actions.append(of.ofp_action_output(port=client_port))
            
            core.openflow.sendToDPID(switch_dpid, msg)

        return 

    def ask_FlowStats(self):
        """
        Sends an OpenFlow flow stats request to every connected switch.
        Called periodically by the timer.
        """
        #  For each connection, it sends an OpenFlow statistics request message
        for connection in core.openflow.connections:
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_FlowStatsReceived(self, event):
        """
        event -> OpenFlow FlowStatsReceived event
        Processes flow statistics to compute per-flow byte rates, then triggers
        server load evaluation.
        """
        # Iterates over the flow statistics received in the event
        for f in event.stats:
            # Checks if it is IP_TYPE, indicating an IPv4 flow
            if f.match.dl_type == ethernet.IP_TYPE:
                
                # Extract Source and Destination IP from the match object
                src_ip = f.match.nw_src
                dst_ip = f.match.nw_dst
                
                # Create a key pair that will be used to identify the flow
                key = (src_ip, dst_ip)

                if key not in self.flow_stats:
                    self.flow_stats[key] = 0
                
                total_bytes = f.byte_count
                prev_total_bytes = self.prev_flow_stats.get(key, 0)

                if total_bytes < prev_total_bytes:
                    byte_diff = total_bytes
                else:
                    byte_diff = total_bytes - prev_total_bytes

                rate = byte_diff / self.time

                # Update flow stats with new rate
                self.flow_stats[key] = rate

                self.prev_flow_stats[key] = total_bytes

        # Evaluate server loads and enforce drop rules if overloaded
        self.extract_min_ratio_server()
        self.check_overloaded_servers()

    def _handle_FlowRemoved(self, event):
        """
        event -> OpenFlow FlowRemoved event
        Cleans up internal flow tracking data when a flow is removed due to idle timeout.
        """
        # Checks if the flow removal is due to an idle timeout (it has been idle for too long)
        if event.idleTimeout:
            flow_match = event.ofp.match
            switch_dpid = core.Discovery.switch_dpid
            log.warn(f"  ->  switch {switch_dpid} removed flow from {flow_match.nw_src} to {flow_match.nw_dst}")
            flow_key = (flow_match.nw_src, flow_match.nw_dst)
            # Cleanup data
            if flow_key in self.dict_flows.keys():
                self.dict_flows[flow_key] = 0
            if flow_key in self.flow_stats.keys():
                self.flow_stats[flow_key] = 0
            if flow_key in self.prev_flow_stats.keys():
                self.prev_flow_stats[flow_key] = 0
            if flow_key in self.flow_to_server:
                del self.flow_to_server[flow_key]


    def extract_min_ratio_server(self):
        """
        Returns the IP of the server with the lowest load ratio (load / max_capacity).
        Skips overloaded servers (ratio >= 1). Returns None if no server is available.
        """
        min_ratio = float('inf')
        best_server_ip = None

        #iterate through the servers
        for server_ip in core.Discovery.servers.keys():

            current_server_load = 0
            # Sum rates of all client->gateway flows routed to this server
            for flow_key, rate in self.flow_stats.items():
                if self.flow_to_server.get(flow_key) == server_ip:
                    current_server_load += rate
            ratio = current_server_load / self.max_capacity
            print(f"[Server Analysis] IP: {server_ip} | Current Rate: {current_server_load:.2f} B/s | Ratio: {ratio:.4f}")
            if ratio >= 1:
                print(f"[Server Analysis] [WARNING!] Server {server_ip} is overloaded, I'm skipping it...")
                continue
            if ratio < min_ratio:
                min_ratio = ratio
                best_server_ip = server_ip
        if best_server_ip:
            return best_server_ip
        else:
            print("No servers found or valid.")
            return None

    def get_server_load(self, server_ip):
        """
        server_ip -> IP address of the server
        Returns the total byte rate (B/s) of all flows routed to this server.
        """
        load = 0
        for flow_key, rate in self.flow_stats.items():
            if self.flow_to_server.get(flow_key) == server_ip:
                load += rate
        return load

    def check_overloaded_servers(self):
        """
        Checks each server's load against max_capacity.
        If overloaded: installs a high-priority drop rule for each flow routed to it.
        If recovered: removes the drop rule so traffic can resume.
        """
        switch_dpid = core.Discovery.switch_dpid

        for server_ip in core.Discovery.servers.keys():
            load = self.get_server_load(server_ip)
            is_overloaded = load >= self.max_capacity

            if is_overloaded and server_ip not in self.dropped_servers:
                # Server just became overloaded -> install drop rules
                print(f"[Overload] Server {server_ip} overloaded ({load:.0f} B/s). Installing drop rules.")
                self.dropped_servers.add(server_ip)

                for flow_key, target_server in self.flow_to_server.items():
                    if target_server == server_ip:
                        src_ip, dst_ip = flow_key
                        # Drop rule: same match as the forwarding rule but higher priority and no actions
                        msg = of.ofp_flow_mod()
                        msg.priority = 60000
                        msg.hard_timeout = self.time * 2
                        msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=src_ip, nw_dst=dst_ip)
                        # No actions = drop
                        core.openflow.sendToDPID(switch_dpid, msg)

            elif not is_overloaded and server_ip in self.dropped_servers:
                # Server recovered -> remove drop rules
                print(f"[Overload] Server {server_ip} recovered ({load:.0f} B/s). Removing drop rules.")
                self.dropped_servers.discard(server_ip)

                for flow_key, target_server in self.flow_to_server.items():
                    if target_server == server_ip:
                        src_ip, dst_ip = flow_key
                        # Delete the drop rule
                        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                        msg.priority = 60000
                        msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=src_ip, nw_dst=dst_ip)
                        core.openflow.sendToDPID(switch_dpid, msg)
        

def launch():
    core.registerNew(LoadBalancer)
