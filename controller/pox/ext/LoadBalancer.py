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

        self.max_capacity = 1000 #bytes

        self.time = 7

        # Timer to see flows situation in the network
        Timer(self.time, self.ask_FlowStats, recurring=True)

    def _handle_PacketIn(self, event):
        # event handler that extracts the parsed packet from it (the event)
        packet = event.parsed

        # Checks if the packet is an IPv4 packet
        # Checks source and destination MAC addresses are not equal to the gateway's MAC address of the ARP component (the fake one)
        if (packet.find('ipv4') and packet.src != core.ARP.gateway_MAC and packet.dst != core.ARP.gateway_MAC):
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

        #first handle clients
        if src_host_ip in core.Discovery.clients:
            # -> handle flow to servers
            key = (src_host_ip, dst_host_ip)
            if key in self.dict_flows.keys():
                #flow already exists
                pass
            else:
                #find server greedly
                
                self.dict_flows[key] = ?
                #flow must be created
                # initializes an OpenFlow flow modification message
                msg = of.ofp_flow_mod()

                # sets timeout to remove the flow
                msg.idle_timeout = 25

                # flow removed message will be sent when the rule expires
                msg.flags = of.OFPFF_SEND_FLOW_REM

                # condition for the flow rule
                msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=src_host_ip, nw_dst=dst_host_ip)

                #there is only a switch
                # set output action of the message to the port connected to the destination host
                switch_dpid = core.Discovery.switch_dpid
                switch_to_server_port = core.Discovery.servers[dst_host_ip]["port"]

                msg.actions = [of.ofp_action_output(port=switch_to_server_port)]

                # send the message to the destination switch
                core.openflow.sendToDPID(switch_dpid, msg)
        else:



        return

            

            

            

    # def _handle_FlowRemoved(self, event):
    #     # Checks if the flow removal is due to an idle timeout (it has been idle for too long)
    #     if event.idleTimeout:
    #         flow_match = event.ofp.match

    #         dict_switch_id = core.LinkDiscovery.sw_id
    #         sw_id = [key for key, value in dict_switch_id.items() if value == event.dpid]

    #         # tell that the flow has been removed
    #         log.info(
    #             f"  ->  switch {sw_id, dpidToStr(event.dpid)} removed flow from {flow_match.nw_src} to {flow_match.nw_dst}")

    #         # now it is needed to remove the flow from the network_occupation (total weight)
    #         flow_id = (flow_match.nw_src, flow_match.nw_dst, flow_match.dl_type)

    #         if flow_id in self.dict_flows.keys():

    #             # get graph object with class NetworkGraph
    #             graph = core.NetworkGraph.graph

    #             # If the flow is present in the dictionary, it decreases the flow counter for every link used by the flow
    #             for link in self.dict_flows[flow_id]:
    #                 core.NetworkGraph.remove_weight(graph, link[0], link[1], 1)

    #             # removes the flow from the dict_flows dictionary
    #             self.dict_flows.pop(flow_id)

    def _handle_FlowStatsReceived(self, event):
        # dictionary to store keys (src_ip, dest_ip) and values (total_bytes)

        # iterates over the flow statistics received in the event
        for f in event.stats:
            total_bytes = 0
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
                
                total_bytes += f.byte_count
                self.flow_stats[key] = self.flow_capacity, total_bytes
        # --- Output/Logging ---
        print(f"Stats received from switch: {event.connection.dpid}")
        
        for (src, dst), capacity in self.flow_stats.items():
            print(f"Src: {src} -> Dst: {dst} | Capacity: {capacity}")

    def ask_FlowStats(self):

        #  For each connection, it sends an OpenFlow statistics request message (flow statistics)
        for connection in core.openflow.connections:
            # This triggers the switch to respond with flow statistics.
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))


def launch():
    core.registerNew(LoadBalancer)
