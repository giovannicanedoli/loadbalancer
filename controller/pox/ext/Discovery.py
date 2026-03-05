import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.recoco import Timer

from pox.lib.util import dpidToStr

log = core.getLogger()

MAX_HOST = 7
MIN_SWITCH = 1
DEBUG_CONNECTION_UP = False


class Discovery:

    def __init__(self):

        # adds the hostDiscovery instance as a listener to OpenFlow-related events
        core.openflow.addListeners(self)

        # dictionary to store information about discovered hosts
        self.clients = {}
        self.servers = {}


        # dictionary to store information about switches
        self.switches = {}
        self.switch_dpid = None

        # dictionary to map switch identifiers to switch datapath IDs
        self.sw_id = {}

        # list for all rememeber all connections
        self.connections_list = []

        # id to count connections_list
        self.id = 1

        self.time_period = 6

        # initializes fake IP address for the client-side gateway.
        self.fake_ip_gw = IPAddr("10.0.0.100")

        # initializes fake IP address for the server-side gateway.
        self.fake_ip_gw_server = IPAddr("10.0.1.100")

        # initializes fake MAC address for the gateway.
        self.fake_mac_gw = EthAddr("00:00:00:00:11:11")

        # server subnet prefix for detection
        self.server_subnet = "10.0.1."

        #Timer(self.time_period, self._timer_func, recurring=True)

    def _handle_ConnectionUp(self, event):
        # Event handler method that is called when a new OpenFlow connection is established

        # Associates the current connection ID with the switch ID
        self.sw_id[self.id] = event.dpid
        self.switch_dpid = event.dpid

        # Stores information about switch
        self.switches[event.dpid] = event.ofp.ports

        # adds the new connection to the list of connections
        self.connections_list.append(event.connection)

        #install flow rule
        self.install_flow_rule(event.dpid)

        if DEBUG_CONNECTION_UP:
            print("Connection Up: " + dpidToStr(event.dpid) + ", " + str(self.id))

        # run the search of the host, when all switches have been found
        if self.id >= MIN_SWITCH:
            self.search_host()

        # increment connection ID
        self.id += 1

    def search_host(self):

        print("Discovering clients and servers")

        # calls the hostDiscovery method for each connection
        for connection in self.connections_list:

            # Iterates through a max number of hosts
            for number_of_host in range(1, MAX_HOST + 1):
                
                # ---- CLIENTS SEARCH (10.0.0.x subnet) ----

                # Constructs an ARP request packet with a fake MAC address, and ARP request opcode
                arp_req = arp()
                arp_req.hwsrc = self.fake_mac_gw
                arp_req.opcode = arp.REQUEST
                arp_req.protosrc = self.fake_ip_gw
                arp_req.protodst = IPAddr(f"10.0.0.1{number_of_host}")

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

                # ---- SERVERS SEARCH (10.0.1.x subnet) ----

                arp_req_srv = arp()
                arp_req_srv.hwsrc = self.fake_mac_gw
                arp_req_srv.opcode = arp.REQUEST
                arp_req_srv.protosrc = self.fake_ip_gw_server
                arp_req_srv.protodst = IPAddr(f"10.0.1.1{number_of_host}")

                ether_srv = ethernet()
                ether_srv.type = ethernet.ARP_TYPE
                ether_srv.dst = EthAddr.BROADCAST
                ether_srv.src = self.fake_mac_gw
                ether_srv.payload = arp_req_srv

                msg_srv = of.ofp_packet_out()
                msg_srv.data = ether_srv.pack()

                msg_srv.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
                connection.send(msg_srv)



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
                # Detect servers by subnet (10.0.1.x = server, 10.0.0.x = client)
                is_server = str(ip_host).startswith(self.server_subnet)
                #case we have a server
                if is_server and ip_host not in self.servers: 
                    self.servers[ip_host] = {"switch": event.dpid, "port": event.port, "mac": mac_host}

                    # take the switch ID from linkDiscovery
                    dict_sw_id = self.sw_id
                    sw_id = [key for key, value in dict_sw_id.items() if value == event.dpid]

                    # convert sw_dpid in string type
                    sw_dpid = dpidToStr(self.servers[ip_host]["switch"])
                    port = self.servers[ip_host]["port"]
                    
                    #log.info(f"  ->  server {ip_host} is connected to switch {sw_id, sw_dpid} through switch port {port}")

                elif not is_server and ip_host not in self.clients:
                    self.clients[ip_host] = {"switch": event.dpid, "port": event.port, "mac": mac_host}

                    # take the switch ID from linkDiscovery
                    dict_sw_id = self.sw_id
                    sw_id = [key for key, value in dict_sw_id.items() if value == event.dpid]

                    # convert sw_dpid in string type
                    sw_dpid = dpidToStr(self.clients[ip_host]["switch"])
                    port = self.clients[ip_host]["port"]
                    
                    #log.info(f"  ->  client {ip_host} is connected to switch {sw_id, sw_dpid} through switch port {port}")

    def _timer_func(self):
        self.send_stat_req()

    def send_stat_req(self):
        connection = self.switch_connection
        dpid = self.sw_id[1]
        try:
            msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
            connection.send(msg)
        except Exception as e:
            print(f"Error sending stats request to {dpidToStr(dpid)}: {e}")

    def install_flow_rule(self, dpid):
        # Install proactive rule to catch discovery probes
        msg = of.ofp_flow_mod()
        msg.priority = 50000
        match = of.ofp_match(dl_src=self.fake_mac_gw)
        msg.match = match
        msg.actions = [of.ofp_action_output(port=of.OFPP_CONTROLLER)]
        core.openflow.sendToDPID(dpid, msg)

def launch():
    core.registerNew(Discovery)
