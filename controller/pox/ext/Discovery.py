import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.recoco import Timer

from pox.lib.util import dpidToStr

log = core.getLogger()

NUM_CLIENTS = 4
NUM_SERVERS = 3
DEBUG_CONNECTION_UP = False


class Discovery:

    def __init__(self):

        core.openflow.addListeners(self)

        self.clients = {}
        self.servers = {}
        self.switches = {}
        self.switch_dpid = None
        self.sw_id = {}
        self.connection = None
        self.id = 1
        self.time_period = 6

        # Fake addresses used for discovery probes (not real hosts)
        self.fake_ip_gw = IPAddr("10.0.0.100")
        self.fake_ip_gw_server = IPAddr("10.0.1.100")
        self.fake_mac_gw = EthAddr("00:00:00:00:11:11")
        self.server_subnet = "10.0.1."

    def _handle_ConnectionUp(self, event):
        """
        event -> OpenFlow ConnectionUp event
        Stores switch info, installs discovery flow rule, and triggers host search.
        """
        self.sw_id[self.id] = event.dpid
        self.switch_dpid = event.dpid
        self.switches[event.dpid] = event.ofp.ports
        self.connection = event.connection

        self.install_flow_rule(event.dpid)

        if DEBUG_CONNECTION_UP:
            log.info("Connection Up: " + dpidToStr(event.dpid) + ", " + str(self.id))

        self.search_host()
        self.id += 1

    def search_host(self):
        """
        Broadcasts ARP requests to discover clients (10.0.0.1x) and servers (10.0.1.1x).
        Replies are handled in _handle_PacketIn to populate self.clients and self.servers.
        """
        print("Discovering clients and servers")
        connection = self.connection

        for client in range(1, NUM_CLIENTS + 1):
            arp_req = arp()
            arp_req.hwsrc = self.fake_mac_gw
            arp_req.opcode = arp.REQUEST
            arp_req.protosrc = self.fake_ip_gw
            arp_req.protodst = IPAddr(f"10.0.0.1{client}")

            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = EthAddr.BROADCAST
            ether.src = self.fake_mac_gw
            ether.payload = arp_req

            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
            connection.send(msg)

        for server in range(1, NUM_SERVERS + 1):
            arp_req = arp()
            arp_req.hwsrc = self.fake_mac_gw
            arp_req.opcode = arp.REQUEST
            arp_req.protosrc = self.fake_ip_gw_server
            arp_req.protodst = IPAddr(f"10.0.1.1{server}")

            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = EthAddr.BROADCAST
            ether.src = self.fake_mac_gw
            ether.payload = arp_req

            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL)) 
            connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        event -> OpenFlow PacketIn event
        Processes ARP replies directed to the fake MAC and registers
        the host as a client or server based on its subnet.
        """
        eth_frame = event.parsed

        if eth_frame.type == ethernet.ARP_TYPE and eth_frame.dst == self.fake_mac_gw:
            arp_message = eth_frame.payload

            if arp_message.opcode == arp.REPLY:
                ip_host = arp_message.protosrc
                mac_host = arp_message.hwsrc
                # Classify by subnet: 10.0.1.x = server, 10.0.0.x = client
                is_server = str(ip_host).startswith(self.server_subnet)

                if is_server and ip_host not in self.servers:
                    self.servers[ip_host] = {"switch": event.dpid, "port": event.port, "mac": mac_host}

                    sw_id = [key for key, value in self.sw_id.items() if value == event.dpid]
                    sw_dpid = dpidToStr(self.servers[ip_host]["switch"])
                    port = self.servers[ip_host]["port"]

                    if DEBUG_CONNECTION_UP:
                        log.info(f"  ->  server {ip_host} is connected to switch {sw_id, sw_dpid} through switch port {port}")

                elif not is_server and ip_host not in self.clients:
                    self.clients[ip_host] = {"switch": event.dpid, "port": event.port, "mac": mac_host}

                    sw_id = [key for key, value in self.sw_id.items() if value == event.dpid]
                    sw_dpid = dpidToStr(self.clients[ip_host]["switch"])
                    port = self.clients[ip_host]["port"]

                    if DEBUG_CONNECTION_UP:
                        log.info(f"  ->  client {ip_host} is connected to switch {sw_id, sw_dpid} through switch port {port}")

    def _timer_func(self):
        self.send_stat_req()

    def send_stat_req(self):
        """
        Sends an OpenFlow flow stats request to the switch.
        """
        connection = self.connection
        dpid = self.sw_id[1]
        try:
            msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
            connection.send(msg)
        except Exception as e:
            print(f"Error sending stats request to {dpidToStr(dpid)}: {e}")

    def install_flow_rule(self, dpid):
        """
        dpid -> switch datapath ID
        Installs a high-priority flow rule that sends packets with the fake MAC src to the controller.
        """
        msg = of.ofp_flow_mod()
        msg.priority = 50000
        match = of.ofp_match(dl_src=self.fake_mac_gw)
        msg.match = match
        msg.actions = [of.ofp_action_output(port=of.OFPP_CONTROLLER)]
        core.openflow.sendToDPID(dpid, msg)

def launch():
    core.registerNew(Discovery)
