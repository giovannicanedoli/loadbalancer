import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()


class ARP:
    def __init__(self) -> None:
        core.openflow.addListeners(self)

        self.client_gateway_IP = IPAddr("10.0.0.1")
        self.client_gateway_MAC = EthAddr("00:00:00:00:00:01")

        self.server_gateway_IP = IPAddr("10.0.1.0")
        self.server_gateway_MAC = EthAddr("00:00:00:00:00:02")

    def _handle_PacketIn(self, event):
        """
        event -> OpenFlow PacketIn event
        Handles ARP requests (ignoring discovery probes) and routes them to the
        appropriate handler based on whether the target is a gateway or a known client.
        """
        packet = event.parsed

        # Ignore discovery probes (fake_mac_gw)
        if packet.type == packet.ARP_TYPE and packet.payload.opcode == arp.REQUEST and packet.src != core.Discovery.fake_mac_gw:
            packet_ARP = packet.payload

            if packet.payload.protodst == self.client_gateway_IP:
                self.handle_ARP_Request(event, packet_ARP, gateway_mac=self.client_gateway_MAC)

            elif packet.payload.protodst == self.server_gateway_IP:
                self.handle_ARP_Request(event, packet_ARP, gateway_mac=self.server_gateway_MAC)
            else:
                print("Ip address not recognized!")

    def handle_ARP_Request(self, event, packet_ARP, gateway_mac):
        """
        event       -> OpenFlow PacketIn event
        packet_ARP  -> parsed ARP payload from the request
        gateway_mac -> MAC to use as source if replying for a gateway, None if replying for a client
        Constructs and sends an ARP reply back to the requester.
        """
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY

        # Use the gateway MAC in the ARP reply
        arp_reply.hwsrc = gateway_mac

        arp_reply.hwdst = packet_ARP.hwsrc
        # Swap IPs: reply src = request dst, reply dst = request src
        arp_reply.protosrc = packet_ARP.protodst
        arp_reply.protodst = packet_ARP.protosrc

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = packet_ARP.hwsrc

        if gateway_mac is not None:
            ether.src = gateway_mac
        else:
            ether.src = core.Discovery.clients[packet_ARP.protodst]["mac"]

        ether.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)


def launch():
    core.registerNew(ARP)
