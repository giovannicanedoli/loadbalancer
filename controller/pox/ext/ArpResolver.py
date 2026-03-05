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

        # Client-side gateway (10.0.0.0/24 subnet)
        self.client_gateway_IP = IPAddr("10.0.0.1")
        self.client_gateway_MAC = EthAddr("00:00:00:00:00:01")

        # Server-side gateway (10.0.1.0/24 subnet)
        self.server_gateway_IP = IPAddr("10.0.1.0")
        self.server_gateway_MAC = EthAddr("00:00:00:00:00:02")

    def _handle_PacketIn(self, event):
        # This method handles ARP requests. By checking if they are directed to the gateway or hosts in the network, it installs flow rules and handles ARP replies.

        packet = event.parsed

        # checks if the packet type is ARP and if the ARP packet is an ARP request (not done for host discovery)
        if packet.type == packet.ARP_TYPE and packet.payload.opcode == arp.REQUEST and packet.src != core.Discovery.fake_mac_gw:

            # extracts the ARP payload from the packet
            packet_ARP = packet.payload

            # DE-COMMENT TO SEE THE PRINT OF THE ARP REQUEST
            # log.info(f"ARP, Request who-has {packet_ARP.protodst} tell {packet_ARP.protosrc}")


            # Check if the ARP request is for the client-side gateway (10.0.0.1)
            if packet.payload.protodst == self.client_gateway_IP:
                self.handle_ARP_Request(event, packet_ARP, gateway_mac=self.client_gateway_MAC)

            # Check if the ARP request is for the server-side gateway (10.0.1.0)
            elif packet.payload.protodst == self.server_gateway_IP:
                self.handle_ARP_Request(event, packet_ARP, gateway_mac=self.server_gateway_MAC)

            # checks if the destination IP address is a known client in the network
            elif packet.payload.protodst in core.Discovery.clients.keys():
                self.handle_ARP_Request(event, packet_ARP, gateway_mac=None)
            else:
                print("Ip address not recognized!")


    def handle_ARP_Request(self, event, packet_ARP, gateway_mac):
        # This method generates an ARP reply message, encapsulates it in an Ethernet frame, and sends it out as a packet-out message to the switch
        # gateway_mac is set when replying for a gateway IP, None when replying for a client

        # Creates ARP reply message and set the opcode to indicate that it's an ARP reply
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY

        # sets the source MAC address (hwsrc) of the ARP reply
        if gateway_mac is not None:
            # This is for ARP requests for a gateway (client-side or server-side)
            arp_reply.hwsrc = gateway_mac
        else:
            # This is for ARP requests for clients in the network
            arp_reply.hwsrc = core.Discovery.clients[packet_ARP.protodst]["mac"]

        # set the destination MAC address (hwdst) of the ARP reply to the source MAC address (hwsrc) of the received ARP request
        arp_reply.hwdst = packet_ARP.hwsrc

        # swaps the source and destination IP addresses to complete the reply
        arp_reply.protosrc = packet_ARP.protodst
        arp_reply.protodst = packet_ARP.protosrc

        # Create ethernet frame
        ether = ethernet()

        # set its type to ARP
        ether.type = ethernet.ARP_TYPE

        # sets the destination MAC address (dst) of the Ethernet frame to the source MAC address of the received ARP request.
        ether.dst = packet_ARP.hwsrc

        # sets the source MAC address (src) of the Ethernet frame
        if gateway_mac is not None:
            # This is for ARP requests for a gateway (client-side or server-side)
            ether.src = gateway_mac
        else:
            # This is for ARP requests for clients in the network
            ether.src = core.Discovery.clients[packet_ARP.protodst]["mac"]

        # sets the payload of the Ethernet frame to the ARP reply message
        ether.payload = arp_reply

        # DE-COMMENT TO SEE THE PRINT OF THE ARP REPLY
        #log.info(f"ARP, Reply {arp_reply.protosrc} is-at {arp_reply.hwsrc}")

        # create an OpenFlow packet-out message and send it
        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)


def launch():
    core.registerNew(ARP)
