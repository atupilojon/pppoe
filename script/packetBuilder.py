from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.ppp import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet
    from pppoeSesion import PPPoESession


class PPPoEPacketBuilder:
    @staticmethod
    def buildPacket(session: 'PPPoESession', type):
        if type == "PADI":
            return PPPoEPADI.build(session)
        if type == "PADR":
            return PPPoEPADR.build(session)


class Ethernet:
    @staticmethod
    def buildLayer(session: 'PPPoESession') -> 'Packet':
        packet = Ether(src=session.src_mac, dst=session.dst_mac)
        if session.providerVlan is not None:
            packet.add_payload(Dot1Q(vlan=session.clientVlan))
        if session.clientVlan is not None:
            packet.add_payload(Dot1Q(vlan=session.clientVlan))
        return packet


class PPPoEPADI:
    @staticmethod
    def build(session: 'PPPoESession') -> 'Packet':
        packet = Ethernet.buildLayer(session)
        # discovery with default tag
        packet.add_payload(PPPoED() / PPPoETag(tag_type=257))
        return packet


class PPPoEPADR:
    @staticmethod
    def build(session: 'PPPoESession') -> 'Packet':
        packet = Ethernet.buildLayer(session)
        # discovery with default tag
        packet.add_payload(PPPoED(code=25)/PPPoETag(tag_type=257)/PPPoETag(tag_type=260,tag_value=session.cookie))
        return packet



