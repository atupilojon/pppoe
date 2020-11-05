from scapy.layers.ppp import PPPoED
from scapy.packet import Packet

class PacketHandler:
    @staticmethod
    def filterPPPoED(packet: 'Packet') -> 'Packet':
        if packet.haslayer(PPPoED):
            PacketHandlerPPPoED.handle(packet)