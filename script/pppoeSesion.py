from scapy.automaton import Automaton
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.ppp import *
from scapy.sendrecv import sendp, srp, srp1
from packetBuilder import PPPoEPacketBuilder

IPv4 = 33

class PPPoESession(Automaton):

    def __init__(self, serviceVlanId=None, clientVlanId=None, iface=None):
        # ToDo: host unique incremental
        self.hostUnique = b'8100000100001562'
        self.src_mac = '26:4A:34:9B:2A:A4'
        self.dst_mac = 'ff:ff:ff:ff:ff:ff'
        self.id = 0 # sessionId
        self.iface = "Interna"
        self.clientVlan = clientVlanId
        self.providerVlan = serviceVlanId
        self.cookie = None
        self.mtu = PPP_LCP_MRU_Option(max_recv_unit=1492)
        self.magicNumber = PPP_LCP_Magic_Number_Option(magic_number=25735955)

    def discoveryPADI(self):
        # return sendp(self.ethernetHeader()/self.vlanClientHeader()/self.vlanServiceHeader()/self.pppoePADI(), iface=self.iface, verbose=False)
        # sendp(self.ethernetHeader() / self.pppoePADI(), iface=self.iface)
        sendp(PPPoEPacketBuilder.buildPacket(session=self, type='PADI'), iface=self.iface)

    def discoveryPADR(self, dst_mac, cookie):
        sendp(self.ethernetHeader(dst_mac) / self.pppoePADR(cookie), iface=self.iface)

    def configurationPPP(self, dst_mac, sessionId):
        code=1
        magicNumber = self.magicNumber
        sendp(self.ethernetHeader(dst_mac) / self.pppoeLCP(code, sessionId, magicNumber), iface=self.iface)

    def configurationACK(self, dst_mac, sessionId):
        code=2
        magicNumber= PPP_LCP_Magic_Number_Option(magic_number=556202959)
        sendp(self.ethernetHeader(dst_mac) / self.pppoeLCP(code, sessionId, magicNumber), iface=self.iface)

    def sendPacket(self, payload):
        sendp(self.ethernetHeader()/self.vlanClientHeader()/self.vlanServiceHeader()/self.pppoePADI()/PPP(proto=IPv4)/payload, iface=self.iface, verbose=False)

    # packet's building parts
    def ethernetHeader(self, dst_mac='ff:ff:ff:ff:ff:ff'):
        return Ether(src=self.src_mac, dst=dst_mac)

    def vlanServiceHeader(self):
        return Dot1Q(vlan=self.vlan)

    def vlanClientHeader(self):
        return Dot1Q(vlan=self.providerVlan)

    def pppoePADI(self):
        return PPPoED()/PPPoETag(tag_type=257)/PPPoETag(tag_type=259,tag_value="\x00\x01")

    def pppoePADIBis(self):
        return PPPoED()/PPPoETag()

    def pppoePADR(self, cookie):
        return PPPoED(code=25)/PPPoETag(tag_type=257)/PPPoETag(tag_type=260,tag_value=cookie)

    def pppoeLCP(self, code, sessionId, magicNumber):
        return PPPoE(sessionid=sessionId)/PPP()/PPP_LCP_Configure(code=code, id=1, options=[self.mtu, magicNumber])