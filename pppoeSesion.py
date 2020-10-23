from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.ppp import PPPoE, PPP, PPPoED, PPPoED_Tags, PPPoETag
from scapy.packet import bind_layers, Raw
from scapy.sendrecv import sendp

# protocols
IPv4 = 33
#LCP = 49185

#

class PPPoESession():

    def __init__(self, sessionId=0, serviceVlanId=100, clientVlanId=20):
        self.hostUnique = ""
        self.src_mac = 'fa:16:3e:94:6a:10'
        self.dst_mac = 'ff:ff:ff:ff:ff:ff'
        self.id = sessionId
        self.iface = "eth2"
        self.vlan = clientVlanId
        self.providerVlan = serviceVlanId
        # self.src_ip = "100.64.0.10"
        # self.dst_ip = "100.64.0.1"

    def discoveryPADI(self):
        return sendp(self.ethernetHeader()/self.vlanClientHeader()/self.vlanServiceHeader()/self.pppoePADI(), iface=self.iface, verbose=False)

    def sendPacket(self, payload):
        sendp(self.ethernetHeader()/self.vlanClientHeader()/self.vlanServiceHeader()/self.pppoePADI()/PPP(proto=IPv4)/payload, iface=self.iface, verbose=False)

    # packet's building parts
    def ethernetHeader(self):
        return Ether(src=self.src_mac, dst=self.dst_mac)

    def vlanServiceHeader(self):
        return Dot1Q(vlan=self.vlan)

    def vlanClientHeader(self):
        return Dot1Q(vlan=self.providerVlan)

    def pppoePADI(self):
        return PPPoED()/PPPoETag()