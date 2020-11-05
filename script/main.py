
# from scapy.arch import get_if_list, get_windows_if_list, get_if_hwaddr
# from scapy.packet import Raw
from scapy.packet import Packet
from scapy.sendrecv import sniff

# from pppoeGenerator import PPPoEGenerator
from packetHandler import PacketHandler
from pppoeSesion import PPPoESession
from sessionHandler import SessionHandler
import time

# winList = get_windows_if_list()
# intfList = get_if_list()
# macList = get_if_hwaddr()

# Pull guids and names from the windows list
# guidToNameDict = { e["guid"]: e["name"] for e in winList}

# Extract the guids from the interface list
# guidsFromIntfList = [(e.split("_"))[1] for e in intfList]

# Press the green button in the gutter to run the script.


if __name__ == '__main__':
    session = PPPoESession()
    # handler = SessionHandler()
    session.discoveryPADI()
    sniff(store=False, filter="pppoed", iface="Interna", prn=lambda pkt:PacketHandler.filterPADO(pkt))
    packet.show()
    # time.sleep(0.2)
    # session.discoveryPADR('5e:00:00:00:00:00', b'ik~\xbcl5\xdf\xa1,\xa7\x83\xe8\x13\x11\x7f\x9f')
    # time.sleep(0.2)
    # session.configurationPPP('5e:00:00:00:00:00',10)
    # time.sleep(0.2)
    # session.configurationACK('5e:00:00:00:00:00', 10)

