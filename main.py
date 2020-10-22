
from scapy.arch import get_if_list, get_windows_if_list, get_if_hwaddr
from scapy.packet import Raw

from pppoeGenerator import PPPoEGenerator
from pppoeSesion import PPPoESession

winList = get_windows_if_list()
intfList = get_if_list()
# macList = get_if_hwaddr()

# Pull guids and names from the windows list
guidToNameDict = { e["guid"]: e["name"] for e in winList}

# Extract the guids from the interface list
guidsFromIntfList = [(e.split("_"))[1] for e in intfList]

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    session = PPPoESession()
    session.discoveryPADI()
