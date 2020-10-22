from scapy.packet import Raw
from scapy.layers.inet import IP
import pppoeSesion

class PPPoEGenerator():

    def generateSession(self, initial, final):
        sessionList = []
        for session in range(initial, final+1):
            sessionList.append(pppoeSesion.PPPoESession(session,session))
        return sessionList

    def activateSession(self, sessionList):
        for session in sessionList:
            session.sendPacket(IP())