#!/usr/bin/env python

from scapy.all import *
import netaddr
import sys
import time
import operator
from termcolor import colored

probes = []

def packet_handler(pkt):
    #grab new client probe
    if pkt.haslayer(Dot11ProbeReq):
        if len(pkt.info) > 0:
           mac = pkt.addr2
           strength = str(-(256-ord(pkt.notdecoded[-4:-3])))
           seen = False
           for probe in probes:
           #if already seen client, update count, strength, time, and add ssid if not seen before
               if probe.clientMAC == mac:
                   probe.count = probe.count + 1
                   probe.strength = strength
                   probe.lastSeen = lastSeen=time.time()
                   seen=True
                   if pkt[Dot11ProbeReq].info not in probe.ssid:
                       probe.ssid.append(pkt[Dot11ProbeReq].info)
           #else add the new client and ssid
           if not seen:
               probe = probeEntry(clientMAC=pkt.addr2,count=1,lastSeen=time.time(),strength=strength)
               probe.ssid.append(pkt[Dot11ProbeReq].info)
               probes.append(probe)

           #clear screen and print ascii
           print(chr(27) + "[2J")
           printAscii()
           
           #sort probes so newest on top. limit limit lines printed to screen. print data
           lineCount = 0
           probes.sort(key=operator.attrgetter('lastSeen'),reverse=True)
           for probe in probes:
               if not lineCount > 25: 
                   lineCount = lineCount + 2
                   print colored("Client MAC: ","red")+probe.clientMAC+colored(" Count: ","red")+'{:3}'.format(probe.count) + colored(" dBm: ","red") + probe.strength + colored(" OUI: ","red") + probe.oui
                   for ssid in probe.ssid:
                       print colored(ssid,"yellow")
                       lineCount = lineCount + 1
                   print


class probeEntry:
    def __init__(self,clientMAC,count,lastSeen,strength):
        self.clientMAC = clientMAC
        self.ssid = []
        self.count = count
        self.lastSeen = lastSeen
        self.strength = strength

        try:
            parsed_mac = netaddr.EUI(clientMAC)
            self.oui = parsed_mac.oui.registration().org
            if self.oui == "":
                self.out = "Unknown"
        except netaddr.core.NotRegisteredError, e:
            self.oui = "Unknown"


def printAscii():
    print colored("""
$$$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\  
$$  __$$\ $$  __$$\ $$ |  $$ |$$$ __$$\ $$  __$$\ 
$$ |  $$ |$$ /  \__|$$ |  $$ |$$$$\ $$ |\__/  $$ |
$$ |  $$ |$$ |      $$$$$$$$ |$$\$$\$$ | $$$$$$  |
$$ |  $$ |$$ |      \_____$$ |$$ \$$$$ |$$  ____/ 
$$ |  $$ |$$ |  $$\       $$ |$$ |\$$$ |$$ |      
$$$$$$$  |\$$$$$$  |      $$ |\$$$$$$  /$$$$$$$$\ 
\_______/  \______/       \__| \______/ \________|
                                                                                                 
""",'green')
print(chr(27) + "[2J")
printAscii()
print "No probe requests seen yet!"
sniff(iface = sys.argv[1], count=0, store=0, prn=packet_handler)
