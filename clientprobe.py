#!/usr/bin/env python

from scapy.all import *
import netaddr
import sys
import time
import operator
from termcolor import colored

probes = []

def packet_handler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if len(pkt.info) > 0:
           key = pkt.addr2+"|"+pkt[Dot11ProbeReq].info
           seen = False
           for probe in probes:
           #if seen client asking for this ssid before
               if probe.key == key:
                   probe.count = probe.count + 1
                   seen=True
           #else just update the count
           if not seen:
               probe = probeEntry(clientMAC=pkt.addr2,ssid=pkt[Dot11ProbeReq].info,count=1,firstSeen=time.time())
               probes.append(probe)

           #clear screen and print ascii
           print(chr(27) + "[2J")
           printAscci()
           
           #sort probes so newest on top. limit limit lines printed to screen. print data
           lineCount = 0
           probes.sort(key=operator.attrgetter('firstSeen'),reverse=True)
           for probe in probes:
               if not lineCount > 25: 
                   lineCount = lineCount + 1
                   print colored("Client: ","red")+probe.clientMAC+colored(" SSID: ","red")+'{:25}'.format(probe.ssid)+colored(" Count: ","red")+'{:3}'.format(probe.count) + colored(" OUI: ","red") + probe.oui

class probeEntry:
    def __init__(self,clientMAC,ssid,count,firstSeen):
        self.clientMAC = clientMAC
        self.ssid = ssid
        self.count = count
        self.firstSeen = firstSeen
        self.key = clientMAC+"|"+ssid

        try:
            parsed_mac = netaddr.EUI(clientMAC)
            self.oui = parsed_mac.oui.registration().org
        except netaddr.core.NotRegisteredError, e:
            self.oui = "UNKNOWN"


def printAscci():
    print """

$$$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\  
$$  __$$\ $$  __$$\ $$ |  $$ |$$$ __$$\ $$  __$$\ 
$$ |  $$ |$$ /  \__|$$ |  $$ |$$$$\ $$ |\__/  $$ |
$$ |  $$ |$$ |      $$$$$$$$ |$$\$$\$$ | $$$$$$  |
$$ |  $$ |$$ |      \_____$$ |$$ \$$$$ |$$  ____/ 
$$ |  $$ |$$ |  $$\       $$ |$$ |\$$$ |$$ |      
$$$$$$$  |\$$$$$$  |      $$ |\$$$$$$  /$$$$$$$$\ 
\_______/  \______/       \__| \______/ \________|
                                                                                                 
"""
print(chr(27) + "[2J")
printAscci()
print "No probe requests seen yet!"
sniff(iface = sys.argv[1], count=0, store=0, prn=packet_handler)