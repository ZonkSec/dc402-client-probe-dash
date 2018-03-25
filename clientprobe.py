#!/usr/bin/env python

from scapy.all import *
import sys
import time
import operator
from termcolor import colored
from manuf import manuf

clients = []

def packet_handler(pkt):
    #grab new client probe
    if pkt.haslayer(Dot11ProbeReq):
        if len(pkt.info) > 0:
           mac = pkt.addr2
           strength = str(-(256-ord(pkt.notdecoded[-4:-3])))
           seen = False
           for client in clients:
           #if already seen client, update count, strength, time, and add ssid if not seen before
               if client.clientMAC == mac:
                   client.count = client.count + 1
                   client.strength = strength
                   client.lastSeen = lastSeen=time.time()
                   seen=True
                   if pkt[Dot11ProbeReq].info not in client.ssid:
                       client.ssid.append(pkt[Dot11ProbeReq].info)
           #else add the new client and ssid
           if not seen:
               client = clientEntry(clientMAC=pkt.addr2,count=1,lastSeen=time.time(),strength=strength)
               client.ssid.append(pkt[Dot11ProbeReq].info)
               clients.append(client)

           #clear screen and print ascii
           print(chr(27) + "[2J")
           printAscii()
           
           #sort clients so newest on top. limit limit lines printed to screen. print data
           lineCount = 0
           clients.sort(key=operator.attrgetter('lastSeen'),reverse=True)
           for client in clients:
               if not lineCount > 25: 
                   lineCount = lineCount + 2
                   print colored("Client MAC: ","red")+client.clientMAC+colored(" Count: ","red")+'{:3}'.format(client.count) + colored(" dBm: ","red") + client.strength + colored(" OUI: ","red") + client.oui
                   for ssid in client.ssid:
                       print colored(ssid,"yellow")
                       lineCount = lineCount + 1
                   print


class clientEntry:
    def __init__(self,clientMAC,count,lastSeen,strength):
        self.clientMAC = clientMAC
        self.ssid = []
        self.count = count
        self.lastSeen = lastSeen
        self.strength = strength
        self.oui = str(p.get_manuf_long(str(clientMAC)))


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
print "Loading OUI..."
p = manuf.MacParser(update=False) #set to true to download new OUI
print "No probe requests seen yet!"
sniff(iface = sys.argv[1], count=0, store=0, prn=packet_handler)