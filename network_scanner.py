#!/usr/bin/env python

import scapy.all as scapy
import optparse #succesor is argparse 


def get_args():
    parser=optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range")

    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an target, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff:ff:ff") # Make sure that it send to more than 1 address
    arp_request_broadcast = broadcast/arp_request #scapy allow this / to append
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #send a packet and recieve a packet
    clients=[]
    for response in answered_list:
        client_dict = {"ip":response[1].psrc, "mac":response[1].hwsrc}
        clients.append(client_dict)
    return clients

def print_result(list):
    print("_"*60)
    print("IP\t\tMAC Addresss\n"+"-"*60)
    for x in list:
        print(x["ip"] + "\t\t" + x["mac"])

options=get_args()
print_result(scan(options.target))
#print_result(scan("192.168.0.1/24"))


#srp allows to send packets with a costum ether
##answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1) #send a packet and recieve a packet

    #scapy.ls(scapy.Ether())
    #print(arp_request_broadcast.summary())
    #print(arp_request_broadcast.show())
    #scapy.ls(scapy.ARP()) LIST ALL POSSIBLE FIELDS
#scapy.arping("192.168.0.1/24")
