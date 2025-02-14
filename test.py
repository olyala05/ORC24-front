import scapy.all as scapy
import requests
from flask import Flask, render_template, request, jsonify
app = Flask(__name__)
 
def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    ip_list = []
    for element in answered_list:
        mac_address = element[1].hwsrc
        if mac_address.startswith('02') or mac_address.startswith('12'):
            ip_list.append(element[1].psrc)
    return ip_list


print(scan_network("192.168.1.0/24"))