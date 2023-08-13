from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP
from scapy.sendrecv import srp

broadcast = "FF:FF:FF:FF:FF:FF"
ip_range = "192.168.13.1/24"

my_arp_layer = ARP(pdst = ip_range)
ether_layer = Ether(dst=broadcast)
packet = ether_layer / my_arp_layer

ans, unans = srp(packet, iface="eth0", timeout=2)
for snd, rcv in ans:
    ip = rcv[ARP].psrc
    mac = rcv[Ether].src
    print(f"IP : {ip}\t\tMAC : {mac}")