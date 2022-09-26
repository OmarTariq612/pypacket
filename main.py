import socket
from time import sleep
import pylayers

ipv4 = pylayers.IPv4Layer(
    socket.IPPROTO_UDP,
    src_ip="192.168.0.55",
    dst_ip="192.168.0.100",
    flags=pylayers.IPV4_DONT_FRAGMENT,
)
udp = pylayers.UDPLayer(src_port=5995, dst_port=9559)
pkt = pylayers.serialize_layers(ipv4, udp, pylayers.Payload(b"Hello World"))

with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
    while True:
        sock.sendto(pkt, ("192.168.0.100", 0))
        sleep(1)
