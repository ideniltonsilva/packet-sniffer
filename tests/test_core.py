from src.sniffer.core import pkt_summary
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP


def test_pkt_summary_tcp_ipv4():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80)
    s = pkt_summary(pkt)
    assert "TCP 10.0.0.1:1234 -> 10.0.0.2:80" in s


def test_pkt_summary_udp_ipv6():
    pkt = IPv6(src="2001:db8::1", dst="2001:db8::2")/UDP(sport=53, dport=5300)
    s = pkt_summary(pkt)
    assert "UDP6 2001:db8::1:53 -> 2001:db8::2:5300" in s


def test_pkt_summary_arp():
    pkt = ARP(psrc="192.168.1.10", pdst="192.168.1.1")
    s = pkt_summary(pkt)
    assert "ARP 192.168.1.10:" in s
