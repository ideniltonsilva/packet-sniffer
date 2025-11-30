#!/usr/bin/env python3
from typing import Optional, Callable
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP


def pkt_summary(pkt) -> str:
    proto = "OTHER"
    src = dst = "-"
    sport = dport = ""

    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            proto = f"IP(proto={pkt[IP].proto})"
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        if TCP in pkt:
            proto = "TCP6"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP6"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            proto = f"IPv6(nh={pkt[IPv6].nh})"
    elif ARP in pkt:
        proto = "ARP"
        src = getattr(pkt[ARP], 'psrc', '-')
        dst = getattr(pkt[ARP], 'pdst', '-')
    else:
        proto = pkt.lastlayer().name

    return f"{proto} {src}:{sport} -> {dst}:{dport}"


def run_sniffer(
    iface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    count: int = 0,
    promisc: bool = True,
    timeout: Optional[int] = None,
    on_packet: Optional[Callable] = None,
):
    """Executa sniff com Scapy.
    - iface: nome da interface (ex.: 'eth0', 'Wi-Fi'), ou None para padrão.
    - bpf_filter: filtro BPF (ex.: 'tcp port 80', 'udp or icmp').
    - count: número de pacotes (0 = infinito).
    - promisc: modo promíscuo.
    - timeout: segundos (None = sem limite).
    - on_packet: função que recebe cada pacote (callable).
    """
    sniff(
        iface=iface,
        filter=bpf_filter,
        prn=on_packet,
        count=count,
        promisc=promisc,
        timeout=timeout,
        store=False,
    )
