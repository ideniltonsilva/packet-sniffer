#!/usr/bin/env python3
import csv
import json
import os
from typing import Optional
from scapy.all import PcapWriter
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP


class PcapSink:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        self._writer = PcapWriter(path, append=True, sync=True)

    def write(self, pkt):
        self._writer.write(pkt)

    def close(self):
        try:
            self._writer.close()
        except Exception:
            pass


class CsvSink:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        file_exists = os.path.exists(path)
        self._fh = open(path, 'a', newline='', encoding='utf-8')
        self._csv = csv.writer(self._fh)
        if not file_exists:
            self._csv.writerow(["time", "proto", "src", "sport", "dst", "dport", "length"])

    def write(self, pkt):
        ts = pkt.time
        proto = "OTHER"
        src = dst = "-"
        sport = dport = ""
        length = len(bytes(pkt))

        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if TCP in pkt:
                proto = "TCP"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            else:
                proto = f"IP({pkt[IP].proto})"
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
            if TCP in pkt:
                proto = "TCP6"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP6"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            else:
                proto = f"IPv6({pkt[IPv6].nh})"
        elif ARP in pkt:
            proto = "ARP"
            src = getattr(pkt[ARP], 'psrc', '-')
            dst = getattr(pkt[ARP], 'pdst', '-')

        self._csv.writerow([ts, proto, src, sport, dst, dport, length])

    def close(self):
        try:
            self._fh.flush()
            self._fh.close()
        except Exception:
            pass


class JsonSink:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        self._fh = open(path, 'a', encoding='utf-8')

    def write(self, pkt):
        ts = pkt.time
        proto = "OTHER"
        src = dst = "-"
        sport = dport = None
        length = len(bytes(pkt))

        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if TCP in pkt:
                proto = "TCP"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            else:
                proto = f"IP({pkt[IP].proto})"
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
            if TCP in pkt:
                proto = "TCP6"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP6"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            else:
                proto = f"IPv6({pkt[IPv6].nh})"
        elif ARP in pkt:
            proto = "ARP"
            src = getattr(pkt[ARP], 'psrc', '-')
            dst = getattr(pkt[ARP], 'pdst', '-')

        record = {
            "time": ts,
            "proto": proto,
            "src": src,
            "sport": sport,
            "dst": dst,
            "dport": dport,
            "length": length,
        }
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def close(self):
        try:
            self._fh.flush()
            self._fh.close()
        except Exception:
            pass


class MultiSink:
    def __init__(self, pcap_path: Optional[str] = None, csv_path: Optional[str] = None, json_path: Optional[str] = None):
        self._pcap = PcapSink(pcap_path) if pcap_path else None
        self._csv = CsvSink(csv_path) if csv_path else None
        self._json = JsonSink(json_path) if json_path else None

    def write(self, pkt):
        if self._pcap:
            self._pcap.write(pkt)
        if self._csv:
            self._csv.write(pkt)
        if self._json:
            self._json.write(pkt)

    def close(self):
        if self._pcap:
            self._pcap.close()
        if self._csv:
            self._csv.close()
        if self._json:
            self._json.close()
