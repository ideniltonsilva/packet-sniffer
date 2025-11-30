#!/usr/bin/env python3
import argparse
import sys
from scapy.all import get_if_list
from .core import run_sniffer, pkt_summary
from .writers import MultiSink


def build_parser():
    p = argparse.ArgumentParser(
        prog="sniffer",
        description="Sniffer de pacotes (v2.1) com filtros BPF, PCAP, CSV e JSON."
    )
    p.add_argument("--iface", help="Interface (ex.: eth0, wlan0, 'Wi-Fi')", default=None)
    p.add_argument("--filter", help="Filtro BPF (ex.: 'tcp port 80', 'udp')", default=None)
    p.add_argument("--count", type=int, help="Número de pacotes (0 = ilimitado)", default=0)
    p.add_argument("--timeout", type=int, help="Tempo em segundos (None = ilimitado)", default=None)
    p.add_argument("--no-promisc", action="store_true", help="Desativa modo promíscuo")
    p.add_argument("--pcap", help="Salvar captura em PCAP (ex.: captura.pcap)", default=None)
    p.add_argument("--csv", help="Salvar resumo em CSV (ex.: log.csv)", default=None)
    p.add_argument("--json", help="Salvar resumo em JSON lines (ex.: log.jsonl)", default=None)
    p.add_argument("--quiet", action="store_true", help="Não imprimir resumo por pacote")
    p.add_argument("--list-ifaces", action="store_true", help="Lista interfaces e sai")
    return p


def main(argv=None):
    argv = argv or sys.argv[1:]
    args = build_parser().parse_args(argv)

    if args.list_ifaces:
        for name in get_if_list():
            print(name)
        return 0

    sink = MultiSink(pcap_path=args.pcap, csv_path=args.csv, json_path=args.json)

    def handle(pkt):
        if not args.quiet:
            print(pkt_summary(pkt))
        sink.write(pkt)

    try:
        run_sniffer(
            iface=args.iface,
            bpf_filter=args.filter,
            count=args.count,
            promisc=(not args.no_promisc),
            timeout=args.timeout,
            on_packet=handle
        )
    except PermissionError:
        print("Permissão negada. No Linux/macOS, rode com sudo. No Windows, instale Npcap.")
        return 1
    finally:
        sink.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
