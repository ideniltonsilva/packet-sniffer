# Packet Sniffer v2.1 (Python)

Sniffer de pacotes com **Scapy**, CLI com `argparse`, filtros BPF, saída em **PCAP**, **CSV** e **JSON lines**. Suporte a IPv4, IPv6 e ARP.

## Recursos
- Filtros BPF (tcpdump/Wireshark): `tcp port 80`, `udp`, `host 8.8.8.8`, `ip6` etc.
- Salva PCAP (`--pcap captura.pcap`), log CSV (`--csv log.csv`) e JSONL (`--json log.jsonl`).
- Funciona em Linux/macOS (sudo) e Windows (Npcap).
- Lista interfaces com `--list-ifaces`.

## Instalação
```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\\Scripts\\activate     # Windows
pip install -r requirements.txt
```

### Windows
Instale Npcap e execute o terminal como administrador se necessário.

## Uso
```bash
# Captura geral
sudo python -m src.sniffer.cli

# Filtro HTTP
sudo python -m src.sniffer.cli --filter "tcp port 80"

# Interface específica + PCAP + CSV + JSONL
sudo python -m src.sniffer.cli --iface eth0 --filter "udp port 53" --pcap dns.pcap --csv dns.csv --json dns.jsonl

# Limitar a 100 pacotes
sudo python -m src.sniffer.cli --count 100

# Listar interfaces
python -m src.sniffer.cli --list-ifaces
```

## Testes
```bash
pip install pytest
pytest -q
```

## Aviso legal
Use sniffers apenas em redes sob sua posse ou com autorização explícita. Capturar tráfego de terceiros pode violar leis de privacidade e interceptação.
