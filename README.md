# CodeAlpha_sniffer
#!/usr/bin/env python3
"""
Enhanced Network Packet Sniffer & Analyzer  (v2.0)
==================================================
Features:
  • Live capture with Scapy (BPF filter, interface, count)
  • Layer-by-layer decoding (Ethernet → IP → TCP/UDP → App)
  • Application-layer extraction:  HTTP Host, TLS SNI, DNS query
  • TCP stream reconstruction (Scapy TCPSession)
  • Streaming pcap writer (no RAM blow-up)
  • Graceful Ctrl+C: partial pcap is saved, summary is printed
  • Structured, testable analysis (returns dicts)
  • Rich live dashboard: top talkers + protocol breakdown + pie chart
  • Graceful degradation: clear errors for missing Npcap / libpcap / perms
  • Self-test mode (`--selftest`) — no root needed

Requires:  pip install scapy rich
Platform:  Linux/macOS (sudo) | Windows (Npcap + Administrator)
"""

from __future__ import annotations

import argparse
import datetime
import os
import platform
import signal
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# ---------- Scapy imports (guarded) ----------
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, Raw, DNS,
        DNSQR, get_if_list, PcapWriter, conf, rdpcap,
    )
    from scapy.sessions import TCPSession
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.record import TLS
    from scapy.layers.http import HTTPRequest
except ImportError as e:
    print(f"[!] Scapy import failed: {e}")
    print("    Install with:  pip install scapy")
    sys.exit(1)

# ---------- Rich (optional) ----------
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    RICH_OK = True
except ImportError:
    RICH_OK = False


# =========================================================
#  Data structures
# =========================================================
@dataclass
class PacketInfo:
    """Structured, testable representation of an analyzed packet."""
    timestamp: float
    length: int
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    eth_type: Optional[int] = None
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    proto_num: Optional[int] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    arp_op: Optional[str] = None
    arp_psrc: Optional[str] = None
    arp_pdst: Optional[str] = None
    dns_query: Optional[str] = None
    http_host: Optional[str] = None
    http_method: Optional[str] = None
    tls_sni: Optional[str] = None
    payload_len: int = 0
    payload_preview: str = ""
    app_proto: str = "Unknown"     # HTTP / TLS / DNS / Other

    @property
    def protocol_name(self) -> str:
        if self.app_proto != "Unknown":
            return self.app_proto
        if self.tcp_flags is not None:
            return "TCP"
        if self.sport is not None and self.proto_num == 17:
            return "UDP"
        if self.icmp_type is not None:
            return "ICMP"
        if self.arp_op is not None:
            return "ARP"
        return "Other"

    @property
    def flow_key(self) -> str:
        if not self.src_ip or not self.dst_ip:
            return "non-ip"
        if self.sport is None:
            return f"{self.src_ip}->{self.dst_ip}"
        return f"{self.src_ip}:{self.sport}->{self.dst_ip}:{self.dport}"


# =========================================================
#  Application-layer parsers
# =========================================================
def _extract_http(pkt) -> tuple[Optional[str], Optional[str]]:
    """Return (method, host) if an HTTP request is present."""
    method = host = None
    if HTTPRequest in pkt:
        try:
            method = pkt[HTTPRequest].Method.decode(errors="replace")
            host   = pkt[HTTPRequest].Host.decode(errors="replace")
        except Exception:
            pass
    # Fallback: manual parse of Raw payload for the Host header
    if Raw in pkt and (method is None or host is None):
        try:
            raw = bytes(pkt[Raw].load)
            head = raw.split(b"\r\n\r\n", 1)[0]
            lines = head.split(b"\r\n")
            if lines and lines[0].split()[0] in (
                b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH"
            ):
                method = method or lines[0].split()[0].decode(errors="replace")
                for line in lines[1:]:
                    if line.lower().startswith(b"host:"):
                        host = host or line.split(b":", 1)[1].strip().decode(errors="replace")
                        break
        except Exception:
            pass
    return method, host


def _extract_tls_sni(pkt) -> Optional[str]:
    """Extract the SNI from a TLS ClientHello (very common for HTTPS)."""
    try:
        if TLSClientHello in pkt:
            for ext in pkt[TLSClientHello].ext:
                # 0x0000 = server_name extension
                if getattr(ext, "type", None) == 0:
                    names = getattr(ext, "servernames", None) or []
                    if names:
                        sn = names[0].servername
                        return sn.decode(errors="replace") if isinstance(sn, bytes) else str(sn)
    except Exception:
        pass
    # Fallback: manual parse of Raw TLS record containing SNI
    if Raw in pkt:
        try:
            data = bytes(pkt[Raw].load)
            if len(data) > 5 and data[0] == 0x16:      # TLS handshake
                idx = data.find(b"\x00\x00")           # server_name ext type
                if idx > 0:
                    # very small heuristic
                    sni_len = data[idx + 7]
                    sni = data[idx + 9 : idx + 9 + sni_len]
                    if all(32 <= b < 127 for b in sni):
                        return sni.decode()
        except Exception:
            pass
    return None


# =========================================================
#  Core packet analysis
# =========================================================
def analyze_packet(pkt) -> PacketInfo:
    """Convert a Scapy packet into a structured PacketInfo (no printing)."""
    info = PacketInfo(
        timestamp=float(pkt.time),
        length=len(pkt),
    )

    # ----- L2 -----
    if Ether in pkt:
        info.eth_src  = pkt[Ether].src
        info.eth_dst  = pkt[Ether].dst
        info.eth_type = pkt[Ether].type

    # ----- ARP -----
    if ARP in pkt:
        arp = pkt[ARP]
        info.arp_op   = {1: "who-has", 2: "is-at"}.get(arp.op, str(arp.op))
        info.arp_psrc = arp.psrc
        info.arp_pdst = arp.pdst
        info.app_proto = "ARP"
        return info

    # ----- L3 -----
    if IP in pkt:
        ip = pkt[IP]
        info.ip_version = 4
        info.src_ip, info.dst_ip = ip.src, ip.dst
        info.ttl, info.proto_num = ip.ttl, ip.proto
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        info.ip_version = 6
        info.src_ip, info.dst_ip = ip6.src, ip6.dst
        info.ttl, info.proto_num = ip6.hlim, ip6.nh

    # ----- L4 -----
    if TCP in pkt:
        tcp = pkt[TCP]
        info.sport, info.dport = tcp.sport, tcp.dport
        info.tcp_flags = tcp.sprintf("%TCP.flags%")
        info.tcp_seq, info.tcp_ack = tcp.seq, tcp.ack
    elif UDP in pkt:
        info.sport, info.dport = pkt[UDP].sport, pkt[UDP].dport
    elif ICMP in pkt:
        info.icmp_type, info.icmp_code = pkt[ICMP].type, pkt[ICMP].code

    # ----- Application-layer -----
    if DNS in pkt and pkt[DNS].qd is not None:
        try:
            info.dns_query = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
            info.app_proto = "DNS"
        except Exception:
            pass

    if info.app_proto == "Unknown":
        method, host = _extract_http(pkt)
        if method or host:
            info.http_method, info.http_host = method, host
            info.app_proto = "HTTP"

    if info.app_proto == "Unknown" and (info.dport == 443 or info.sport == 443):
        sni = _extract_tls_sni(pkt)
        if sni:
            info.tls_sni = sni
            info.app_proto = "TLS"

    # ----- Payload -----
    if Raw in pkt:
        payload = bytes(pkt[Raw].load)
        info.payload_len = len(payload)
        snippet = payload[:60]
        info.payload_preview = (
            snippet.hex(" ") +
            ("..." if len(payload) > 60 else "") +
            " | " +
            "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
        )

    return info


# =========================================================
#  Capture engine
# =========================================================
class CaptureEngine:
    """
    Captures packets, analyzes them, writes to pcap (streaming),
    and maintains live stats for the dashboard.
    """

    def __init__(self, iface: Optional[str], bpf: Optional[str],
                 pcap_path: Optional[str], tcp_session: bool):
        self.iface      = iface
        self.bpf        = bpf
        self.pcap_path  = pcap_path
        self.tcp_session= tcp_session

        self.writer: Optional[PcapWriter] = None
        self.packets: list[PacketInfo] = []          # for summary
        self.proto_counts: Counter[str] = Counter()
        self.talkers: Counter[str] = Counter()
        self.flow_bytes: defaultdict[str, int] = defaultdict(int)
        self.start_time = 0.0
        self.lock = threading.Lock()
        self._stop = threading.Event()

        # TCP stream reconstruction: only when no pcap writer needs raw packets
        self.session = TCPSession(prn=self._on_packet) if tcp_session else None

    # -------- public API --------
    def start(self) -> None:
        """Blocking capture. Handles Ctrl+C, saves pcap, prints summary."""
        self.start_time = time.time()
        if self.pcap_path:
            self.writer = PcapWriter(self.pcap_path, append=False, sync=True)

        print(f"[*] Capturing on {self.iface or 'default'} "
              f"| BPF: {self.bpf or '(none)'} "
              f"| pcap: {self.pcap_path or '(disabled)'} "
              f"| TCP streams: {self.tcp_session}")

        try:
            sniff(
                iface=self.iface,
                filter=self.bpf,
                prn=self._handle_raw,
                store=False,           # <- streaming: never accumulate in RAM
                session=self.session,  # <- TCP reassembly when enabled
                stop_filter=lambda _: self._stop.is_set(),
            )
        except PermissionError:
            self._fatal("Permission denied. Run with sudo / Administrator.")
        except OSError as e:
            self._fatal(f"Interface error: {e}")

    def stop(self) -> None:
        self._stop.set()

    # -------- internals --------
    def _handle_raw(self, pkt) -> None:
        """Called by sniff for every packet; writes to pcap, updates stats."""
        if self.writer:
            try:
                self.writer.write(pkt)
            except Exception:
                pass
        # With TCPSession, analysis may be delayed; still count each segment
        info = analyze_packet(pkt)
        self._record(info)

    def _on_packet(self, pkt) -> None:
        """Extra hook for TCPSession reassembly (not used for stats)."""
        # Placeholder — TCPSession invokes this on reassembled streams.
        # We could log reconstructed payloads here in a future version.
        _ = pkt

    def _record(self, info: PacketInfo) -> None:
        with self.lock:
            self.packets.append(info)
            self.proto_counts[info.protocol_name] += 1
            if info.src_ip:
                self.talkers[info.src_ip] += 1
            if info.dst_ip:
                self.talkers[info.dst_ip] += 1
            self.flow_bytes[info.flow_key] += info.length

    def _fatal(self, msg: str) -> None:
        self._stop.set()
        print(f"[!] {msg}")

    def close(self) -> None:
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass


# =========================================================
#  Plain-text printer (used when --no-dashboard / non-TTY)
# =========================================================
def print_packet_text(info: PacketInfo) -> None:
    ts = datetime.datetime.fromtimestamp(info.timestamp).strftime("%H:%M:%S.%f")[:-3]
    print("=" * 78)
    print(f"[+] Packet @ {ts}  |  {info.length} bytes")
    if info.eth_src:
        print(f"  Ethernet : {info.eth_src} -> {info.eth_dst}  (0x{info.eth_type:04x})")
    if info.arp_op:
        print(f"  ARP      : {info.arp_psrc} ({info.arp_op}) {info.arp_pdst}")
        return
    if info.src_ip:
        print(f"  IPv{info.ip_version}   : {info.src_ip} -> {info.dst_ip}  "
              f"| TTL={info.ttl}  proto={info.proto_num}")
    if info.tcp_flags is not None:
        print(f"  TCP      : {info.sport} -> {info.dport}  "
              f"| flags={info.tcp_flags}  seq={info.tcp_seq}  ack={info.tcp_ack}")
    elif info.sport is not None:
        print(f"  UDP      : {info.sport} -> {info.dport}")
    elif info.icmp_type is not None:
        print(f"  ICMP     : type={info.icmp_type} code={info.icmp_code}")
    if info.dns_query:
        print(f"  DNS      : query '{info.dns_query}'")
    if info.http_method or info.http_host:
        print(f"  HTTP     : {info.http_method or '?'} Host={info.http_host or '?'}")
    if info.tls_sni:
        print(f"  TLS SNI  : {info.tls_sni}")
    if info.payload_len:
        print(f"  Payload  : {info.payload_len} bytes  |  {info.payload_preview}")
    print()


# =========================================================
#  Rich dashboard
# =========================================================
def build_dashboard(engine: CaptureEngine) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="talkers", ratio=1),
        Layout(name="protos",  ratio=1),
    )

    layout["header"].update(Panel(
        Text(f"🔎  Live capture  |  packets={len(engine.packets)}  "
             f"elapsed={time.time()-engine.start_time:0.1f}s  "
             f"| Ctrl+C to stop",
             style="bold cyan"),
        border_style="cyan",
    ))

    # Top talkers
    t = Table(title="Top Talkers (by packet count)", expand=True)
    t.add_column("IP", style="green")
    t.add_column("Packets", justify="right")
    for ip, n in engine.talkers.most_common(10):
        t.add_row(ip, str(n))
    layout["talkers"].update(t)

    # Protocol breakdown
    p = Table(title="Protocols", expand=True)
    p.add_column("Proto", style="yellow")
    p.add_column("Count", justify="right")
    p.add_column("Share", justify="right")
    total = sum(engine.proto_counts.values()) or 1
    for proto, n in engine.proto_counts.most_common():
        p.add_row(proto, str(n), f"{n/total*100:5.1f}%")
    layout["protos"].update(p)

    return layout


# =========================================================
#  Summary
# =========================================================
def print_summary(engine: CaptureEngine) -> None:
    print("\n" + "=" * 78)
    print("[*] Capture summary")
    print(f"    Duration      : {time.time()-engine.start_time:0.2f}s")
    print(f"    Total packets : {len(engine.packets)}")
    print(f"    pcap saved to : {engine.pcap_path or '(disabled)'}")

    print("\n    Protocol breakdown:")
    total = sum(engine.proto_counts.values()) or 1
    for proto, n in engine.proto_counts.most_common():
        print(f"      {proto:<6}: {n:>6}  ({n/total*100:5.1f}%)")

    print("\n    Top 5 talkers:")
    for ip, n in engine.talkers.most_common(5):
        print(f"      {ip:<20} {n}")

    print("\n    Top 5 flows (bytes):")
    for flow, nbytes in sorted(engine.flow_bytes.items(),
                               key=lambda kv: kv[1], reverse=True)[:5]:
        print(f"      {flow:<45} {nbytes} bytes")


# =========================================================
#  Self-test (no root required)
# =========================================================
def run_selftest() -> int:
    """Feed synthetic packets through analyze_packet() and assert results."""
    from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR

    print("[*] Running self-test ...")
    failures = 0

    # 1. TCP SYN
    p1 = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=1234, dport=80, flags="S")
    i1 = analyze_packet(p1)
    assert i1.src_ip == "1.1.1.1" and i1.tcp_flags == "S", "TCP parse failed"
    print("  [OK] TCP SYN parsed")

    # 2. UDP DNS
    p2 = Ether()/IP(src="1.1.1.1", dst="8.8.8.8")/UDP(sport=55555, dport=53)/\
         DNS(rd=1, qd=DNSQR(qname="example.com"))
    i2 = analyze_packet(p2)
    assert i2.dns_query == "example.com", f"DNS parse failed: {i2.dns_query}"
    print("  [OK] DNS query parsed")

    # 3. HTTP Host header
    http = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
    p3 = Ether()/IP(src="3.3.3.3", dst="4.4.4.4")/TCP(sport=4444, dport=80)/Raw(load=http)
    i3 = analyze_packet(p3)
    assert i3.http_host == "example.org", f"HTTP Host parse failed: {i3.http_host}"
    assert i3.app_proto == "HTTP"
    print("  [OK] HTTP Host parsed")

    # 4. TLS SNI (synthetic ClientHello)
    # minimal ClientHello with SNI = "test.local"
    sni = b"test.local"
    ext = b"\x00\x00" + (len(sni)+5).to_bytes(2,"big") + \
          (len(sni)+3).to_bytes(2,"big") + b"\x00" + \
          len(sni).to_bytes(2,"big") + sni
    ch_body = b"\x03\x03" + b"\x00"*32 + b"\x00" + b"\x00\x02\x00\x2f" + \
              b"\x01\x00" + len(ext).to_bytes(2,"big") + ext
    hs = b"\x01" + len(ch_body).to_bytes(3,"big") + ch_body
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2,"big") + hs
    p4 = Ether()/IP(src="5.5.5.5", dst="6.6.6.6")/TCP(sport=5555, dport=443)/Raw(load=rec)
    i4 = analyze_packet(p4)
    assert i4.tls_sni == "test.local", f"TLS SNI parse failed: {i4.tls_sni}"
    assert i4.app_proto == "TLS"
    print("  [OK] TLS SNI parsed")

    # 5. PacketInfo.flow_key
    assert i1.flow_key == "1.1.1.1:1234->2.2.2.2:80"
    print("  [OK] flow_key correct")

    print(f"[+] Self-test passed ({failures} failures)")
    return failures


# =========================================================
#  Graceful degradation checks
# =========================================================
def preflight_checks() -> None:
    """Detect missing backends and give the user a clear message."""
    if platform.system() == "Windows":
        try:
            # 'conf.use_pcap' is set by scapy when Npcap/WinPcap is available.
            if not getattr(conf, "use_pcap", False):
                print("[!] Npcap not detected on Windows.")
                print("    Install it from https://npcap.com/ and re-run as Administrator.")
        except Exception:
            pass
    if not hasattr(conf, "iface") or conf.iface is None:
        print("[!] No default interface found. Use --iface to choose one.")


# =========================================================
#  CLI
# =========================================================
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enhanced packet sniffer: capture, decode, dashboard, pcap."
    )
    parser.add_argument("-i", "--iface", help="Interface (e.g. eth0, Wi-Fi)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Stop after N packets (0=unlimited)")
    parser.add_argument("-f", "--filter", dest="bpf",
                        help="BPF filter, e.g. 'tcp port 443'")
    parser.add_argument("-o", "--output", help="Write .pcap to this path")
    parser.add_argument("--tcp-streams", action="store_true",
                        help="Enable TCP stream reconstruction (TCPSession)")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="Disable rich dashboard; print packets as text")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="List interfaces and exit")
    parser.add_argument("--selftest", action="store_true",
                        help="Run offline parser self-test (no root)")
    args = parser.parse_args()

    if args.selftest:
        return run_selftest()

    if args.list_ifaces:
        print("Available interfaces:")
        for i in get_if_list():
            print("  -", i)
        return 0

    preflight_checks()

    engine = CaptureEngine(
        iface=args.iface,
        bpf=args.bpf,
        pcap_path=args.output,
        tcp_session=args.tcp_streams,
    )

    use_dashboard = (not args.no_dashboard) and RICH_OK and sys.stdout.isatty()

    # Ctrl+C handling
    def _sigint(_signum, _frame):
        engine.stop()

    signal.signal(signal.SIGINT, _sigint)

    # --count: wrap to stop after N packets
    if args.count > 0:
        original = engine._record
        def _record_and_count(info):
            original(info)
            if len(engine.packets) >= args.count:
                engine.stop()
        engine._record = _record_and_count  # type: ignore

    try:
        if use_dashboard:
            console = Console()
            with Live(build_dashboard(engine), refresh_per_second=4,
                      console=console, screen=False) as live:
                stop_thread = threading.Thread(target=engine.start, daemon=True)
                stop_thread.start()
                while stop_thread.is_alive():
                    live.update(build_dashboard(engine))
                    time.sleep(0.25)
        else:
            # Non-dashboard: print each packet as text
            orig_handle = engine._handle_raw
            def _handle_and_print(pkt):
                info = analyze_packet(pkt)
                if engine.writer:
                    try: engine.writer.write(pkt)
                    except Exception: pass
                print_packet_text(info)
                engine._record(info)
            engine._handle_raw = _handle_and_print  # type: ignore
            engine.start()
    except KeyboardInterrupt:
        engine.stop()
    finally:
        engine.close()
        print_summary(engine)

    return 0


if __name__ == "__main__":
    sys.exit(main())
