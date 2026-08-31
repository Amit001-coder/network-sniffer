#!/usr/bin/env python3
"""
Basic Network Sniffer

Usage examples:
  sudo python3 sniffer.py --iface eth0 --count 50
  sudo python3 sniffer.py --iface eth0 --filter "tcp port 80" --no-payload
"""
import argparse
import sys
import time
import binascii

PAYLOAD_PREVIEW = 128  # bytes to show from payload

def format_payload(payload: bytes, max_len=PAYLOAD_PREVIEW):
    if not payload:
        return ""
    shown = payload[:max_len]
    hexpart = shown.hex()
    asciipart = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in shown)
    suffix = f"...({len(payload)-max_len} more bytes)" if len(payload) > max_len else ""
    return f"HEX:{hexpart} ASCII:{asciipart} {suffix}"

def print_packet_summary(ts, eth_src, eth_dst, proto, src, dst, sport, dport, extra="", payload=b""):
    timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
    line = f"[{timestr}] {eth_src} -> {eth_dst} | {src}{(':'+str(sport)) if sport else ''} -> {dst}{(':'+str(dport)) if dport else ''} | {proto}"
    if extra:
        line += f" | {extra}"
    print(line)
    if payload:
        print("  Payload:", format_payload(payload))
    print()

# --- Try scapy approach first ---
def run_scapy(iface, count, bpf, show_payload):
    try:
        from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw
    except Exception as e:
        raise e

    def handler(pkt):
        ts = getattr(pkt, 'time', time.time())
        eth_src = pkt.src if hasattr(pkt, 'src') else (pkt[0].src if len(pkt.layers())>0 else 'N/A')
        eth_dst = pkt.dst if hasattr(pkt, 'dst') else (pkt[0].dst if len(pkt.layers())>0 else 'N/A')
        proto = pkt.lastlayer().name if pkt.layers() else pkt.name
        src = dst = sport = dport = ""
        extra = ""
        payload = b""

        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            proto = ip.proto
        if TCP in pkt:
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            extra = f"TCP flags={tcp.flags}"
        elif UDP in pkt:
            udp = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            extra = "UDP"
        elif ICMP in pkt:
            ic = pkt[ICMP]
            extra = f"ICMP type={ic.type} code={ic.code}"
        # raw payload
        if Raw in pkt and show_payload:
            payload = bytes(pkt[Raw].load)

        print_packet_summary(ts, eth_src, eth_dst, proto, src, dst, sport, dport, extra, payload)

    print(f"Using scapy sniff on iface={iface} filter={bpf} count={count}")
    sniff(iface=iface, filter=bpf, prn=handler, store=False, count=count)

# --- Raw socket fallback (Linux only) ---
def run_raw_socket(iface, count, bpf_unused, show_payload):
    import socket
    import struct

    # Create raw socket (Linux)
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if iface:
            sock.bind((iface, 0))
    except PermissionError:
        print("Permission denied: raw sockets require root privileges.")
        sys.exit(1)
    except Exception as e:
        print("Raw socket creation failed:", e)
        sys.exit(1)

    def parse_ethernet(header):
        dst, src, proto = struct.unpack('!6s6sH', header)
        dst_mac = ':'.join('%02x' % b for b in dst)
        src_mac = ':'.join('%02x' % b for b in src)
        return src_mac, dst_mac, proto

    def parse_ipv4(data):
        if len(data) < 20:
            return None
        ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, checksum, src, dst = struct.unpack('!BBHHHBBH4s4s', data[:20])
        ihl = ver_ihl & 0x0F
        header_len = ihl * 4
        src_ip = '.'.join(map(str, src))
        dst_ip = '.'.join(map(str, dst))
        return {
            'header_len': header_len,
            'proto': proto,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'total_len': tot_len
        }

    def parse_tcp(data):
        if len(data) < 20:
            return None
        src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = offset_reserved_flags & 0x01FF
        return src_port, dst_port, flags, offset

    def parse_udp(data):
        if len(data) < 8:
            return None
        src_port, dst_port, length = struct.unpack('!HHH', data[:6])
        return src_port, dst_port, length

    print(f"Using raw socket sniff on iface={iface} (Linux) - Ctrl+C to stop")
    seen = 0
    try:
        while True:
            raw_data, addr = sock.recvfrom(65535)
            ts = time.time()
            if len(raw_data) < 14:
                continue
            eth_header = raw_data[:14]
            payload = raw_data[14:]
            src_mac, dst_mac, eth_proto = parse_ethernet(eth_header)
            if eth_proto == 0x0800 and len(payload) >= 20:  # IPv4
                ip_info = parse_ipv4(payload)
                if not ip_info:
                    continue
                ip_header_len = ip_info['header_len']
                proto = ip_info['proto']
                src_ip = ip_info['src_ip']
                dst_ip = ip_info['dst_ip']
                sport = dport = ""
                extra = ""
                user_payload = b""
                # TCP
                if proto == 6 and len(payload) >= ip_header_len + 20:
                    tcp_seg = payload[ip_header_len:]
                    parsed = parse_tcp(tcp_seg)
                    if parsed:
                        sport, dport, flags, offset = parsed
                        extra = f"TCP flags={flags}"
                        if show_payload:
                            user_payload = tcp_seg[offset:]
                # UDP
                elif proto == 17 and len(payload) >= ip_header_len + 8:
                    udp_seg = payload[ip_header_len:]
                    parsed = parse_udp(udp_seg)
                    if parsed:
                        sport, dport, length = parsed
                        extra = "UDP"
                        if show_payload:
                            user_payload = udp_seg[8:]
                # ICMP
                elif proto == 1 and len(payload) >= ip_header_len + 4:
                    icmp_seg = payload[ip_header_len:]
                    ic_type = icmp_seg[0]
                    ic_code = icmp_seg[1]
                    extra = f"ICMP type={ic_type} code={ic_code}"
                    if show_payload:
                        user_payload = icmp_seg[4:]
                else:
                    if show_payload:
                        user_payload = payload[ip_header_len:]
                print_packet_summary(ts, src_mac, dst_mac, proto, src_ip, dst_ip, sport, dport, extra, user_payload)
            else:
                # Non-IPv4 (ARP, IPv6, etc.) - just print Ethernet summary
                print_packet_summary(time.time(), src_mac, dst_mac, hex(eth_proto), "", "", "", "", "")
            seen += 1
            if count and seen >= count:
                break
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer")
    parser.add_argument('--iface', '-i', help="Network interface to listen on (e.g., eth0)", default=None)
    parser.add_argument('--count', '-c', type=int, help="Number of packets to capture (0 = unlimited)", default=0)
    parser.add_argument('--filter', '-f', help="BPF filter (works when scapy/libpcap is available)", default=None)
    parser.add_argument('--no-payload', dest='show_payload', action='store_false', help="Do not display payloads")
    args = parser.parse_args()

    # Try scapy first (preferable)
    try:
        if args.filter and not args.iface:
            print("Note: BPF filters require libpcap/scapy and an interface; specify --iface.")
        run_scapy(args.iface, args.count if args.count>0 else 0, args.filter, args.show_payload)
    except Exception as e:
        # Fallback message and raw socket attempt on Linux
        print("Scapy not available or failed (falling back to raw socket). Reason:", str(e))
        if sys.platform.startswith("linux"):
            run_raw_socket(args.iface, args.count if args.count>0 else 0, args.filter, args.show_payload)
        else:
            print("Raw socket fallback is Linux-only. Please install scapy (pip install scapy) or run on Linux.")
            sys.exit(1)

if __name__ == '__main__':
    main()