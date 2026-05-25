import time
from multiprocessing import Process, Queue, Event
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, hexdump
from scapy.utils import PcapWriter

def get_packet_protocol(pkt):
    """Identify high-fidelity protocols in scapy packet."""
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if sport == 80 or dport == 80:
            return "HTTP"
        if sport == 443 or dport == 443:
            return "HTTPS"
        if sport == 21 or dport == 21:
            return "FTP"
        if sport == 23 or dport == 23:
            return "TELNET"
        if sport == 22 or dport == 22:
            return "SSH"
        return "TCP"
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if sport == 53 or dport == 53:
            return "DNS"
        if sport in [67, 68] or dport in [67, 68]:
            return "DHCP"
        if sport == 123 or dport == 123:
            return "NTP"
        return "UDP"
    elif ICMP in pkt:
        return "ICMP"
    elif ARP in pkt:
        return "ARP"
    elif IP in pkt:
        return "IP"
    else:
        # Fallback Scapy layer check
        for proto in ["IPv6", "DNS", "DHCP", "ARP", "ICMPv6"]:
            if pkt.haslayer(proto):
                return proto
        return "Other"

def run_sniffer_process(iface, cap_filter, data_queue, stop_event, pcap_filename, offline_file=None):
    """
    Runs in a separate OS process to sniff and parse network packets without
    blocking the GUI thread. Passes structured packet metadata and text dumps
    via data_queue.
    """
    pcap_writer = None
    if pcap_filename:
        try:
            pcap_writer = PcapWriter(pcap_filename, append=True, sync=True)
        except Exception as e:
            data_queue.put(("ERROR", f"Could not open PCAP file: {e}"))

    def packet_callback(pkt):
        if stop_event.is_set():
            return

        try:
            # 1. Save to PCAP (if enabled)
            if pcap_writer:
                pcap_writer.write(pkt)

            # 2. Extract detailed stats
            ts = time.time()
            pkt_len = len(pkt)
            proto = get_packet_protocol(pkt)

            src_ip = "Unknown"
            dst_ip = "Unknown"
            sport = None
            dport = None

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif ARP in pkt:
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
            elif pkt.haslayer("IPv6"):
                src_ip = pkt["IPv6"].src
                dst_ip = pkt["IPv6"].dst
            else:
                # Fallback to Ethernet MAC address
                src_ip = pkt.src if hasattr(pkt, "src") else "Unknown"
                dst_ip = pkt.dst if hasattr(pkt, "dst") else "Unknown"

            # Port Extraction
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            # Scapy summary description
            summary = pkt.summary()[:120]

            # Generate packet field detail text
            try:
                details_str = pkt.show(dump=True)
            except Exception:
                details_str = "Could not parse packet details."

            # Generate beautiful packet hexdump
            try:
                hexdump_str = hexdump(pkt, dump=True)
            except Exception:
                hexdump_str = "Could not generate packet hexdump."

            # Pack all details to transmit to main GUI process
            packet_data = (
                ts, 
                pkt_len, 
                proto, 
                src_ip, 
                sport, 
                dst_ip, 
                dport, 
                summary, 
                details_str, 
                hexdump_str
            )
            data_queue.put(packet_data)

        except Exception as ex:
            # Catch but report to GUI so we don't drop errors silently
            data_queue.put(("ERROR", f"Packet parsing error: {ex}"))

    try:
        kwargs = {
            "prn": packet_callback,
            "store": False,
            "stop_filter": lambda x: stop_event.is_set()
        }
        if offline_file:
            kwargs["offline"] = offline_file
        else:
            kwargs["iface"] = iface
            kwargs["filter"] = cap_filter
            
        sniff(**kwargs)
    except Exception as e:
        data_queue.put(("ERROR", str(e)))
    finally:
        if pcap_writer:
            try:
                pcap_writer.close()
            except Exception:
                pass
