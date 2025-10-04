# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print("Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    if ether_type == "0800":  # IPv4
        parse_ipv4_header(payload)
    elif ether_type == "0806":  # ARP
        parse_arp_header(payload)
    elif ether_type == "86DD":  # IPv6
        parse_ipv6_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = hex_data[4:8]
    hardware_size = int(hex_data[8:10], 16)
    protocol_size = int(hex_data[10:12], 16)
    operation = int(hex_data[12:16], 16)
    sender_mac = ':'.join(hex_data[i:i+2] for i in range(16, 28, 2))
    sender_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(28, 36, 2))
    target_mac = ':'.join(hex_data[i:i+2] for i in range(36, 48, 2))
    target_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(48, 56, 2))

    print("ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {protocol_type:<20} | {int(protocol_type, 16)}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {operation}")
    print(f"  {'Sender MAC:':<25} {hex_data[16:28]:<20} | {sender_mac}")
    print(f"  {'Sender IP:':<25} {hex_data[28:36]:<20} | {sender_ip}")
    print(f"  {'Target MAC:':<25} {hex_data[36:48]:<20} | {target_mac}")
    print(f"  {'Target IP:':<25} {hex_data[48:56]:<20} | {target_ip}")


def parse_ipv4_header(hex_data):
    version_ihl = int(hex_data[:2], 16)
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F)
    header_length = ihl * 4
    total_length = int(hex_data[4:8], 16)
    flags_frag = hex_data[8:12]
    flags_frag_bin = bin(int(flags_frag, 16))[2:].zfill(16)
    flags = (int(hex_data[8:12], 16) >> 13) & 0x7
    reserved = (flags >> 2) & 0x1
    df = (flags >> 1) & 0x1
    mf = flags & 0x1
    fragment_offset = int(hex_data[8:12], 16) & 0x1FFF
    protocol = int(hex_data[18:20], 16)
    src_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(24, 32, 2))
    dst_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(32, 40, 2))

    print("IPv4 Header:")
    print(f"  {'Version:':<25} {version:<20} | {version}")
    print(f"  {'Header Length:':<25} {ihl:<20} | {header_length} bytes")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Flags & Frag Offset:':<25} {flags_frag:<20} | {flags_frag_bin}")
    print(f"    {'Reserved:':<23} {reserved}")
    print(f"    {'DF (Do not Fragment):':<23} {df}")
    print(f"    {'MF (More Fragments):':<23} {mf}")
    print(f"    {'Fragment Offset:':<23} 0x{fragment_offset:03x} | {fragment_offset}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {src_ip}")
    print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {dst_ip}")

    payload = hex_data[header_length*2:]
    if protocol == 1:
        parse_icmp_header(payload)
    elif protocol == 6:
        parse_tcp_header(payload)
    elif protocol == 17:
        parse_udp_header(payload)
    else:
        print("  Unknown IPv4 protocol.")


def parse_icmp_header(hex_data):
    icmp_type = int(hex_data[:2], 16)
    code = int(hex_data[2:4], 16)
    checksum = int(hex_data[4:8], 16)
    print("ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[:2]:<20} | {icmp_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {hex_data[8:]}")


def parse_tcp_header(hex_data):
    src_port = int(hex_data[:4], 16)
    dst_port = int(hex_data[4:8], 16)
    seq_num = int(hex_data[8:16], 16)
    ack_num = int(hex_data[16:24], 16)
    data_offset = (int(hex_data[24:26], 16) >> 4) * 4
    reserved = (int(hex_data[24:26], 16) >> 1) & 0x7
    flags = int(hex_data[26:28], 16)
    window = int(hex_data[28:32], 16)
    checksum = int(hex_data[32:36], 16)
    urg_ptr = int(hex_data[36:40], 16)
    print("TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {src_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {dst_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {seq_num}")
    print(f"  {'Acknowledgment Number:':<25} {hex_data[16:24]:<20} | {ack_num}")
    print(f"  {'Data Offset:':<25} {hex_data[24:26]:<20} | {data_offset} bytes")
    print(f"  {'Reserved:':<25} {reserved}")
    print(f"  {'Flags:':<25} 0b{flags:08b} | {flags}")
    print(f"    {'NS:':<23} {(flags >> 8) & 0x1}")
    print(f"    {'CWR:':<23} {(flags >> 7) & 0x1}")
    print(f"    {'ECE:':<23} {(flags >> 6) & 0x1}")
    print(f"    {'URG:':<23} {(flags >> 5) & 0x1}")
    print(f"    {'ACK:':<23} {(flags >> 4) & 0x1}")
    print(f"    {'PSH:':<23} {(flags >> 3) & 0x1}")
    print(f"    {'RST:':<23} {(flags >> 2) & 0x1}")
    print(f"    {'SYN:':<23} {(flags >> 1) & 0x1}")
    print(f"    {'FIN:':<23} {flags & 0x1}")
    print(f"  {'Window Size:':<25} {hex_data[28:32]:<20} | {window}")
    print(f"  {'Checksum:':<25} {hex_data[32:36]:<20} | {checksum}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[36:40]:<20} | {urg_ptr}")
    print(f"  {'Payload (hex):':<25} {hex_data[data_offset*2:]}")


def parse_udp_header(hex_data):
    src_port = int(hex_data[:4], 16)
    dst_port = int(hex_data[4:8], 16)
    length = int(hex_data[8:12], 16)
    checksum = int(hex_data[12:16], 16)
    print("UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {src_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {dst_port}")
    print(f"  {'Length:':<25} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[12:16]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {hex_data[16:]}")

    # DNS usually runs on port 53
    if src_port == 53 or dst_port == 53:
        parse_dns_header(hex_data[16:])


def parse_dns_header(hex_data):
    transaction_id = hex_data[:4]
    flags = hex_data[4:8]
    questions = int(hex_data[8:12], 16)
    answers = int(hex_data[12:16], 16)
    authority = int(hex_data[16:20], 16)
    additional = int(hex_data[20:24], 16)
    print("DNS Header:")
    print(f"  {'Transaction ID:':<25} {transaction_id}")
    print(f"  {'Flags:':<25} {flags}")
    print(f"  {'Questions:':<25} {questions}")
    print(f"  {'Answer RRs:':<25} {answers}")
    print(f"  {'Authority RRs:':<25} {authority}")
    print(f"  {'Additional RRs:':<25} {additional}")

def parse_ipv6_header(hex_data):
    version = int(hex_data[:2], 16) >> 4
    traffic_class = ((int(hex_data[:2], 16) & 0x0F) << 4) | (int(hex_data[2:4], 16) >> 4)
    flow_label = ((int(hex_data[2:4], 16) & 0x0F) << 16) | int(hex_data[4:8], 16)
    payload_length = int(hex_data[8:12], 16)
    next_header = int(hex_data[12:14], 16)
    hop_limit = int(hex_data[14:16], 16)
    src_ip = ':'.join(hex_data[i:i+4] for i in range(16, 48, 4))
    dst_ip = ':'.join(hex_data[i:i+4] for i in range(48, 80, 4))

    print("IPv6 Header:")
    print(f"  {'Version:':<25} {version}")
    print(f"  {'Traffic Class:':<25} {traffic_class}")
    print(f"  {'Flow Label:':<25} {flow_label}")
    print(f"  {'Payload Length:':<25} {payload_length}")
    print(f"  {'Next Header:':<25} {next_header}")
    print(f"  {'Hop Limit:':<25} {hop_limit}")
    print(f"  {'Source IP:':<25} {src_ip}")
    print(f"  {'Destination IP:':<25} {dst_ip}")

    payload = hex_data[80:]
    if next_header == 58:
        parse_icmpv6_header(payload)
    elif next_header == 6:
        parse_tcp_header(payload)
    elif next_header == 17:
        parse_udp_header(payload)
    else:
        print("  Unknown IPv6 next header.")

def parse_icmpv6_header(hex_data):
    icmpv6_type = int(hex_data[:2], 16)
    code = int(hex_data[2:4], 16)
    checksum = hex_data[4:8]
    print("ICMPv6 Header:")
    print(f"  {'Type:':<25} {hex_data[:2]:<20} | {icmpv6_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code}")
    print(f"  {'Checksum:':<25} {checksum}")
