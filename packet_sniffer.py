import socket
import struct

def mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)

def parse_ethernet_header(packet):
    eth_header = struct.unpack('!6s6sH', packet[:14])
    dest_mac = mac_addr(eth_header[0])
    src_mac = mac_addr(eth_header[1])
    eth_protocol = socket.ntohs(eth_header[2])
    return dest_mac, src_mac, eth_protocol, packet[14:]

def parse_ip_header(packet):
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    return version, ihl, ttl, protocol, src_ip, dst_ip, packet[ihl:]

def parse_tcp_header(packet):
    tcp_header = struct.unpack('!HHLLBBHHH', packet[:20])
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    sequence = tcp_header[2]
    acknowledgment = tcp_header[3]
    doff_reserved = tcp_header[4]
    tcp_header_length = (doff_reserved >> 4) * 4
    return src_port, dst_port, sequence, acknowledgment, tcp_header_length, packet[tcp_header_length:]

def sniff_packets():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        # Parse Ethernet header
        dest_mac, src_mac, eth_protocol, ip_data = parse_ethernet_header(raw_data)
        print(f"\nEthernet Frame:\nDestination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_protocol}")
        
        # Parse IP header if the Ethernet protocol is IP
        if eth_protocol == 8:
            version, ihl, ttl, protocol, src_ip, dst_ip, tcp_data = parse_ip_header(ip_data)
            print(f"IP Packet:\nVersion: {version}, Header Length: {ihl}, TTL: {ttl}")
            print(f"Protocol: {protocol}, Source IP: {src_ip}, Destination IP: {dst_ip}")
            
            # Parse TCP header if the IP protocol is TCP
            if protocol == 6:
                src_port, dst_port, sequence, acknowledgment, tcp_header_length, data = parse_tcp_header(tcp_data)
                print(f"TCP Segment:\nSource Port: {src_port}, Destination Port: {dst_port}")
                print(f"Sequence: {sequence}, Acknowledgment: {acknowledgment}")
                print(f"TCP Header Length: {tcp_header_length}")
                print(f"Data: {data[:64]}")  # Print the first 64 bytes of the data payload for brevity

if __name__ == "__main__":
    sniff_packets()