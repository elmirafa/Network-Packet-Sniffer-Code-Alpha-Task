from scapy.all import sniff, IP, TCP, UDP

# Define a callback function for processing packets
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        protocol = packet[IP].proto  # Protocol (TCP/UDP/ICMP)
        
        print("\n[+] Captured Packet:")
        print("Source IP: {}".format(ip_src))
        print("Destination IP: {}".format(ip_dst))
        print("Protocol: {}".format(protocol))
        
        # Check for TCP or UDP layers and extract ports
        if TCP in packet:
            src_port = packet[TCP].sport  # Source Port
            dst_port = packet[TCP].dport  # Destination Port
            print("TCP Source Port: {}".format(src_port))
            print("TCP Destination Port: {}".format(dst_port))
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print("UDP Source Port: {}".format(src_port))
            print("UDP Destination Port: {}".format(dst_port))

# Start sniffing (requires administrative privileges)
print("Starting the sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
