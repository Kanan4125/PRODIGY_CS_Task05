from scapy.all import sniff, IP, TCP, UDP

# Packet analysis function
def analyze_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Check for protocols and display relevant details
        if TCP in packet:
            print("Protocol: TCP")
        elif UDP in packet:
            print("Protocol: UDP")
        else:
            print("Protocol: Other")
        
        if packet.haslayer('Raw'):
            print(f"Payload Data: {packet['Raw'].load}")
        print("-" * 50)

# Start packet sniffing (on interface "eth0" or any other as per your network)
def start_sniffer(interface="eth0"):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    start_sniffer()
