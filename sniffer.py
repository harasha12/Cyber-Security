from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw

packets = []

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print("\n[+] Packet Captured")
        print(f"    Source IP       : {ip_layer.src}")
        print(f"    Destination IP  : {ip_layer.dst}")
        print(f"    Protocol Number : {ip_layer.proto}")

        if TCP in packet:
            print("    Protocol Type   : TCP")
            print(f"    Source Port     : {packet[TCP].sport}")
            print(f"    Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("    Protocol Type   : UDP")
            print(f"    Source Port     : {packet[UDP].sport}")
            print(f"    Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("    Protocol Type   : ICMP")

        if packet.haslayer(Raw):
            print(f"    Payload         : {packet[Raw].load}")

    packets.append(packet)

print("🔍 Sniffing packets... please wait")
sniff(prn=process_packet, count=10)

# This line will create and save the .pcap file
wrpcap("captured.pcap", packets)
print("✅ Packets saved to 'captured.pcap'")
