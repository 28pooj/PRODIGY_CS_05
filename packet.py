from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    print("\n📦 New Packet Captured:")
    

    if IP in packet:
        ip_layer = packet[IP]
        print(f"🌐 Source IP: {ip_layer.src}")
        print(f"🌐 Destination IP: {ip_layer.dst}")
        print(f"📡 Protocol: {ip_layer.proto}")

        if TCP in packet:
            print("🔗 Protocol Type: TCP")
            print(f"⚡ Source Port: {packet[TCP].sport}")
            print(f"⚡ Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("🔗 Protocol Type: UDP")
            print(f"⚡ Source Port: {packet[UDP].sport}")
            print(f"⚡ Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("🔗 Protocol Type: ICMP")
        

        if Raw in packet:
            payload = packet[Raw].load
            print(f"📄 Payload (first 50 bytes): {payload[:50]}")
        else:
            print("📄 Payload: None")
    else:
        print("⚠️ Non-IP Packet (skipping)")


print("🚀 Starting Network Packet Sniffer...")
print("Press Ctrl+C to stop.\n")

try:
    sniff(prn=packet_callback, count=0, store=False)  
except KeyboardInterrupt:
    print("\n🛑 Stopped Packet Sniffer.")
