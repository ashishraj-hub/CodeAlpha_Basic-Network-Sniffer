from scapy.all import sniff
from scapy.layers.inet import IP,TCP,UDP

def analyze(packet):
    if packet.haslayer(IP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        print(f"Source IP: {src_ip}---->Destination IP: {dst_ip}")

        if packet.haslayer(TCP):
            print("Protocol: TCP")
            payload=bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            payload=bytes(packet[UDP].payload)
        else:
            print("protocol: Other")
            payload=b''
        print(f"Payload Size: {len(payload)} bytes")
        print("-"*50)

sniff(prn=analyze, count=20)