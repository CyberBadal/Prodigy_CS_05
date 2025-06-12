from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = f"Other({proto})"

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        payload = ''
        if Raw in packet:
            payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')[:50]  

        print(f"[+] {protocol} Packet | Source: {src_ip} -> Destination: {dst_ip}")
        if payload:
            print(f"    Payload: {payload}\n")


print("📡 Starting packet capture (press Ctrl+C to stop)...\n")
sniff(prn=packet_callback, filter="ip", store=0)
