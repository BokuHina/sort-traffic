import os
from scapy.all import sniff, IP, TCP, UDP, ARP, Raw, DNS, DNSQR, FTP, FTP_PASV, SMTP

# Створюємо папку для логів (якщо її немає)
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

# Функція для запису даних у файл
def write_to_file(filename, data):
    filepath = os.path.join(log_dir, filename)
    with open(filepath, "a") as f:
        f.write(data + "\n")
    print(f"Записано в файл: {filepath}")

# Визначення типу трафіку
def detect_protocol(pkt):
    if pkt.haslayer(DNS):
        return "DNS"
    elif pkt.haslayer(FTP) or pkt.haslayer(FTP_PASV):
        return "FTP"
    elif pkt.haslayer(SMTP):
        return "SMTP"
    elif pkt.haslayer(Raw):
        payload = bytes(pkt[Raw]).lower()
        if b"http" in payload:
            return "HTTP"
    return "Невідомий"

# Визначення типу шифрування
def detect_encryption(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport in [443, 993, 995, 465]:
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            if payload.startswith(b"\x16\x03\x01"):
                return "TLS 1.0"
            elif payload.startswith(b"\x16\x03\x02"):
                return "TLS 1.1"
            elif payload.startswith(b"\x16\x03\x03"):
                return "TLS 1.2"
            elif payload.startswith(b"\x16\x03\x04"):
                return "TLS 1.3"
        return "Зашифрований трафік (SSL/TLS)"
    return "Без шифрування"

# Функція обробки пакетів
def packet_handler(pkt):
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
        encryption = detect_encryption(pkt)
        packet_type = detect_protocol(pkt)
        
        log_entry = f"IP {src_ip} → {dst_ip} | Протокол: {protocol} | Тип: {packet_type} | Шифрування: {encryption}"
        
        if pkt.haslayer(TCP):
            write_to_file("tcp.log", log_entry)
            if "TLS" in encryption or "SSL" in encryption:
                write_to_file("tls.log", log_entry)
        elif pkt.haslayer(UDP):
            write_to_file("udp.log", log_entry)
        
        print(log_entry)

    elif pkt.haslayer(ARP):
        log_entry = f"ARP Запит: {pkt.summary()}"
        write_to_file("arp.log", log_entry)
        print(log_entry)

# Запуск аналізу трафіку
print("Аналіз трафіку... (натисніть Ctrl+C для зупинки)")
sniff(prn=packet_handler, store=False)
