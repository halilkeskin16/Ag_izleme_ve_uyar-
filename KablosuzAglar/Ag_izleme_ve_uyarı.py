from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, Ether, Raw
from datetime import datetime
import requests

# Zararlı IP adresleri dosyasını yükle
with open('yasakli_ipler.txt', 'r') as file:
    ZARARLI_IPLER = [line.strip() for line in file.readlines()]

log_dosyasi = "paket_loglari.txt"

def get_mac_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200 and response.text.strip():
            return response.text.strip()
        else:
            return "Not Found"
    except:
        return "Üretici Bilgisi Alınamadı"

def guess_device_type(mac_vendor, ports):
    vendor_lower = mac_vendor.lower()
    if "cisco" in vendor_lower:
        return "Muhtemelen bir ağ cihazı (router/switch)"
    elif "apple" in vendor_lower:
        return "Muhtemelen bir Apple cihazı (iPhone/Mac)"
    elif "samsung" in vendor_lower:
        return "Muhtemelen bir Samsung cihazı (telefon/tablet)"
    elif "microsoft" in vendor_lower:
        return "Muhtemelen bir Windows cihazı"
    elif 80 in ports or 443 in ports:
        return "Web servisi çalıştıran bir cihaz"
    elif 22 in ports:
        return "SSH açık, muhtemelen bir Linux/Unix sistemi"
    elif 3389 in ports:
        return "RDP açık, muhtemelen bir Windows sistemi"
    else:
        return "Belirlenemeyen cihaz türü"

def paket_analiz(paket):
    global ZARARLI_IPLER
    
    zaman = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log = f"Paket Yakalandı: {zaman}\n"

    zararli_ip_tespit = False
    zararli_ip = ""
    ports = set()
    vendor = "Bilinmeyen Üretici"

    if paket.haslayer(Ether):
        mac = paket[Ether].src
        vendor = get_mac_vendor(mac)
        log += f"Kaynak MAC: {mac} (Üretici: {vendor})\n"
    
    if paket.haslayer(IP):
        kaynak_ip = paket[IP].src
        hedef_ip = paket[IP].dst
        log += f"Kaynak IP: {kaynak_ip}\n"
        log += f"Hedef IP: {hedef_ip}\n"

        if kaynak_ip in ZARARLI_IPLER:
            zararli_ip_tespit = True
            zararli_ip = kaynak_ip
        elif hedef_ip in ZARARLI_IPLER:
            zararli_ip_tespit = True
            zararli_ip = hedef_ip
        
        log += f"TTL: {paket[IP].ttl}\n"

    if paket.haslayer(TCP):
        ports.add(paket[TCP].sport)
        ports.add(paket[TCP].dport)
        log += f"Kaynak Port: {paket[TCP].sport}\n"
        log += f"Hedef Port: {paket[TCP].dport}\n"
        log += f"Sıra Numarası: {paket[TCP].seq}\n"
    
    if paket.haslayer(UDP):
        ports.add(paket[UDP].sport)
        ports.add(paket[UDP].dport)
        log += f"Kaynak Port: {paket[UDP].sport}\n"
        log += f"Hedef Port: {paket[UDP].dport}\n"
    
    if paket.haslayer(ICMP):
        log += f"ICMP Tipi: {paket[ICMP].type}\n"
        
    if paket.haslayer(Raw):
        log += f"Ham Veri: {paket[Raw].load}\n"
    
    device_type = guess_device_type(vendor, ports)
    log += f"Tahmini Cihaz Türü: {device_type}\n"
    
    if zararli_ip_tespit:
        log += f"UYARI: Zararlı IP tespit edildi: {zararli_ip}\n"
        print(f"Uyarı! Zararlı IP tespit edildi: {zararli_ip}")
    
    log += "-" * 50 + "\n"

    # Log dosyasına yazma işlemi
    with open(log_dosyasi, 'a') as f:
        f.write(log)
    
    print(log)  # Konsola da yazdır

# Paket yakalamayı başlat
print("Paket yakalama başladı. Çıkmak için Ctrl+C tuşlarına basın.")
try:
    sniff(prn=paket_analiz, store=False, count=10)
except KeyboardInterrupt:
    print("\nPaket yakalama sonlandırıldı.")
