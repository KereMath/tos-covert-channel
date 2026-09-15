#!/usr/bin/env python3
import argparse
import time
import sys
import signal
from collections import Counter
from statistics import mean, stdev
from scapy.all import sniff, IP, UDP, Raw

parser = argparse.ArgumentParser(description='TOS Covert Channel Receiver with Header and Performance Measurement')
parser.add_argument('--tos-mapping-bits', type=int, default=3, 
                    help='TOS alanında kullanılacak bit sayısı (1-8)')
parser.add_argument('--port', type=int, default=8888, 
                    help='Dinlenecek UDP portu')
parser.add_argument('--timeout', type=int, default=180,
                    help='Paket alınamadığında durması için timeout (saniye)')
parser.add_argument('--packets-per-symbol', type=int, default=1,
                    help='Her sembol için beklenen paket sayısı (redundancy)')
parser.add_argument('--iface', type=str, default="eth0", 
                    help="Dinlenecek ağ arayüzü")
args = parser.parse_args()

class TOSCovertReceiver:
    def __init__(self, bits_per_symbol, port, packets_per_symbol=1):
        self.bits_per_symbol = bits_per_symbol
        self.port = port
        self.packets_per_symbol = packets_per_symbol
        # Durumlar: "waiting", "header", "payload", "complete"
        self.state = "waiting"
        
        # Header için sabit uzunluk: en az 16 bit -> bits_per_symbol’a göre yukarı yuvarlanır.
        self.header_symbol_count = -(-16 // self.bits_per_symbol)
        self.header_symbols = []  # Header kısmında toplanan semboller
        self.payload_symbols = []  # Payload kısmında toplanan semboller
        
        # Redundans için geçici sembol buffer
        self.symbol_buffer = []
        self.current_symbol_count = 0
        
        self.payload_count_expected = None  # Header'dan belirlenecek payload sembol sayısı
        
        self.start_time = None
        self.end_time = None
        self.last_packet_time = None

        # Alınan mesajların performans ölçümleri: [(mesaj süresi, throughput), ...]
        self.performance_results = []

    def reset(self):
        self.state = "waiting"
        self.header_symbols = []
        self.payload_symbols = []
        self.symbol_buffer = []
        self.current_symbol_count = 0
        self.payload_count_expected = None
        self.start_time = None
        self.end_time = None

    def process_control(self, payload):
        if payload == b"START":
            if self.state == "waiting":
                print("START sinyali alındı. HEADER durumuna geçiliyor.")
                self.state = "header"
                self.header_symbols = []
                self.symbol_buffer = []
                self.current_symbol_count = 0
            else:
                print(f"Ek START sinyali alındı (durum: {self.state}); yoksayılıyor.")
        elif payload == b"END":
            # END paketlerini yalnızca payload tamamlanmışsa işleyelim.
            if self.state == "header":
                print("END sinyali alındı ancak header tamamlanmadı; yoksayılıyor.")
            elif self.state == "payload":
                if self.payload_count_expected is None or len(self.payload_symbols) < self.payload_count_expected:
                    print("END sinyali alındı ancak payload tamamlanmadı; yoksayılıyor.")
                else:
                    print("END sinyali alındı, mesaj tamamlandı.")
                    self.state = "complete"
                    self.end_time = time.time()
                    self.process_received_data()
            else:
                # waiting veya complete durumunda kontrol paketleri yoksayılıyor.
                pass

    def add_symbol(self, symbol_value, target_list):
        self.symbol_buffer.append(symbol_value)
        self.current_symbol_count += 1
        if self.current_symbol_count >= self.packets_per_symbol:
            most_common_value = Counter(self.symbol_buffer).most_common(1)[0][0]
            target_list.append(most_common_value)
            self.symbol_buffer = []
            self.current_symbol_count = 0

    def packet_handler(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(Raw) and packet[UDP].dport == self.port):
            return
        
        tos_value = packet[IP].tos
        payload = packet[Raw].load
        self.last_packet_time = time.time()
        if self.start_time is None:
            self.start_time = self.last_packet_time

        # Kontrol paketleri
        if payload in [b"START", b"END"]:
            self.process_control(payload)
            return

        # Duruma bağlı işleme:
        if self.state == "header" and payload == b"HEADER":
            self.add_symbol(tos_value, self.header_symbols)
            if len(self.header_symbols) == self.header_symbol_count:
                header_binary = ''.join(format(s, f'0{self.bits_per_symbol}b') for s in self.header_symbols)
                self.payload_count_expected = int(header_binary, 2)
                print(f"Header alındı. {self.payload_count_expected} payload sembolü bekleniyor.")
                self.state = "payload"
        elif self.state == "payload" and payload == b"DATA":
            self.add_symbol(tos_value, self.payload_symbols)
            if self.payload_count_expected is not None and len(self.payload_symbols) == self.payload_count_expected:
                self.state = "complete"
                self.end_time = time.time()
                self.process_received_data()

    def decode_binary_to_message(self, symbols):
        binary_string = ''.join(format(value, f'0{self.bits_per_symbol}b') for value in symbols)
        decoded_message = ''
        for i in range(0, len(binary_string) - (len(binary_string) % 8), 8):
            byte = binary_string[i:i+8]
            try:
                decoded_message += chr(int(byte, 2))
            except Exception:
                decoded_message += '?'
        return decoded_message

    def process_received_data(self):
        if not self.payload_symbols:
            print("Hiç payload sembolü alınamadı.")
            return
        message = self.decode_binary_to_message(self.payload_symbols)
        duration = self.end_time - self.start_time if self.end_time and self.start_time else 0
        # Payload'da (header'da belirlenen) sembol sayısı * bits_per_symbol = toplam bit sayısı
        payload_bits = self.payload_count_expected * self.bits_per_symbol if self.payload_count_expected else 0
        throughput = payload_bits / duration if duration > 0 else 0
        print("\nAlınan ve çözümlenen mesaj:")
        print(message)
        print(f"Mesaj süresi: {duration:.3f} saniye, Kapasite: {throughput:.3f} bit/s")
        self.performance_results.append((duration, throughput))
        self.reset()

    def print_performance(self):
        if not self.performance_results:
            print("Hiç mesaj alınmadı, performans ölçümü yapılamadı.")
            return
        durations = [r[0] for r in self.performance_results]
        throughputs = [r[1] for r in self.performance_results]
        n = len(self.performance_results)
        avg_duration = mean(durations)
        avg_throughput = mean(throughputs)
        if n > 1:
            ci_duration = 1.96 * stdev(durations) / (n**0.5)
            ci_throughput = 1.96 * stdev(throughputs) / (n**0.5)
        else:
            ci_duration = 0
            ci_throughput = 0
        print("\n***** Performans Özeti *****")
        print(f"Alınan mesaj sayısı: {n}")
        print(f"Ortalama süre: {avg_duration:.3f} ± {ci_duration:.3f} saniye")
        print(f"Ortalama kapasite: {avg_throughput:.3f} ± {ci_throughput:.3f} bit/s")
        print("******************************\n")

    def start_capturing(self, timeout=180):
        def handle_timeout(signum, frame):
            print("Timeout gerçekleşti. Yakalama durduruluyor.")
            if self.state in ["header", "payload"]:
                print("Eksik mesaj alınmış. Durum sıfırlanıyor.")
                self.reset()
            self.print_performance()
            sys.exit(0)
        
        signal.signal(signal.SIGALRM, handle_timeout)
        signal.alarm(timeout)
        
        try:
            sniff(prn=self.packet_handler, filter=f"udp port {self.port}", iface=args.iface, store=0)
        except KeyboardInterrupt:
            print("\nKlavye kesintisi tespit edildi. Son performans bilgileri:")
            self.print_performance()
            sys.exit(0)

def main():
    # Test konfigürasyon parametrelerini yazdır
    print("=== Receiver Test Configuration ===")
    print(f"TOS Mapping Bits      : {args.tos_mapping_bits}")
    print(f"Redundancy (Packets/Symbol): {args.packets_per_symbol}")
    print(f"UDP Port              : {args.port}")
    print(f"Timeout (s)           : {args.timeout}")
    print(f"Interface             : {args.iface}")
    print("=====================================\n")
    
    receiver = TOSCovertReceiver(args.tos_mapping_bits, args.port, args.packets_per_symbol)
    print("TOS Covert Channel Receiver başlatılıyor...")
    receiver.start_capturing(args.timeout)

if __name__ == "__main__":
    main()
