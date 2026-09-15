#!/usr/bin/env python3
import argparse
import time
import os
import sys
import random
import math
from scapy.all import IP, UDP, Raw, send

parser = argparse.ArgumentParser(description='TOS Covert Channel Sender with Header')
parser.add_argument('--message', type=str, default='CENG435 TOS COVERT CHANNEL',
                    help='Gizli olarak iletilecek mesaj')
parser.add_argument('--tos-mapping-bits', type=int, default=3, 
                    help='TOS alanında kullanılacak bit sayısı (1-8)')
parser.add_argument('--interval', type=float, default=0.1, 
                    help='Paketler arası zaman aralığı (saniye)')
parser.add_argument('--target-ip', type=str, 
                    default=os.getenv('INSECURENET_HOST_IP', '10.0.0.15'),
                    help='Hedef IP adresi')
parser.add_argument('--port', type=int, default=8888, 
                    help='Kullanılacak UDP portu')
parser.add_argument('--packets-per-symbol', type=int, default=1,
                    help='Her sembol için gönderilecek paket sayısı (redundancy)')
parser.add_argument('--repeat-message', type=int, default=1,
                    help='Mesajın tekrarlanma sayısı')
args = parser.parse_args()

def string_to_symbols(message, bits_per_symbol):
    # Mesajı 8-bit ASCII şeklinde binary'ye çevirir.
    binary = ''.join(format(ord(char), '08b') for char in message)
    # Bit sayısına göre eksik kalan bitleri sıfırlarla tamamla.
    if len(binary) % bits_per_symbol != 0:
        padding = bits_per_symbol - (len(binary) % bits_per_symbol)
        binary += '0' * padding
    symbols = [int(binary[i:i+bits_per_symbol], 2) for i in range(0, len(binary), bits_per_symbol)]
    return symbols

def create_header(num_symbols, bits_per_symbol):
    # Payload (veri) sembol sayısını kodlamak için en az 16 bitlik header kullanıyoruz.
    header_symbol_count = -(-16 // bits_per_symbol)
    header_bit_length = header_symbol_count * bits_per_symbol
    header_binary = format(num_symbols, f'0{header_bit_length}b')
    header_symbols = [int(header_binary[i:i+bits_per_symbol], 2) for i in range(0, len(header_binary), bits_per_symbol)]
    return header_symbols, header_symbol_count

def send_packet(tos_value, payload, target_ip, port):
    packet = IP(dst=target_ip, tos=tos_value) / UDP(dport=port, sport=random.randint(1024, 65535)) / Raw(load=payload)
    send(packet, verbose=0)

def send_message(message, bits_per_symbol, interval, target_ip, port, packets_per_symbol):
    payload_symbols = string_to_symbols(message, bits_per_symbol)
    num_payload_symbols = len(payload_symbols)
    header_symbols, header_symbol_count = create_header(num_payload_symbols, bits_per_symbol)
    
    total_packets = 0
    start_time = time.time()
    
    print("START sinyali gönderiliyor...")
    # START kontrol paketlerini birkaç kez gönder
    for _ in range(3):
        send_packet(0, b"START", target_ip, port)
        total_packets += 1
        time.sleep(interval)
        
    print("Header gönderiliyor...")
    for sym in header_symbols:
        for _ in range(packets_per_symbol):
            send_packet(sym, b"HEADER", target_ip, port)
            total_packets += 1
            time.sleep(interval)
            
    print("Payload (veri) gönderiliyor...")
    for sym in payload_symbols:
        for _ in range(packets_per_symbol):
            send_packet(sym, b"DATA", target_ip, port)
            total_packets += 1
            time.sleep(interval)
            
    print("END sinyali gönderiliyor...")
    for _ in range(3):
        send_packet(0, b"END", target_ip, port)
        total_packets += 1
        time.sleep(interval)
        
    end_time = time.time()
    time_taken = end_time - start_time
    return time_taken, len(payload_symbols), total_packets

def main():
    # Test konfigürasyon parametrelerini yazdır.
    print("=== Sender Test Configuration ===")
    print(f"Mesaj                : {args.message}")
    print(f"TOS Mapping Bits     : {args.tos_mapping_bits}")
    print(f"Interval (s)         : {args.interval}")
    print(f"Hedef IP             : {args.target_ip}")
    print(f"UDP Port             : {args.port}")
    print(f"Redundancy (Packets/Symbol): {args.packets_per_symbol}")
    print(f"Tekrar sayısı        : {args.repeat_message}")
    print("=================================\n")
    
    for i in range(args.repeat_message):
        print(f"\nMesaj tekrarı {i+1} başlıyor...")
        time_taken, symbols_sent, packets_sent = send_message(
            args.message, args.tos_mapping_bits, args.interval, 
            args.target_ip, args.port, args.packets_per_symbol
        )
        print(f"Tekrar {i+1}: {time_taken:.3f} saniye sürdü, Payload sembol sayısı: {symbols_sent}, Toplam paket: {packets_sent}")
        if i < args.repeat_message - 1:
            time.sleep(1)

if __name__ == "__main__":
    main()
