#!/usr/bin/env python3
# simple_detector.py - v2 (FP hatası düzeltildi)
import asyncio
from nats.aio.client import Client as NATS
import os
from scapy.all import Ether, IP, UDP, Raw
from collections import deque, defaultdict
import time
import math

class SimpleTOSDetector:
    def __init__(self):
        self.nc = NATS()
        self.tos_history = deque(maxlen=50)
        self.metrics = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "packets": 0}
        self.covert_active = False
        self.last_report = time.time()
        
    async def connect(self):
        nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
        await self.nc.connect(nats_url)
        print(f"[DETECTOR] Connected to NATS")
        
    def calculate_variance(self, values):
        """Varyans hesapla (NumPy yerine)"""
        if len(values) < 2:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
    
    def calculate_entropy(self, values):
        """Shannon entropy hesapla"""
        if not values:
            return 0
        counts = defaultdict(int)
        for v in values:
            counts[v] += 1
        total = len(values)
        entropy = 0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
    
    async def handle_packet(self, msg):
        """Paket işle"""
        try:
            packet = Ether(msg.data)
            self.metrics["packets"] += 1
            
            if packet.haslayer(IP) and packet.haslayer(UDP):
                tos = packet[IP].tos
                self.tos_history.append(tos)
                
                # --- 1. Bilgi Toplama Aşaması ---
                is_start_packet = False
                is_end_packet = False
                detected_by_payload = False

                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if payload == b"START":
                        is_start_packet = True
                        detected_by_payload = True
                    elif payload == b"END":
                        is_end_packet = True
                        detected_by_payload = True
                    elif payload in [b"HEADER", b"DATA"]:
                        detected_by_payload = True

                # --- 2. Tespit Aşaması ---
                detected_by_stats = False
                if len(self.tos_history) >= 20:
                    entropy = self.calculate_entropy(list(self.tos_history))
                    variance = self.calculate_variance(list(self.tos_history))
                    unusual = sum(1 for t in self.tos_history if t != 0)
                    if entropy > 0.3 or variance > 5 or unusual > 10:
                        detected_by_stats = True
                
                detected = detected_by_payload or detected_by_stats
                
                # --- 3. Sınıflandırma Aşaması (Metrikleri Güncelle) ---
                # Bir paket, kanal zaten aktifse VEYA kanalı başlatan START paketi ise True Positive'dir.
                if detected and (self.covert_active or is_start_packet):
                    self.metrics["tp"] += 1
                elif detected and not self.covert_active:
                    self.metrics["fp"] += 1
                elif not detected and self.covert_active:
                    self.metrics["fn"] += 1
                else: # not detected and not self.covert_active
                    self.metrics["tn"] += 1

                # --- 4. Durum Güncelleme Aşaması ---
                # Metrikler güncellendikten SONRA, bir sonraki paket için durumu güncelle.
                if is_start_packet:
                    self.covert_active = True
                    print("[DETECTOR] Covert channel START detected")
                elif is_end_packet:
                    self.covert_active = False
                    print("[DETECTOR] Covert channel END detected")

                if detected:
                    print(f"[ALERT] Covert channel detected! TOS={tos}")
            
            # Paketi ilet
            if msg.subject == "inpktsec":
                await self.nc.publish("outpktinsec", msg.data)
            else:
                await self.nc.publish("outpktsec", msg.data)
            
            # Periyodik rapor
            if time.time() - self.last_report > 5:
                self.report()
                self.last_report = time.time()
                
        except Exception as e:
            print(f"[ERROR] {e}")
    
    def report(self):
        """Metrikleri raporla"""
        tp, fp, tn, fn = self.metrics["tp"], self.metrics["fp"], self.metrics["tn"], self.metrics["fn"]
        total = tp + fp + tn + fn
        if total == 0:
            return
            
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\n{'='*50}")
        print(f"Packets: {self.metrics['packets']}")
        print(f"TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
        print(f"Precision: {precision:.3f}, Recall: {recall:.3f}, F1: {f1:.3f}")
        print(f"{'='*50}\n")
    
    async def run(self):
        await self.connect()
        await self.nc.subscribe("inpktsec", cb=self.handle_packet)
        await self.nc.subscribe("inpktinsec", cb=self.handle_packet)
        
        print("[DETECTOR] Simple TOS detector started...")
        
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\n[DETECTOR] Final report:")
            self.report()
            await self.nc.close()

if __name__ == "__main__":
    detector = SimpleTOSDetector()
    asyncio.run(detector.run())
