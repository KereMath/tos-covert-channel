#!/usr/bin/env python3
# enhanced_mitigator.py - Phase 4 Covert Channel Mitigator with Metrics
import asyncio
from nats.aio.client import Client as NATS
import os
from scapy.all import Ether, IP, UDP, Raw
from collections import deque, defaultdict
import time
import math
import json

class EnhancedTOSMitigator:
    def __init__(self):
        self.nc = NATS()
        self.tos_history = deque(maxlen=50)
        self.covert_active = False
        self.metrics = {
            "packets_processed": 0,
            "packets_mitigated": 0,
            "tos_normalized": 0,
            "bytes_mitigated": 0,
            "mitigation_rate": 0.0
        }
        self.last_report = time.time()
        
    async def connect(self):
        nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
        await self.nc.connect(nats_url)
        print(f"[MITIGATOR] Connected to NATS")
        
    def calculate_variance(self, values):
        if len(values) < 2: return 0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)
    
    def calculate_entropy(self, values):
        if not values: return 0
        counts = defaultdict(int)
        for v in values: counts[v] += 1
        total = len(values)
        entropy = 0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
    
    async def handle_packet(self, msg):
        """Detects and mitigates covert packets."""
        try:
            packet = Ether(msg.data)
            self.metrics["packets_processed"] += 1
            
            # Default action: forward the packet as is.
            mitigated_packet = packet
            mitigated = False
            
            if packet.haslayer(IP) and packet.haslayer(UDP):
                original_tos = packet[IP].tos
                self.tos_history.append(original_tos)
                
                detected_by_payload = False
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if payload in [b"START", b"END", b"HEADER", b"DATA"]:
                        detected_by_payload = True
                        if payload == b"START":
                            self.covert_active = True
                        elif payload == b"END":
                            self.covert_active = False

                detected_by_stats = False
                if len(self.tos_history) >= 20:
                    entropy = self.calculate_entropy(list(self.tos_history))
                    variance = self.calculate_variance(list(self.tos_history))
                    unusual_tos = sum(1 for t in list(self.tos_history)[-20:] if t != 0)
                    
                    if entropy > 0.3 or variance > 5 or unusual_tos > 10:
                        detected_by_stats = True
                
                detected = detected_by_payload or detected_by_stats
                
                # --- MITIGATION LOGIC ---
                if detected:
                    mitigated = True
                    self.metrics["packets_mitigated"] += 1
                    self.metrics["bytes_mitigated"] += len(msg.data)
                    
                    if original_tos != 0:
                        self.metrics["tos_normalized"] += 1
                    
                    print(f"[MITIGATION] Covert packet detected with TOS={original_tos}. Normalizing to TOS=0.")
                    mitigated_packet = packet.copy()
                    mitigated_packet[IP].tos = 0
                    
                    # Optional: Add noise or padding
                    # if packet.haslayer(Raw) and len(packet[Raw].load) < 100:
                    #     mitigated_packet[Raw].load += b'\x00' * 10  # Add padding
            
            # Periodic metrics report
            if time.time() - self.last_report > 5:
                self.report_metrics()
                self.last_report = time.time()
            
            # Forward the (potentially mitigated) packet
            modified_data = bytes(mitigated_packet)
            if msg.subject == "inpktsec":
                await self.nc.publish("outpktinsec", modified_data)
            else:
                await self.nc.publish("outpktsec", modified_data)
                
        except Exception as e:
            print(f"[ERROR] {e}")
    
    def report_metrics(self):
        """Report mitigation metrics"""
        total = self.metrics["packets_processed"]
        mitigated = self.metrics["packets_mitigated"]
        
        if total > 0:
            self.metrics["mitigation_rate"] = (mitigated / total) * 100
        
        print(f"\n{'='*60}")
        print(f"[METRICS] Mitigation Statistics:")
        print(f"  Total packets: {total}")
        print(f"  Mitigated packets: {mitigated}")
        print(f"  TOS fields normalized: {self.metrics['tos_normalized']}")
        print(f"  Bytes mitigated: {self.metrics['bytes_mitigated']}")
        print(f"  Mitigation rate: {self.metrics['mitigation_rate']:.2f}%")
        print(f"{'='*60}\n")
    
    def save_results(self):
        """Save metrics to file"""
        with open('/code/python-processor/mitigation_results.json', 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"[MITIGATOR] Results saved to mitigation_results.json")
    
    async def run(self):
        await self.connect()
        await self.nc.subscribe("inpktsec", cb=self.handle_packet)
        await self.nc.subscribe("inpktinsec", cb=self.handle_packet)
        print("[MITIGATOR] Enhanced covert channel mitigator started...")
        print("[MITIGATOR] Mitigation strategy: TOS normalization (set to 0)")
        
        try:
            while True: 
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\n[MITIGATOR] Final statistics:")
            self.report_metrics()
            self.save_results()
            await self.nc.close()

if __name__ == "__main__":
    mitigator = EnhancedTOSMitigator()
    asyncio.run(mitigator.run())