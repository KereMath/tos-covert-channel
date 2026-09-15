#!/usr/bin/env python3
import asyncio
import os
import random
from nats.aio.client import Client as NATS
from scapy.layers.l2 import Ether

class ScapyDelayProcessor:
    def __init__(self):
        self.nc = NATS()
        self.delay_value = float(os.getenv("DELAY_VALUE", "20"))
        
    async def connect(self):
        nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
        await self.nc.connect(nats_url)

    async def handle_packet(self, msg):
        subject = msg.subject
        data = msg.data
        
        ether_frame = Ether(data)
        
        delay = random.expovariate(self.delay_value)
        await asyncio.sleep(delay)
        
        target = "outpktinsec" if subject == "inpktsec" else "outpktsec"
        await self.nc.publish(target, data)
        
    async def run(self):
        await self.connect()
        await self.nc.subscribe("inpktsec", cb=self.handle_packet)
        await self.nc.subscribe("inpktinsec", cb=self.handle_packet)
        while True:
            await asyncio.sleep(1)

if __name__ == "__main__":
    processor = ScapyDelayProcessor()
    asyncio.run(processor.run())