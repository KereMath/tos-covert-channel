#!/usr/bin/env python3
import os
import re
import glob
import matplotlib.pyplot as plt
import numpy as np

delay_values = []
avg_rtts = []

for filename in glob.glob("*.txt"):
    try:
        delay_value = float(filename.split('.')[0])
        
        with open(filename, 'r') as f:
            content = f.read()
            
            rtt_match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', content)
            
            if rtt_match:
                avg_rtt = float(rtt_match.group(2))
                
                # Store the raw values
                delay_values.append(delay_value)
                avg_rtts.append(avg_rtt)
    except:
        print(f"Skipping file: {filename}")

combined = sorted(zip(delay_values, avg_rtts))
delay_values, avg_rtts = zip(*combined)

plt.figure(figsize=(10, 6))

plt.plot(delay_values, avg_rtts, 'o-', markersize=8, linewidth=2)

plt.title("Effect of Random Delay on Round-Trip Time", fontsize=16)
plt.xlabel("Delay Value (λ)", fontsize=14)
plt.ylabel("Average RTT (ms)", fontsize=14)

plt.grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
plt.savefig("delay_analysis.png", dpi=300)
print("Plot saved as 'delay_analysis.png'")

print("\nData points:")
for d, r in zip(delay_values, avg_rtts):
    print(f"Delay: {d}, RTT: {r:.2f} ms")

plt.show()