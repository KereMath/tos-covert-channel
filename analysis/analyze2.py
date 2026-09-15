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
                
                delay_values.append(delay_value)
                avg_rtts.append(avg_rtt)
    except:
        print(f"Skipping file: {filename}")

combined = sorted(zip(delay_values, avg_rtts))
delay_values, avg_rtts = zip(*combined)

mean_delays = [1000/dv for dv in delay_values]

plt.figure(figsize=(12, 8))

plt.plot(mean_delays, avg_rtts, 'o-', markersize=10, linewidth=2, color='blue')

plt.xticks([])  
plt.xlim(min(mean_delays)*0.5, max(mean_delays)*1.5)  # Add more margin

num_points = len(mean_delays)
for i, (x, y) in enumerate(zip(mean_delays, avg_rtts)):
    angle = (i * 40) % 360 
    distance = 60 + (i * 10) % 40  
    
    rad_angle = np.radians(angle)
    dx = distance * np.cos(rad_angle)
    dy = distance * np.sin(rad_angle)
    
    plt.annotate(f"{x:.1f}", 
                xy=(x, y), 
                xytext=(dx, dy), 
                textcoords='offset points',
                arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0.2', color='gray'),
                ha='center', va='center', 
                fontsize=10, 
                bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='gray', alpha=0.8))

plt.title("Effect of Random Delay on Round-Trip Time", fontsize=16)
plt.xlabel("Mean Value (1/λ*1000 ms)", fontsize=14)
plt.ylabel("Average RTT (ms)", fontsize=14)

plt.grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
plt.savefig("mean_delay_rtt_analysis.png", dpi=300)

print("\nData points:")
print("--------------------------------------")
print("| Lambda (λ) | Mean Delay (ms) | RTT (ms) |")
print("--------------------------------------")
for d, m, r in zip(delay_values, mean_delays, avg_rtts):
    print(f"| {d:9.1f} | {m:14.2f} | {r:7.2f} |")
print("--------------------------------------")

plt.show()