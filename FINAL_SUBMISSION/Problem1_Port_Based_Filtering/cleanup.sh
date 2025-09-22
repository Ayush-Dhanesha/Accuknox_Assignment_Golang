#!/bin/bash

# Cleanup script to remove any existing XDP programs from interfaces
echo "🧹 Cleaning up existing XDP programs..."

# Remove XDP program from loopback interface
ip link set dev lo xdp off 2>/dev/null || true

# Remove XDP program from any ethernet interfaces
for iface in eth0 enp0s3 wlan0; do
    ip link set dev $iface xdp off 2>/dev/null || true
done

echo "✅ Cleanup complete"
