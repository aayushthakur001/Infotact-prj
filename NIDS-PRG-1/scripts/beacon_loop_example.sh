#!/usr/bin/env bash
# Usage: ./scripts/beacon_loop_example.sh <target_ip>
TARGET_IP="${1:-192.168.1.14}"
while true; do
  curl -H "Host: malicious-c2-server.com" "http://${TARGET_IP}/ping"
  sleep 10
done
