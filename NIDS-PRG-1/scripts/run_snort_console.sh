#!/usr/bin/env bash
# Usage: sudo ./scripts/run_snort_console.sh <interface>
IFACE="${1:-enp0s3}"
sudo snort -A console -q -c /etc/snort/snort.conf -i "$IFACE"
