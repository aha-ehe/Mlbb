import time
import os
import sys

def read_net_dev():
    """Reads /proc/net/dev to get total RX packets."""
    total_rx_packets = 0
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
            for line in lines[2:]:  # Skip headers (first two lines)
                # Handle inconsistent formatting (some distros verify space after colon)
                # "eth0:123" vs "eth0: 123"
                parts = line.replace(':', ' ').split()
                if len(parts) > 2:
                    # Index 0: Interface Name
                    # Index 1: RX Bytes
                    # Index 2: RX Packets
                    try:
                        total_rx_packets += int(parts[2])
                    except ValueError:
                        continue
    except FileNotFoundError:
        return 0
    return total_rx_packets

def read_ctxt():
    """Reads /proc/stat to get total context switches."""
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('ctxt'):
                    return int(line.split()[1])
    except FileNotFoundError:
        return 0
    return 0

def main():
    print("=== Server-Side Interrupt Storm Detector ===")
    print("Monitoring PPS (Packets Per Second) and Context Switches...")
    print("Press Ctrl+C to stop.\n")

    last_rx_pkts = read_net_dev()
    last_ctxt = read_ctxt()
    last_time = time.time()

    # Thresholds for detection (Adjust based on server baseline)
    PPS_THRESHOLD = 5000       # 5k PPS is suspicious for a single game instance
    CTXT_THRESHOLD = 10000     # High context switching indicates interrupt storm

    try:
        while True:
            time.sleep(1)

            current_rx_pkts = read_net_dev()
            current_ctxt = read_ctxt()
            current_time = time.time()

            elapsed = current_time - last_time
            if elapsed == 0: continue

            pps = (current_rx_pkts - last_rx_pkts) / elapsed
            ctx_switch_rate = (current_ctxt - last_ctxt) / elapsed

            # Detection Logic
            status = "NORMAL"
            if pps > PPS_THRESHOLD or ctx_switch_rate > CTXT_THRESHOLD:
                status = "WARNING: POTENTIAL STORM"
                if pps > PPS_THRESHOLD * 2:
                    status = "CRITICAL: INTERRUPT STORM DETECTED"

            print(f"Time: {time.strftime('%H:%M:%S')} | PPS: {int(pps):<6} | CTXT/s: {int(ctx_switch_rate):<6} | Status: {status}")

            last_rx_pkts = current_rx_pkts
            last_ctxt = current_ctxt
            last_time = current_time

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    if not os.path.exists('/proc/net/dev'):
        print("Error: This script requires a Linux environment with /proc filesystem.")
        sys.exit(1)
    main()
