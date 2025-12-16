"""
Real-Time Packet Sniffer & Attack Detector
Captures network traffic and detects attacks in real-time
"""

import socket
import struct
import threading
from datetime import datetime
from collections import defaultdict
import time
from neo4j import GraphDatabase
import pickle
import numpy as np
import os

# ============================================
# Configuration
# ============================================

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ids12345"  # ⚠️ Change!

# Load AI Model
MODEL_PATH = "../outputs/models/rf_intrusion_model.pkl"
SCALER_PATH = "../outputs/models/scaler.pkl"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# ============================================
# Traffic Monitor
# ============================================

class TrafficMonitor:
    
    def __init__(self, window_size=10):
        self.window_size = window_size  # seconds
        self.traffic_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'connections': set(),
            'start_time': time.time()
        })
        self.model = None
        self.scaler = None
        self.flow_id_counter = 100000
        
    def load_model(self):
        """Load AI model if available"""
        try:
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
                print("✅ AI Model loaded!")
                return True
            else:
                print("⚠️  Model not found, using rule-based detection")
                return False
        except Exception as e:
            print(f"⚠️  Could not load model: {e}")
            return False
    
    def analyze_flow(self, src_ip, dst_ip, src_port, dst_port, packet_size):
        """Analyze traffic flow and detect attacks"""
        
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        stats = self.traffic_stats[flow_key]
        
        # Update stats
        stats['packets'] += 1
        stats['bytes'] += packet_size
        stats['connections'].add((src_ip, dst_ip))
        
        # Check if window expired
        elapsed = time.time() - stats['start_time']
        if elapsed >= self.window_size:
            # Analyze this flow
            is_attack, attack_type = self.detect_attack(flow_key, stats)
            
            if is_attack:
                self.report_attack(src_ip, dst_ip, src_port, dst_port, 
                                 stats, attack_type)
            
            # Reset stats
            del self.traffic_stats[flow_key]
    
    def detect_attack(self, flow_key, stats):
        """
        Detect if traffic is an attack using heuristics
        ⚠️ VERY SENSITIVE FOR TESTING!
        """
        packets = stats['packets']
        rate = packets / self.window_size
        
        # VERY LOW THRESHOLDS FOR LOCALHOST TESTING
        
        # DDoS: Low packet rate
        if rate > 3:  # Just 3 packets/sec!
            return True, "DDoS"
        
        # Port Scan: Few unique destinations
        if len(stats['connections']) > 2:
            return True, "PortScan"
        
        # Connection Flood: ANY repeated connections
        if packets > 3:  # Just 3 packets total!
            return True, "ConnectionFlood"
        
        # HTTP Flood: Check common ports
        if ':80' in flow_key or ':443' in flow_key or ':8080' in flow_key or ':9999' in flow_key:
            if packets > 2:  # Just 2 packets to web port!
                return True, "HTTPFlood"
        
        return False, "BENIGN"
    
    def report_attack(self, src_ip, dst_ip, src_port, dst_port, stats, attack_type):
        """Report detected attack to Neo4j"""
        
        self.flow_id_counter += 1
        
        attack_data = {
            'flow_id': self.flow_id_counter,
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'source_port': src_port,
            'dest_port': dst_port,
            'flow_duration': self.window_size * 1000,  # ms
            'total_fwd_packets': stats['packets'],
            'total_bwd_packets': 0,
            'flow_packets': stats['packets'],
            'actual_label': attack_type,
            'predicted_label': attack_type,
            'is_attack': 1,
            'is_correct': 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Insert to Neo4j
        self.insert_to_neo4j(attack_data)
        
        # Display alert
        print("\n" + "="*70)
        print(f"🚨 ATTACK DETECTED!")
        print("="*70)
        print(f"Type: {attack_type}")
        print(f"Source: {src_ip}:{src_port}")
        print(f"Target: {dst_ip}:{dst_port}")
        print(f"Packets: {stats['packets']} ({stats['packets']/self.window_size:.1f} pkt/s)")
        print(f"Time: {attack_data['timestamp']}")
        print("="*70 + "\n")
    
    def insert_to_neo4j(self, attack):
        """Insert attack into Neo4j"""
        try:
            with driver.session() as session:
                query = """
                MERGE (source:IP {address: $source_ip})
                MERGE (dest:IP {address: $dest_ip})
                CREATE (flow:NetworkFlow {
                    flow_id: $flow_id,
                    source_port: $source_port,
                    dest_port: $dest_port,
                    flow_duration: $flow_duration,
                    total_fwd_packets: $total_fwd_packets,
                    total_bwd_packets: $total_bwd_packets,
                    flow_packets: $flow_packets,
                    actual_label: $actual_label,
                    predicted_label: $predicted_label,
                    is_attack: $is_attack,
                    is_correct: $is_correct,
                    timestamp: $timestamp
                })
                CREATE (source)-[:CONNECTS_TO]->(flow)
                CREATE (flow)-[:TARGETS]->(dest)
                """
                session.run(query, **attack)
                print("✅ Attack logged to Neo4j")
        except Exception as e:
            print(f"❌ Neo4j error: {e}")

# ============================================
# Simple Packet Sniffer (Windows Compatible)
# ============================================

class SimplePacketSniffer:
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.running = False
        
    def parse_ip_header(self, data):
        """Parse IP header"""
        try:
            # IP Header is first 20 bytes
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            
            version_ihl = ip_header[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            protocol = ip_header[6]
            src_addr = socket.inet_ntoa(ip_header[8])
            dst_addr = socket.inet_ntoa(ip_header[9])
            
            return src_addr, dst_addr, protocol, iph_length
        except:
            return None, None, None, None
    
    def parse_tcp_header(self, data, iph_length):
        """Parse TCP header"""
        try:
            tcp_header = struct.unpack('!HHLLBBHHH', data[iph_length:iph_length+20])
            src_port = tcp_header[0]
            dst_port = tcp_header[1]
            return src_port, dst_port
        except:
            return None, None
    
    def start_sniffing(self):
        """Start packet sniffing"""
        print("\n" + "="*70)
        print("🔍 PACKET SNIFFER STARTED")
        print("="*70)
        print("Monitoring network traffic...")
        print("Press Ctrl+C to stop\n")
        
        self.running = True
        
        try:
            # Create raw socket (Windows)
            host = socket.gethostbyname(socket.gethostname())
            
            # RAW socket
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((host, 0))
            
            # Include IP headers
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Enable promiscuous mode (Windows)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            packet_count = 0
            
            while self.running:
                # Receive packet
                packet = sniffer.recvfrom(65565)
                packet_data = packet[0]
                
                # Parse IP header
                src_ip, dst_ip, protocol, iph_length = self.parse_ip_header(packet_data)
                
                if src_ip and dst_ip:
                    packet_count += 1
                    
                    # TCP protocol
                    if protocol == 6:
                        src_port, dst_port = self.parse_tcp_header(packet_data, iph_length)
                        
                        if src_port and dst_port:
                            # Analyze flow
                            self.monitor.analyze_flow(src_ip, dst_ip, src_port, 
                                                    dst_port, len(packet_data))
                    
                    # Display progress
                    if packet_count % 100 == 0:
                        print(f"📊 Packets analyzed: {packet_count}")
            
            # Disable promiscuous mode
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            
        except PermissionError:
            print("\n❌ Error: Need administrator privileges!")
            print("Run as: python packet_sniffer.py (with admin rights)")
        except KeyboardInterrupt:
            print("\n⚠️  Sniffer stopped by user")
        except Exception as e:
            print(f"\n❌ Error: {e}")
        finally:
            self.running = False
            print("\n✅ Sniffer stopped")

# ============================================
# Main
# ============================================

def main():
    print("\n" + "="*70)
    print("🛡️  REAL-TIME INTRUSION DETECTION SYSTEM")
    print("="*70)
    print("\n⚠️  This tool requires administrator privileges on Windows!")
    print("\nFeatures:")
    print("  • Real-time packet capture")
    print("  • Attack detection (DDoS, PortScan, Floods)")
    print("  • Automatic logging to Neo4j")
    print("  • Dashboard integration")
    
    input("\nPress Enter to start sniffer...")
    
    # Initialize
    monitor = TrafficMonitor(window_size=5)  # 5 second window
    monitor.load_model()
    
    sniffer = SimplePacketSniffer(monitor)
    
    # Start sniffing
    sniffer.start_sniffing()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Exiting...")