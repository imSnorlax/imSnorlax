"""
AI-Based Real-Time Packet Sniffer
Uses REAL AI Model (10 features) for attack detection
"""

import socket
import struct
import time
from datetime import datetime
from collections import defaultdict
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

# AI Model Paths
MODEL_PATH = "../outputs/models/rf_simple_model.pkl"
SCALER_PATH = "../outputs/models/scaler_simple.pkl"
ENCODER_PATH = "../outputs/models/label_encoder.pkl"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# ============================================
# AI-Based Traffic Monitor
# ============================================

class AITrafficMonitor:
    
    def __init__(self, window_size=10):
        self.window_size = window_size
        self.flow_stats = defaultdict(lambda: {
            'start_time': time.time(),
            'packets': [],
            'fwd_packets': 0,
            'bwd_packets': 0,
            'packet_lengths': [],
            'fwd_lengths': [],
            'inter_arrival_times': [],
            'last_packet_time': None,
            'dest_port': 0
        })
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.flow_id_counter = 300000
        
    def load_ai_model(self):
        """Load simplified AI model"""
        try:
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
                with open(ENCODER_PATH, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                
                print("=" * 70)
                print("✅ AI MODEL LOADED SUCCESSFULLY!")
                print("=" * 70)
                print(f"Model: Simplified Random Forest (10 features)")
                print(f"Ready for REAL AI-based detection!")
                print("=" * 70 + "\n")
                return True
            else:
                print(f"❌ Model not found at: {MODEL_PATH}")
                return False
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False
    
    def analyze_packet(self, src_ip, dst_ip, src_port, dst_port, packet_size, is_forward=True):
        """Analyze individual packet and update flow stats"""
        
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        stats = self.flow_stats[flow_key]
        
        # Update basic stats
        current_time = time.time()
        
        if stats['last_packet_time'] is not None:
            iat = (current_time - stats['last_packet_time']) * 1000  # ms
            stats['inter_arrival_times'].append(iat)
        
        stats['last_packet_time'] = current_time
        stats['packets'].append(packet_size)
        stats['packet_lengths'].append(packet_size)
        stats['dest_port'] = dst_port
        
        if is_forward:
            stats['fwd_packets'] += 1
            stats['fwd_lengths'].append(packet_size)
        else:
            stats['bwd_packets'] += 1
        
        # Check if window expired
        elapsed = current_time - stats['start_time']
        if elapsed >= self.window_size:
            # Analyze this flow with AI
            self.analyze_flow_with_ai(flow_key, stats, src_ip, dst_ip, src_port, dst_port)
            # Reset
            del self.flow_stats[flow_key]
    
    def extract_features(self, stats):
        """Extract 10 features for AI model"""
        
        elapsed = time.time() - stats['start_time']
        total_packets = len(stats['packets'])
        
        if total_packets == 0:
            return None
        
        # Calculate features
        flow_duration = elapsed * 1000  # ms
        total_fwd = stats['fwd_packets']
        total_bwd = stats['bwd_packets']
        
        # IAT Mean
        iat_mean = np.mean(stats['inter_arrival_times']) if stats['inter_arrival_times'] else 0
        
        # Packet lengths
        packet_length_mean = np.mean(stats['packet_lengths']) if stats['packet_lengths'] else 0
        fwd_length_mean = np.mean(stats['fwd_lengths']) if stats['fwd_lengths'] else 0
        
        # Dest port
        dest_port = stats['dest_port']
        
        # Fwd IAT Total
        fwd_iat_total = sum(stats['inter_arrival_times']) if stats['inter_arrival_times'] else 0
        
        # Subflow Fwd Packets (simplified: same as total_fwd)
        subflow_fwd = total_fwd
        
        # Average packet size
        avg_packet_size = packet_length_mean
        
        # Create feature vector (10 features)
        features = np.array([
            flow_duration,
            total_fwd,
            total_bwd,
            iat_mean,
            packet_length_mean,
            fwd_length_mean,
            dest_port,
            fwd_iat_total,
            subflow_fwd,
            avg_packet_size
        ]).reshape(1, -1)
        
        return features
    
    def analyze_flow_with_ai(self, flow_key, stats, src_ip, dst_ip, src_port, dst_port):
        """Use AI model to detect attack"""
        
        if self.model is None:
            return
        
        # Extract features
        features = self.extract_features(stats)
        
        if features is None:
            return
        
        try:
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # AI Prediction
            prediction = self.model.predict(features_scaled)[0]
            prediction_proba = self.model.predict_proba(features_scaled)[0]
            
            # Get label
            predicted_label = self.label_encoder.inverse_transform([prediction])[0]
            confidence = max(prediction_proba) * 100
            
            # If attack detected
            if predicted_label != 'BENIGN':
                self.report_attack(
                    src_ip, dst_ip, src_port, dst_port,
                    stats, predicted_label, confidence
                )
        
        except Exception as e:
            print(f"⚠️  AI prediction error: {e}")
    
    def report_attack(self, src_ip, dst_ip, src_port, dst_port, stats, attack_type, confidence):
        """Report AI-detected attack"""
        
        self.flow_id_counter += 1
        
        total_packets = len(stats['packets'])
        
        attack_data = {
            'flow_id': self.flow_id_counter,
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'source_port': src_port,
            'dest_port': dst_port,
            'flow_duration': (time.time() - stats['start_time']) * 1000,
            'total_fwd_packets': stats['fwd_packets'],
            'total_bwd_packets': stats['bwd_packets'],
            'flow_packets': total_packets,
            'actual_label': attack_type,
            'predicted_label': attack_type,
            'is_attack': 1,
            'is_correct': 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Insert to Neo4j
        self.insert_to_neo4j(attack_data)
        
        # Display alert
        print("\n" + "=" * 70)
        print(f"🚨 AI-DETECTED ATTACK!")
        print("=" * 70)
        print(f"🤖 AI Model Prediction: {attack_type}")
        print(f"📊 Confidence: {confidence:.1f}%")
        print(f"🔴 Source: {src_ip}:{src_port}")
        print(f"🎯 Target: {dst_ip}:{dst_port}")
        print(f"📦 Packets: {total_packets}")
        print(f"⏱️  Duration: {attack_data['flow_duration']:.0f}ms")
        print(f"🕒 Time: {attack_data['timestamp']}")
        print("=" * 70 + "\n")
    
    def insert_to_neo4j(self, attack):
        """Insert attack to Neo4j"""
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
# Packet Sniffer
# ============================================

class AIPacketSniffer:
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.running = False
    
    def parse_ip_header(self, data):
        """Parse IP header"""
        try:
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
        """Start AI-based packet sniffing"""
        print("\n" + "=" * 70)
        print("🤖 AI-BASED PACKET SNIFFER STARTED")
        print("=" * 70)
        print("Using REAL AI Model for attack detection!")
        print("Monitoring network traffic...")
        print("Press Ctrl+C to stop\n")
        
        self.running = True
        
        try:
            host = socket.gethostbyname(socket.gethostname())
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((host, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            packet_count = 0
            
            while self.running:
                packet = sniffer.recvfrom(65565)
                packet_data = packet[0]
                
                src_ip, dst_ip, protocol, iph_length = self.parse_ip_header(packet_data)
                
                if src_ip and dst_ip and protocol == 6:  # TCP
                    src_port, dst_port = self.parse_tcp_header(packet_data, iph_length)
                    
                    if src_port and dst_port:
                        packet_count += 1
                        
                        # Analyze with AI
                        self.monitor.analyze_packet(
                            src_ip, dst_ip, src_port, dst_port,
                            len(packet_data), is_forward=True
                        )
                        
                        if packet_count % 100 == 0:
                            print(f"📊 Packets analyzed: {packet_count} (AI-based detection active)")
            
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            
        except PermissionError:
            print("\n❌ Need administrator privileges!")
        except KeyboardInterrupt:
            print("\n⚠️  Sniffer stopped by user")
        except Exception as e:
            print(f"\n❌ Error: {e}")
        finally:
            self.running = False
            print("\n✅ AI Sniffer stopped")

# ============================================
# Main
# ============================================

def main():
    print("\n" + "=" * 70)
    print("🤖 AI-BASED INTRUSION DETECTION SYSTEM")
    print("=" * 70)
    print("\n⚡ Real AI Model Detection (10 Features)")
    print("⚠️  Requires administrator privileges on Windows!\n")
    
    input("Press Enter to start AI sniffer...")
    
    # Initialize
    monitor = AITrafficMonitor(window_size=10)
    
    if not monitor.load_ai_model():
        print("\n❌ Cannot start without AI model!")
        return
    
    sniffer = AIPacketSniffer(monitor)
    sniffer.start_sniffing()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Exiting...")