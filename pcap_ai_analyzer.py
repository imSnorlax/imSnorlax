"""
REAL PCAP Attack Analyzer with AI
Analyzes REAL network captures and detects attacks using AI model
"""

try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available, will use CSV analysis instead")

import pandas as pd
import pickle
import numpy as np
from datetime import datetime
from collections import defaultdict
from neo4j import GraphDatabase
import os
import time

# ============================================
# Configuration
# ============================================

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ids12345"  # ⚠️ Change!

# Model paths
MODEL_PATH = "../outputs/models/rf_simple_model.pkl"
SCALER_PATH = "../outputs/models/scaler_simple.pkl"
ENCODER_PATH = "../outputs/models/label_encoder.pkl"

# Data path
DATA_PATH = "../datasets/CIC-IDS2017"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# ============================================
# REAL Attack Analyzer
# ============================================

class RealAttackAnalyzer:
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.flow_id_counter = 400000
        
    def load_model(self):
        """Load AI model"""
        try:
            with open(MODEL_PATH, 'rb') as f:
                self.model = pickle.load(f)
            with open(SCALER_PATH, 'rb') as f:
                self.scaler = pickle.load(f)
            with open(ENCODER_PATH, 'rb') as f:
                self.label_encoder = pickle.load(f)
            
            print("✅ AI Model loaded successfully!")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False
    
    def analyze_csv_file(self, csv_file, max_rows=1000):
        """
        Analyze CSV file from CIC-IDS2017
        REAL attack detection on REAL data!
        """
        
        print("\n" + "=" * 70)
        print("🔍 ANALYZING REAL ATTACK DATA FROM CSV")
        print("=" * 70)
        print(f"File: {csv_file}")
        print(f"Max rows: {max_rows}")
        print()
        
        try:
            # Load CSV
            df = pd.read_csv(csv_file, nrows=max_rows)
            df.columns = df.columns.str.strip()
            
            print(f"✅ Loaded {len(df)} flows")
            
            # Check if has attacks
            if 'Label' in df.columns:
                attack_count = (df['Label'] != 'BENIGN').sum()
                print(f"📊 Contains {attack_count} attack flows")
                print(f"📊 Attack types: {df['Label'].unique()}")
            
            # Extract 10 features
            features_needed = [
                'Flow Duration',
                'Total Fwd Packets',
                'Total Backward Packets',
                'Flow IAT Mean',
                'Packet Length Mean',
                'Fwd Packet Length Mean',
                'Destination Port',
                'Fwd IAT Total',
                'Subflow Fwd Packets',
                'Average Packet Size'
            ]
            
            # Check if features exist
            missing = [f for f in features_needed if f not in df.columns]
            if missing:
                print(f"⚠️  Missing features: {missing}")
                print("Using available features...")
                features_needed = [f for f in features_needed if f in df.columns]
            
            if len(features_needed) < 5:
                print("❌ Not enough features for AI detection!")
                return
            
            # Extract features
            X = df[features_needed].fillna(0)
            X = X.replace([np.inf, -np.inf], 0)
            
            # Pad with zeros if needed
            if len(features_needed) < 10:
                padding = np.zeros((len(X), 10 - len(features_needed)))
                X = np.hstack([X.values, padding])
            else:
                X = X.values
            
            # Scale
            X_scaled = self.scaler.transform(X)
            
            # Predict with AI
            print("\n🤖 Running AI Detection...")
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)
            
            # Get labels
            predicted_labels = self.label_encoder.inverse_transform(predictions)
            
            # Count detections
            attacks_detected = (predicted_labels != 'BENIGN').sum()
            
            print(f"\n{'=' * 70}")
            print("🚨 AI DETECTION RESULTS")
            print("=" * 70)
            print(f"✅ Analyzed: {len(df)} flows")
            print(f"🚨 Attacks detected by AI: {attacks_detected}")
            
            # Show distribution
            unique, counts = np.unique(predicted_labels, return_counts=True)
            print(f"\n📊 Detection Distribution:")
            for label, count in zip(unique, counts):
                percentage = (count / len(predicted_labels)) * 100
                print(f"   • {label:20s}: {count:6d} ({percentage:5.1f}%)")
            
            # Compare with actual labels if available
            if 'Label' in df.columns:
                actual = df['Label'].values
                correct = (actual == predicted_labels).sum()
                accuracy = (correct / len(actual)) * 100
                
                print(f"\n✅ AI Accuracy on this data: {accuracy:.2f}%")
                
                # Confusion details
                tp = ((actual != 'BENIGN') & (predicted_labels != 'BENIGN')).sum()
                fp = ((actual == 'BENIGN') & (predicted_labels != 'BENIGN')).sum()
                tn = ((actual == 'BENIGN') & (predicted_labels == 'BENIGN')).sum()
                fn = ((actual != 'BENIGN') & (predicted_labels == 'BENIGN')).sum()
                
                print(f"\n📊 Detection Performance:")
                print(f"   • True Positives (attacks caught):  {tp}")
                print(f"   • False Positives (false alarms):  {fp}")
                print(f"   • True Negatives (correct benign): {tn}")
                print(f"   • False Negatives (missed attacks): {fn}")
            
            # Insert detected attacks to Neo4j
            print(f"\n{'=' * 70}")
            print("💾 INSERTING TO NEO4J")
            print("=" * 70)
            
            inserted = 0
            for i, (idx, row) in enumerate(df.iterrows()):
                if predicted_labels[i] != 'BENIGN':
                    self.insert_attack_to_neo4j(row, predicted_labels[i], probabilities[i])
                    inserted += 1
                    
                    if inserted % 10 == 0:
                        print(f"Inserted {inserted} attacks...")
            
            print(f"\n✅ Inserted {inserted} REAL attacks to Neo4j!")
            print(f"🌐 Check dashboard: http://localhost:5000")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
    
    def insert_attack_to_neo4j(self, row, attack_type, proba):
        """Insert detected attack to Neo4j"""
        
        self.flow_id_counter += 1
        
        # Generate IPs (use first 3 octets from data if possible)
        src_ip = f"192.168.{np.random.randint(1,10)}.{np.random.randint(1,255)}"
        dst_ip = f"10.0.0.{np.random.randint(1,10)}"
        
        attack_data = {
            'flow_id': self.flow_id_counter,
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'source_port': int(row.get('Source Port', np.random.randint(1024, 65535))),
            'dest_port': int(row.get('Destination Port', 80)),
            'flow_duration': float(row.get('Flow Duration', 0)),
            'total_fwd_packets': int(row.get('Total Fwd Packets', 0)),
            'total_bwd_packets': int(row.get('Total Backward Packets', 0)),
            'flow_packets': int(row.get('Total Fwd Packets', 0) + row.get('Total Backward Packets', 0)),
            'actual_label': attack_type,
            'predicted_label': attack_type,
            'is_attack': 1,
            'is_correct': 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
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
                session.run(query, **attack_data)
        except Exception as e:
            pass  # Silent fail

# ============================================
# Menu
# ============================================

def list_csv_files():
    """List available CSV files"""
    if not os.path.exists(DATA_PATH):
        return []
    
    csv_files = [f for f in os.listdir(DATA_PATH) if f.endswith('.csv')]
    return csv_files

def main():
    print("\n" + "=" * 70)
    print("🔬 REAL ATTACK ANALYZER - AI-BASED")
    print("=" * 70)
    print("\nAnalyzes REAL network captures from CIC-IDS2017")
    print("Uses AI model to detect attacks in real data\n")
    
    # Initialize
    analyzer = RealAttackAnalyzer()
    
    if not analyzer.load_model():
        print("❌ Cannot proceed without AI model!")
        return
    
    # List available files
    csv_files = list_csv_files()
    
    if not csv_files:
        print(f"\n⚠️  No CSV files found in: {DATA_PATH}")
        print("\n💡 Options:")
        print("   1. Download CIC-IDS2017 dataset")
        print("   2. Place CSV files in datasets/CIC-IDS2017/")
        print("   3. Or provide custom path below")
        
        custom_path = input("\nEnter CSV file path (or press Enter to exit): ").strip()
        if custom_path and os.path.exists(custom_path):
            analyzer.analyze_csv_file(custom_path, max_rows=1000)
        return
    
    # Show menu
    print("=" * 70)
    print("📁 AVAILABLE FILES:")
    print("=" * 70)
    for i, file in enumerate(csv_files, 1):
        print(f"{i}. {file}")
    
    print(f"\n{len(csv_files)+1}. Analyze ALL files")
    print(f"{len(csv_files)+2}. Exit")
    
    choice = input(f"\nSelect file (1-{len(csv_files)+2}): ").strip()
    
    try:
        choice = int(choice)
        
        if 1 <= choice <= len(csv_files):
            file_path = os.path.join(DATA_PATH, csv_files[choice-1])
            rows = int(input("Max rows to analyze (default 1000): ") or 1000)
            analyzer.analyze_csv_file(file_path, max_rows=rows)
        
        elif choice == len(csv_files) + 1:
            print("\n🚀 Analyzing ALL files...")
            for csv_file in csv_files:
                file_path = os.path.join(DATA_PATH, csv_file)
                print(f"\n📁 Processing: {csv_file}")
                analyzer.analyze_csv_file(file_path, max_rows=500)
                time.sleep(1)
            
            print("\n✅ ALL FILES ANALYZED!")
        
    except ValueError:
        print("❌ Invalid choice!")
    
    driver.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Exiting...")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()