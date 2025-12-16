"""
Real-Time Attack Simulator for IDS Dashboard
Simulates network attacks and inserts them into Neo4j
"""

import random
import time
from datetime import datetime
from neo4j import GraphDatabase
import numpy as np

# ============================================
# Configuration Neo4j
# ============================================

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ids12345"  # ⚠️ Change avec ton password!

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# ============================================
# Attack Types Configuration
# ============================================

ATTACK_TYPES = {
    'DDoS': {
        'probability': 0.4,
        'packets_range': (5000, 50000),
        'duration_range': (100, 5000),
        'ports': [80, 443, 8080, 53]
    },
    'PortScan': {
        'probability': 0.3,
        'packets_range': (100, 1000),
        'duration_range': (50, 500),
        'ports': list(range(20, 9000, 100))
    },
    'BruteForce': {
        'probability': 0.2,
        'packets_range': (200, 2000),
        'duration_range': (200, 2000),
        'ports': [22, 21, 3389, 445]
    },
    'WebAttack': {
        'probability': 0.1,
        'packets_range': (50, 500),
        'duration_range': (10, 200),
        'ports': [80, 443, 8080, 8443]
    }
}

# IP Pools
SOURCE_IPS = [
    f"192.168.{random.randint(1, 10)}.{random.randint(1, 255)}" 
    for _ in range(20)
]

DEST_IPS = [
    f"10.0.{random.randint(1, 5)}.{random.randint(1, 255)}" 
    for _ in range(10)
]

# ============================================
# Attack Generator
# ============================================

class AttackSimulator:
    
    def __init__(self, driver):
        self.driver = driver
        self.flow_id_counter = 10000
        
    def generate_attack(self):
        """Generate a random attack flow"""
        
        # Select attack type based on probability
        attack_type = random.choices(
            list(ATTACK_TYPES.keys()),
            weights=[ATTACK_TYPES[t]['probability'] for t in ATTACK_TYPES.keys()]
        )[0]
        
        config = ATTACK_TYPES[attack_type]
        
        # Generate attack parameters
        source_ip = random.choice(SOURCE_IPS)
        dest_ip = random.choice(DEST_IPS)
        source_port = random.randint(1024, 65535)
        dest_port = random.choice(config['ports'])
        
        flow_duration = random.randint(*config['duration_range'])
        total_packets = random.randint(*config['packets_range'])
        fwd_packets = int(total_packets * random.uniform(0.6, 0.9))
        bwd_packets = total_packets - fwd_packets
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        self.flow_id_counter += 1
        
        return {
            'flow_id': self.flow_id_counter,
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'source_port': source_port,
            'dest_port': dest_port,
            'flow_duration': flow_duration,
            'total_fwd_packets': fwd_packets,
            'total_bwd_packets': bwd_packets,
            'flow_packets': total_packets,
            'actual_label': attack_type,
            'predicted_label': attack_type,  # Perfect detection for demo
            'is_attack': 1,
            'is_correct': 1,
            'timestamp': timestamp
        }
    
    def insert_attack_to_neo4j(self, attack):
        """Insert attack into Neo4j"""
        
        with self.driver.session() as session:
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
            RETURN flow.flow_id as flow_id
            """
            
            result = session.run(query, **attack)
            return result.single()['flow_id']
    
    def run_simulation(self, num_attacks=50, delay=2):
        """
        Run attack simulation
        
        Args:
            num_attacks: Number of attacks to generate
            delay: Delay between attacks (seconds)
        """
        
        print("=" * 70)
        print("🚨 ATTACK SIMULATION STARTED")
        print("=" * 70)
        print(f"\n⚙️  Configuration:")
        print(f"   • Number of attacks: {num_attacks}")
        print(f"   • Delay between attacks: {delay} seconds")
        print(f"   • Attack types: {', '.join(ATTACK_TYPES.keys())}")
        print(f"\n🎯 Starting simulation...\n")
        
        try:
            for i in range(num_attacks):
                # Generate attack
                attack = self.generate_attack()
                
                # Insert into Neo4j
                flow_id = self.insert_attack_to_neo4j(attack)
                
                # Display
                print(f"[{i+1}/{num_attacks}] 🚨 Attack Detected!")
                print(f"   Type: {attack['actual_label']}")
                print(f"   Source: {attack['source_ip']}:{attack['source_port']}")
                print(f"   Target: {attack['dest_ip']}:{attack['dest_port']}")
                print(f"   Packets: {attack['flow_packets']:,}")
                print(f"   Flow ID: {flow_id}")
                print(f"   Time: {attack['timestamp']}")
                print()
                
                # Wait before next attack
                if i < num_attacks - 1:
                    time.sleep(delay)
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Simulation interrupted by user")
        
        print("\n" + "=" * 70)
        print("✅ SIMULATION COMPLETED")
        print("=" * 70)
        print(f"\n📊 Total attacks simulated: {i + 1}")
        print(f"🌐 Check dashboard: http://localhost:5000")
        print(f"💡 Refresh the page to see new attacks!\n")

# ============================================
# Interactive Menu
# ============================================

def show_menu():
    """Display simulation menu"""
    
    print("\n" + "=" * 70)
    print("🎮 ATTACK SIMULATION MENU")
    print("=" * 70)
    print("\n1. Quick Simulation (10 attacks, 1 sec delay)")
    print("2. Standard Simulation (50 attacks, 2 sec delay)")
    print("3. Intense Simulation (100 attacks, 0.5 sec delay)")
    print("4. Custom Simulation")
    print("5. Continuous Simulation (until stopped)")
    print("6. Exit")
    print("\n" + "=" * 70)

def run_menu():
    """Run interactive menu"""
    
    simulator = AttackSimulator(driver)
    
    while True:
        show_menu()
        choice = input("\nChoose option (1-6): ").strip()
        
        if choice == '1':
            print("\n🚀 Quick Simulation...")
            simulator.run_simulation(num_attacks=10, delay=1)
        
        elif choice == '2':
            print("\n🚀 Standard Simulation...")
            simulator.run_simulation(num_attacks=50, delay=2)
        
        elif choice == '3':
            print("\n🚀 Intense Simulation...")
            simulator.run_simulation(num_attacks=100, delay=0.5)
        
        elif choice == '4':
            try:
                num = int(input("Number of attacks: "))
                delay = float(input("Delay between attacks (seconds): "))
                print(f"\n🚀 Custom Simulation ({num} attacks, {delay}s delay)...")
                simulator.run_simulation(num_attacks=num, delay=delay)
            except ValueError:
                print("❌ Invalid input!")
        
        elif choice == '5':
            print("\n🚀 Continuous Simulation (Press Ctrl+C to stop)...")
            simulator.run_simulation(num_attacks=999999, delay=1)
        
        elif choice == '6':
            print("\n👋 Exiting simulator...")
            break
        
        else:
            print("❌ Invalid choice!")
        
        input("\nPress Enter to continue...")

# ============================================
# Main Execution
# ============================================

if __name__ == "__main__":
    try:
        # Test Neo4j connection
        print("🔗 Testing Neo4j connection...")
        with driver.session() as session:
            session.run("RETURN 1")
        print("✅ Neo4j connected!\n")
        
        # Run menu
        run_menu()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("💡 Make sure Neo4j is running and credentials are correct!")
    
    finally:
        driver.close()
        print("✅ Simulator closed.")