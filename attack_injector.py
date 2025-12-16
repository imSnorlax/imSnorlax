"""
Manual Attack Injector - Direct to Neo4j
Bypasses sniffer - adds attacks directly to database
Perfect for testing dashboard!
"""

from neo4j import GraphDatabase
from datetime import datetime
import random
import time

# ============================================
# Configuration
# ============================================

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ids12345"  # ⚠️ Change!

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# ============================================
# Attack Injector
# ============================================

class ManualAttackInjector:
    
    def __init__(self):
        self.flow_id = 200000
    
    def inject_attack(self, attack_type="DDoS"):
        """Inject a single attack into Neo4j"""
        
        self.flow_id += 1
        
        # Generate attack data
        attack = {
            'flow_id': self.flow_id,
            'source_ip': f"192.168.{random.randint(1,10)}.{random.randint(1,255)}",
            'dest_ip': f"10.0.0.{random.randint(1,10)}",
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([80, 443, 22, 3389, 8080]),
            'flow_duration': random.randint(100, 5000),
            'total_fwd_packets': random.randint(1000, 50000),
            'total_bwd_packets': random.randint(100, 5000),
            'flow_packets': random.randint(1100, 55000),
            'actual_label': attack_type,
            'predicted_label': attack_type,
            'is_attack': 1,
            'is_correct': 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Insert to Neo4j
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
            RETURN flow.flow_id as flow_id
            """
            result = session.run(query, **attack)
            flow_id = result.single()['flow_id']
        
        return attack, flow_id
    
    def inject_multiple(self, count=10, attack_type="DDoS", delay=1):
        """Inject multiple attacks"""
        
        print("="*70)
        print(f"💉 INJECTING {count} {attack_type} ATTACKS")
        print("="*70)
        print(f"Target: Neo4j Database")
        print(f"Delay: {delay} seconds between attacks\n")
        
        for i in range(count):
            attack, flow_id = self.inject_attack(attack_type)
            
            print(f"[{i+1}/{count}] ✅ Attack Injected!")
            print(f"   Flow ID: {flow_id}")
            print(f"   Type: {attack['actual_label']}")
            print(f"   Source: {attack['source_ip']}:{attack['source_port']}")
            print(f"   Target: {attack['dest_ip']}:{attack['dest_port']}")
            print(f"   Packets: {attack['flow_packets']:,}")
            print(f"   Time: {attack['timestamp']}")
            print()
            
            if i < count - 1:
                time.sleep(delay)
        
        print("="*70)
        print(f"✅ INJECTION COMPLETE!")
        print("="*70)
        print(f"\n💡 Refresh dashboard: http://localhost:5000")
        print(f"📊 Total attacks injected: {count}\n")

# ============================================
# Menu
# ============================================

def show_menu():
    print("\n" + "="*70)
    print("💉 MANUAL ATTACK INJECTOR")
    print("="*70)
    print("\n1. Inject 1 DDoS Attack (test)")
    print("2. Inject 10 DDoS Attacks")
    print("3. Inject 5 PortScan Attacks")
    print("4. Inject 5 HTTPFlood Attacks")
    print("5. Inject Mixed Attacks (20 total)")
    print("6. Custom Injection")
    print("7. Exit")
    print("\n" + "="*70)

def main():
    print("\n" + "="*70)
    print("💉 MANUAL ATTACK INJECTOR FOR TESTING")
    print("="*70)
    print("\nThis tool injects attacks DIRECTLY into Neo4j")
    print("Perfect for testing dashboard without network traffic!\n")
    
    # Test connection
    try:
        with driver.session() as session:
            session.run("RETURN 1")
        print("✅ Neo4j Connected!\n")
    except Exception as e:
        print(f"❌ Neo4j Connection Failed: {e}")
        return
    
    injector = ManualAttackInjector()
    
    while True:
        show_menu()
        choice = input("\nSelect option (1-7): ").strip()
        
        if choice == '1':
            print("\n💉 Injecting 1 test attack...")
            attack, flow_id = injector.inject_attack("DDoS")
            print(f"✅ Attack {flow_id} injected!")
            print(f"   Type: {attack['actual_label']}")
            print(f"   Source: {attack['source_ip']}")
            print(f"   Target: {attack['dest_ip']}")
            print(f"\n💡 Refresh dashboard to see it!")
        
        elif choice == '2':
            injector.inject_multiple(count=10, attack_type="DDoS", delay=0.5)
        
        elif choice == '3':
            injector.inject_multiple(count=5, attack_type="PortScan", delay=1)
        
        elif choice == '4':
            injector.inject_multiple(count=5, attack_type="HTTPFlood", delay=1)
        
        elif choice == '5':
            print("\n💉 Injecting mixed attacks...")
            types = ["DDoS", "PortScan", "HTTPFlood", "BruteForce"]
            for i in range(20):
                attack_type = random.choice(types)
                attack, flow_id = injector.inject_attack(attack_type)
                print(f"[{i+1}/20] ✅ {attack_type} attack {flow_id} injected")
                time.sleep(0.3)
            print("\n✅ 20 mixed attacks injected!")
        
        elif choice == '6':
            try:
                attack_type = input("Attack type (DDoS/PortScan/HTTPFlood/BruteForce): ").strip()
                count = int(input("Number of attacks: "))
                delay = float(input("Delay between attacks (seconds): "))
                injector.inject_multiple(count=count, attack_type=attack_type, delay=delay)
            except ValueError:
                print("❌ Invalid input!")
        
        elif choice == '7':
            print("\n👋 Exiting...")
            break
        
        else:
            print("❌ Invalid option!")
        
        input("\nPress Enter to continue...")
    
    driver.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()