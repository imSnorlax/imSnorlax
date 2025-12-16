from flask import Flask, render_template, jsonify
from flask_cors import CORS
from neo4j import GraphDatabase
import os

app = Flask(__name__)
CORS(app)

# ============================================
# Configuration Neo4j
# ============================================
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ids12345"  

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def get_db():
    return driver

# ============================================
# Routes API
# ============================================

@app.route('/')
def index():
    """Page principale du dashboard"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Statistiques globales"""
    with get_db().session() as session:
        result = session.run("""
            MATCH (flow:NetworkFlow)
            RETURN 
                count(*) as total_flows,
                sum(CASE WHEN flow.is_attack = 1 THEN 1 ELSE 0 END) as total_attacks,
                sum(CASE WHEN flow.is_attack = 0 THEN 1 ELSE 0 END) as benign_flows,
                sum(flow.is_correct) as correct_predictions,
                count(*) - sum(flow.is_correct) as incorrect_predictions
        """)
        
        record = result.single()
        
        total = record['total_flows']
        attacks = record['total_attacks']
        benign = record['benign_flows']
        correct = record['correct_predictions']
        incorrect = record['incorrect_predictions']
        
        accuracy = (correct / total * 100) if total > 0 else 0
        
        return jsonify({
            'total_flows': total,
            'total_attacks': attacks,
            'benign_flows': benign,
            'accuracy': round(accuracy, 2),
            'correct_predictions': correct,
            'incorrect_predictions': incorrect
        })

@app.route('/api/attacks')
def get_attacks():
    """Liste des attaques détectées"""
    with get_db().session() as session:
        result = session.run("""
            MATCH (source:IP)-[:CONNECTS_TO]->(flow:NetworkFlow)-[:TARGETS]->(dest:IP)
            WHERE flow.is_attack = 1
            RETURN 
                flow.flow_id as flow_id,
                source.address as source_ip,
                dest.address as dest_ip,
                flow.source_port as source_port,
                flow.dest_port as dest_port,
                flow.actual_label as attack_type,
                flow.predicted_label as predicted,
                flow.is_correct as is_correct,
                flow.timestamp as timestamp,
                flow.flow_packets as packets
            ORDER BY flow.flow_id DESC
            LIMIT 100
        """)
        
        attacks = []
        for record in result:
            attacks.append({
                'flow_id': record['flow_id'],
                'source_ip': record['source_ip'],
                'dest_ip': record['dest_ip'],
                'source_port': record['source_port'],
                'dest_port': record['dest_port'],
                'attack_type': record['attack_type'],
                'predicted': record['predicted'],
                'is_correct': bool(record['is_correct']),
                'timestamp': record['timestamp'],
                'packets': record['packets']
            })
        
        return jsonify(attacks)

@app.route('/api/attack-types')
def get_attack_types():
    """Distribution des types d'attaques"""
    with get_db().session() as session:
        result = session.run("""
            MATCH (flow:NetworkFlow)
            WHERE flow.is_attack = 1
            RETURN 
                flow.actual_label as attack_type,
                count(*) as count
            ORDER BY count DESC
        """)
        
        types = []
        for record in result:
            types.append({
                'type': record['attack_type'],
                'count': record['count']
            })
        
        return jsonify(types)

@app.route('/api/top-sources')
def get_top_sources():
    """Top IPs sources d'attaques"""
    with get_db().session() as session:
        result = session.run("""
            MATCH (source:IP)-[:CONNECTS_TO]->(flow:NetworkFlow)
            WHERE flow.is_attack = 1
            RETURN 
                source.address as ip,
                count(flow) as attack_count
            ORDER BY attack_count DESC
            LIMIT 10
        """)
        
        sources = []
        for record in result:
            sources.append({
                'ip': record['ip'],
                'count': record['attack_count']
            })
        
        return jsonify(sources)

@app.route('/api/top-targets')
def get_top_targets():
    """Top IPs ciblées par attaques"""
    with get_db().session() as session:
        result = session.run("""
            MATCH (flow:NetworkFlow)-[:TARGETS]->(dest:IP)
            WHERE flow.is_attack = 1
            RETURN 
                dest.address as ip,
                count(flow) as attack_count
            ORDER BY attack_count DESC
            LIMIT 10
        """)
        
        targets = []
        for record in result:
            targets.append({
                'ip': record['ip'],
                'count': record['attack_count']
            })
        
        return jsonify(targets)

@app.route('/api/timeline')
def get_timeline():
    """Timeline des attaques"""
    with get_db().session() as session:
        result = session.run("""
            MATCH (flow:NetworkFlow)
            WHERE flow.is_attack = 1
            RETURN 
                flow.timestamp as timestamp,
                count(*) as count
            ORDER BY timestamp
            LIMIT 100
        """)
        
        timeline = []
        for record in result:
            timeline.append({
                'timestamp': record['timestamp'],
                'count': record['count']
            })
        
        return jsonify(timeline)

@app.route('/api/health')
def health_check():
    """Vérifier connexion Neo4j"""
    try:
        with get_db().session() as session:
            result = session.run("RETURN 1 as test")
            result.single()
        return jsonify({'status': 'healthy', 'neo4j': 'connected'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================
# Lancer l'application
# ============================================

if __name__ == '__main__':
    print("=" * 70)
    print("🚀 INTRUSION DETECTION SYSTEM - DASHBOARD")
    print("=" * 70)
    print(f"\n🌐 Dashboard accessible sur: http://localhost:5000")
    print(f"🗄️  Neo4j URI: {NEO4J_URI}")
    print(f"\n✅ Serveur démarré! Appuie Ctrl+C pour arrêter.\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)