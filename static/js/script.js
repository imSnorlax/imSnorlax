// ============================================
// Global Variables
// ============================================

const API_BASE = 'http://localhost:5000/api';
let attackTypesChart = null;
let topSourcesChart = null;

// ============================================
// Initialize Dashboard
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 IDS Dashboard Initialized');
    
    // Check connection
    checkConnection();
    
    // Load all data
    loadStats();
    loadAttacks();
    loadAttackTypes();
    loadTopSources();
    
    // Auto-refresh every 30 seconds
    setInterval(() => {
        loadStats();
        loadAttacks();
    }, 30000);
});

// ============================================
// Connection Check
// ============================================

async function checkConnection() {
    const statusElement = document.getElementById('connectionStatus');
    
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        
        if (data.status === 'healthy') {
            statusElement.innerHTML = '<i class="fas fa-circle"></i> Connected';
            statusElement.classList.add('connected');
            statusElement.classList.remove('error');
        } else {
            throw new Error('Unhealthy');
        }
    } catch (error) {
        statusElement.innerHTML = '<i class="fas fa-circle"></i> Connection Error';
        statusElement.classList.add('error');
        statusElement.classList.remove('connected');
        console.error('Connection error:', error);
    }
}

// ============================================
// Load Statistics
// ============================================

async function loadStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const data = await response.json();
        
        // Update stats cards with animation
        updateStatValue('totalFlows', data.total_flows);
        updateStatValue('totalAttacks', data.total_attacks);
        updateStatValue('benignFlows', data.benign_flows);
        updateStatValue('accuracy', data.accuracy + '%');
        
        console.log('✅ Stats loaded:', data);
    } catch (error) {
        console.error('❌ Error loading stats:', error);
    }
}

function updateStatValue(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        // Animate number change
        const currentValue = element.textContent;
        element.style.transform = 'scale(1.1)';
        element.textContent = formatNumber(value);
        setTimeout(() => {
            element.style.transform = 'scale(1)';
        }, 200);
    }
}

function formatNumber(num) {
    if (typeof num === 'string') return num;
    return num.toLocaleString();
}

// ============================================
// Load Attacks Table
// ============================================

async function loadAttacks() {
    const tbody = document.getElementById('attacksTableBody');
    
    try {
        const response = await fetch(`${API_BASE}/attacks`);
        const attacks = await response.json();
        
        if (attacks.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="loading">No attacks detected</td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = attacks.map(attack => `
            <tr>
                <td>${attack.flow_id}</td>
                <td><code>${attack.source_ip}</code></td>
                <td><code>${attack.dest_ip}</code></td>
                <td>${attack.source_port} → ${attack.dest_port}</td>
                <td><span class="badge danger">${attack.attack_type}</span></td>
                <td>${attack.predicted}</td>
                <td>${formatNumber(attack.packets)}</td>
                <td>
                    ${attack.is_correct 
                        ? '<span class="badge success"><i class="fas fa-check"></i> Correct</span>' 
                        : '<span class="badge warning"><i class="fas fa-exclamation"></i> Incorrect</span>'}
                </td>
                <td>${formatTimestamp(attack.timestamp)}</td>
            </tr>
        `).join('');
        
        console.log(`✅ Loaded ${attacks.length} attacks`);
    } catch (error) {
        console.error('❌ Error loading attacks:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="loading" style="color: var(--danger-color);">
                    <i class="fas fa-exclamation-triangle"></i> Error loading attacks
                </td>
            </tr>
        `;
    }
}

function formatTimestamp(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// ============================================
// Load Attack Types Chart
// ============================================

async function loadAttackTypes() {
    try {
        const response = await fetch(`${API_BASE}/attack-types`);
        const types = await response.json();
        
        const ctx = document.getElementById('attackTypesChart').getContext('2d');
        
        // Destroy existing chart
        if (attackTypesChart) {
            attackTypesChart.destroy();
        }
        
        const labels = types.map(t => t.type);
        const data = types.map(t => t.count);
        const colors = generateColors(types.length);
        
        attackTypesChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderColor: '#1e293b',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#f1f5f9',
                            padding: 15,
                            font: { size: 12 }
                        }
                    },
                    tooltip: {
                        backgroundColor: '#0f172a',
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        borderColor: '#2563eb',
                        borderWidth: 1,
                        padding: 12,
                        displayColors: true
                    }
                }
            }
        });
        
        console.log('✅ Attack types chart loaded');
    } catch (error) {
        console.error('❌ Error loading attack types:', error);
    }
}

// ============================================
// Load Top Sources Chart
// ============================================

async function loadTopSources() {
    try {
        const response = await fetch(`${API_BASE}/top-sources`);
        const sources = await response.json();
        
        const ctx = document.getElementById('topSourcesChart').getContext('2d');
        
        // Destroy existing chart
        if (topSourcesChart) {
            topSourcesChart.destroy();
        }
        
        const labels = sources.map(s => s.ip);
        const data = sources.map(s => s.count);
        
        topSourcesChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attack Count',
                    data: data,
                    backgroundColor: 'rgba(239, 68, 68, 0.8)',
                    borderColor: '#ef4444',
                    borderWidth: 2,
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: '#0f172a',
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        borderColor: '#2563eb',
                        borderWidth: 1,
                        padding: 12
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8', font: { size: 11 } },
                        grid: { color: '#334155', display: false }
                    },
                    y: {
                        ticks: { color: '#94a3b8', font: { size: 11 } },
                        grid: { color: '#334155' },
                        beginAtZero: true
                    }
                }
            }
        });
        
        console.log('✅ Top sources chart loaded');
    } catch (error) {
        console.error('❌ Error loading top sources:', error);
    }
}

// ============================================
// Utility Functions
// ============================================

function generateColors(count) {
    const colors = [
        'rgba(239, 68, 68, 0.8)',   // Red
        'rgba(245, 158, 11, 0.8)',  // Orange
        'rgba(234, 179, 8, 0.8)',   // Yellow
        'rgba(16, 185, 129, 0.8)',  // Green
        'rgba(59, 130, 246, 0.8)',  // Blue
        'rgba(168, 85, 247, 0.8)',  // Purple
        'rgba(236, 72, 153, 0.8)',  // Pink
        'rgba(20, 184, 166, 0.8)'   // Teal
    ];
    
    return colors.slice(0, count);
}

// ============================================
// Export Functions for HTML
// ============================================

window.loadStats = loadStats;
window.loadAttacks = loadAttacks;
window.loadAttackTypes = loadAttackTypes;
window.loadTopSources = loadTopSources;

console.log('✅ Dashboard JavaScript loaded successfully');v