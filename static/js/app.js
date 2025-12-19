// Exposure One - Frontend Application Logic

let currentScanData = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
});

function setupEventListeners() {
    // Scan form
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScan);
    }
    
    // View switcher buttons
    const executiveBtn = document.getElementById('executiveBtn');
    const technicalBtn = document.getElementById('technicalBtn');
    
    if (executiveBtn) {
        executiveBtn.addEventListener('click', () => switchView('executive'));
    }
    
    if (technicalBtn) {
        technicalBtn.addEventListener('click', () => switchView('technical'));
    }
}

async function handleScan(e) {
    e.preventDefault();
    
    const target = document.getElementById('target').value.trim();
    if (!target) {
        alert('Per favore inserisci un dominio o IP');
        return;
    }
    
    // Show loading
    showLoading(true);
    hideResults();
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target })
        });
        
        if (!response.ok) {
            throw new Error(`Errore HTTP: ${response.status}`);
        }
        
        const data = await response.json();
        currentScanData = data;
        
        // Hide loading and show results
        showLoading(false);
        displayResults(data);
        
    } catch (error) {
        showLoading(false);
        alert(`Errore durante la scansione: ${error.message}`);
        console.error('Scan error:', error);
    }
}

function showLoading(show) {
    const loading = document.getElementById('loading');
    if (loading) {
        loading.classList.toggle('active', show);
    }
}

function hideResults() {
    const results = document.getElementById('results');
    if (results) {
        results.classList.remove('active');
    }
}

function displayResults(data) {
    const results = document.getElementById('results');
    if (!results) return;
    
    // Show results container
    results.classList.add('active');
    
    // Display both views
    displayExecutiveView(data);
    displayTechnicalView(data);
    
    // Default to executive view
    switchView('executive');
    
    // Scroll to results
    results.scrollIntoView({ behavior: 'smooth' });
}

function displayExecutiveView(data) {
    const view = document.getElementById('executiveView');
    if (!view) return;
    
    const { risk_score, executive_view } = data;
    
    // Risk score card
    const scoreColor = getRiskColor(risk_score.risk_level);
    const scoreHTML = `
        <div class="risk-score-card">
            <h2>Exposure Score</h2>
            <div class="score-display" style="color: ${scoreColor}">
                ${risk_score.total_score}
            </div>
            <span class="risk-badge risk-${risk_score.risk_level}">
                ${risk_score.risk_level.toUpperCase()} EXPOSURE
            </span>
            <p style="margin-top: 1rem; color: var(--color-text-dim);">
                Target: <strong>${data.target}</strong>
            </p>
        </div>
    `;
    
    // Top risks
    const topRisksHTML = `
        <div class="info-card">
            <h3>🔴 Top 3 Rischi</h3>
            <ul>
                ${executive_view.top_risks.map(risk => `<li>${risk}</li>`).join('')}
            </ul>
        </div>
    `;
    
    // Recommendations
    const recommendationsHTML = `
        <div class="info-card">
            <h3>✅ Raccomandazioni Prioritarie</h3>
            <ul>
                ${executive_view.recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
        </div>
    `;
    
    // Category breakdown
    const categoryHTML = `
        <div class="info-card">
            <h3>📊 Breakdown per Categoria</h3>
            <ul>
                ${Object.entries(risk_score.category_scores)
                    .sort((a, b) => b[1] - a[1])
                    .map(([cat, score]) => `
                        <li>
                            <strong>${cat}:</strong> 
                            <span style="color: ${getScoreColor(score)}">${score}/100</span>
                        </li>
                    `).join('')}
            </ul>
        </div>
    `;
    
    view.innerHTML = `
        ${scoreHTML}
        <div class="info-grid">
            ${topRisksHTML}
            ${recommendationsHTML}
            ${categoryHTML}
        </div>
    `;
}

function displayTechnicalView(data) {
    const view = document.getElementById('technicalView');
    if (!view) return;
    
    const { technical_view, scan_duration } = data;
    
    // Stats grid
    const statsHTML = `
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">${technical_view.total_findings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--color-critical)">
                    ${technical_view.findings_by_severity.critical}
                </div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--color-high)">
                    ${technical_view.findings_by_severity.high}
                </div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--color-moderate)">
                    ${technical_view.findings_by_severity.moderate}
                </div>
                <div class="stat-label">Moderate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--color-low)">
                    ${technical_view.findings_by_severity.low}
                </div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${scan_duration}s</div>
                <div class="stat-label">Scan Duration</div>
            </div>
        </div>
    `;
    
    // Modules results
    const modulesHTML = technical_view.modules_results.map(module => {
        const findingsHTML = module.findings.length > 0 
            ? module.findings.map(f => createFindingHTML(f)).join('')
            : '<p style="color: var(--color-text-dim);">✓ Nessun finding rilevato</p>';
        
        return `
            <div class="module-section">
                <div class="module-header">
                    <h3 class="module-title">${module.module_name}</h3>
                    <span class="module-status status-${module.status}">
                        ${module.status}
                    </span>
                </div>
                <p style="color: var(--color-text-dim); margin-bottom: 1rem;">
                    Execution time: ${module.execution_time}s
                </p>
                ${findingsHTML}
            </div>
        `;
    }).join('');
    
    view.innerHTML = statsHTML + modulesHTML;
}

function createFindingHTML(finding) {
    return `
        <div class="finding-item ${finding.severity}">
            <div class="finding-header">
                <div class="finding-title">${finding.title}</div>
                <span class="severity-badge severity-${finding.severity}">
                    ${finding.severity}
                </span>
            </div>
            <div class="finding-description">${finding.description}</div>
            ${finding.evidence ? `
                <div class="finding-evidence">
                    <strong>Evidence:</strong> ${finding.evidence}
                </div>
            ` : ''}
            ${finding.impact ? `
                <div style="margin-top: 0.75rem; color: var(--color-text-dim);">
                    <strong>Impact:</strong> ${finding.impact}
                </div>
            ` : ''}
            ${finding.recommendation ? `
                <div class="finding-recommendation">
                    <strong>💡 Recommendation:</strong> ${finding.recommendation}
                </div>
            ` : ''}
        </div>
    `;
}

function switchView(viewName) {
    // Update buttons
    const executiveBtn = document.getElementById('executiveBtn');
    const technicalBtn = document.getElementById('technicalBtn');
    
    executiveBtn.classList.toggle('active', viewName === 'executive');
    technicalBtn.classList.toggle('active', viewName === 'technical');
    
    // Update views
    const executiveView = document.getElementById('executiveView');
    const technicalView = document.getElementById('technicalView');
    
    executiveView.classList.toggle('active', viewName === 'executive');
    technicalView.classList.toggle('active', viewName === 'technical');
}

function getRiskColor(riskLevel) {
    const colors = {
        'low': 'var(--color-low)',
        'moderate': 'var(--color-moderate)',
        'high': 'var(--color-high)',
        'critical': 'var(--color-critical)'
    };
    return colors[riskLevel] || 'var(--color-text)';
}

function getScoreColor(score) {
    if (score >= 76) return 'var(--color-critical)';
    if (score >= 51) return 'var(--color-high)';
    if (score >= 26) return 'var(--color-moderate)';
    return 'var(--color-low)';
}
