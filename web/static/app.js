const API_BASE = 'http://localhost:5000/api';
let currentFilter = 'all';
let refreshInterval;

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadScans();
    startAutoRefresh();
    
    // Profile change handler
    document.getElementById('scanProfile').addEventListener('change', (e) => {
        const customGroup = document.getElementById('customModulesGroup');
        customGroup.style.display = e.target.value === 'custom' ? 'block' : 'none';
    });
});

function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        loadStats();
        loadScans();
    }, 3000); // Refresh every 3 seconds
}

// API calls
async function loadStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const data = await response.json();
        
        // Update header status
        const statusText = data.in_progress > 0 
            ? `${data.in_progress} ${t('scan')}${data.in_progress !== 1 ? 's' : ''} ${t('inProgress')}`
            : data.latest_scan_id 
                ? t('showingLatest')
                : t('noScansYet');
        
        document.getElementById('scanStatusText').textContent = statusText;
        
        // Update severity counts from latest scan
        document.getElementById('criticalCount').textContent = data.severity_totals.critical || 0;
        document.getElementById('highCount').textContent = data.severity_totals.high || 0;
        document.getElementById('mediumCount').textContent = data.severity_totals.medium || 0;
        document.getElementById('lowCount').textContent = data.severity_totals.low || 0;
        document.getElementById('infoCount').textContent = data.severity_totals.info || 0;
        
        // Show indicator if displaying latest scan
        if (data.latest_scan_id) {
            const indicator = document.querySelector('.stats-indicator');
            if (!indicator) {
                const statsGrid = document.querySelector('.stats-grid');
                const div = document.createElement('div');
                div.className = 'stats-indicator';
                div.style.cssText = 'grid-column: 1 / -1; text-align: center; color: var(--text-secondary); font-size: 12px; margin-top: -8px;';
                div.textContent = `Показаны результаты последнего скана (ID: ${data.latest_scan_id})`;
                statsGrid.appendChild(div);
            }
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

async function loadScans() {
    try {
        const response = await fetch(`${API_BASE}/scans`);
        const scans = await response.json();
        
        // Sort by ID descending (newest first)
        scans.sort((a, b) => b.id - a.id);
        
        // Update recent scans (top 5)
        const recentScansEl = document.getElementById('recentScans');
        if (scans.length === 0) {
            recentScansEl.innerHTML = `<div class="empty-state">${t('noScansYetClickNew')}</div>`;
        } else {
            recentScansEl.innerHTML = scans.slice(0, 5).map(scan => renderScanItem(scan)).join('');
        }
        
        // Update all scans view
        const allScansEl = document.getElementById('allScans');
        if (scans.length === 0) {
            allScansEl.innerHTML = `<div class="empty-state">${t('noScansYet')}</div>`;
        } else {
            allScansEl.innerHTML = scans.map(scan => renderScanItem(scan)).join('');
        }
        
        // Update recent risks
        loadRecentRisks(scans);
        
        // Update all risks
        loadAllRisks(scans);
        
    } catch (error) {
        console.error('Failed to load scans:', error);
    }
}

function renderScanItem(scan) {
    const statusClass = scan.status === 'running' ? 'running' : 
                       scan.status === 'completed' ? 'completed' : 'error';
    const statusText = scan.status === 'running' ? t('running') :
                      scan.status === 'completed' ? t('completedStatus') : t('error');
    
    const timeText = scan.start_time ? 
        new Date(scan.start_time).toLocaleString('ru-RU', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        }) : '';
    
    const findingsText = scan.status === 'completed' ? 
        ` • ${scan.total_findings} finding${scan.total_findings !== 1 ? 's' : ''}` : '';
    
    // Show severity breakdown for completed scans
    let severityBadges = '';
    if (scan.status === 'completed' && scan.severity_counts) {
        const badges = [];
        if (scan.severity_counts.critical) badges.push(`<span class="mini-badge critical">${scan.severity_counts.critical}C</span>`);
        if (scan.severity_counts.high) badges.push(`<span class="mini-badge high">${scan.severity_counts.high}H</span>`);
        if (scan.severity_counts.medium) badges.push(`<span class="mini-badge medium">${scan.severity_counts.medium}M</span>`);
        if (scan.severity_counts.low) badges.push(`<span class="mini-badge low">${scan.severity_counts.low}L</span>`);
        if (scan.severity_counts.info) badges.push(`<span class="mini-badge info">${scan.severity_counts.info}I</span>`);
        if (badges.length > 0) {
            severityBadges = `<div class="severity-badges">${badges.join(' ')}</div>`;
        }
    }
    
    return `
        <div class="scan-item" onclick="showScanDetails(${scan.id})">
            <div class="scan-info">
                <div class="scan-url">${escapeHtml(scan.url)}</div>
                <div class="scan-meta">${scan.profile} • ${timeText}${findingsText}</div>
                ${severityBadges}
            </div>
            <span class="scan-badge ${statusClass}">${statusText}</span>
        </div>
    `;
}

function loadRecentRisks(scans) {
    // Show risks from latest completed scan only
    let latestScan = null;
    let latestTime = null;
    
    for (const scan of scans.filter(s => s.status === 'completed')) {
        if (scan.end_time && (!latestTime || scan.end_time > latestTime)) {
            latestTime = scan.end_time;
            latestScan = scan;
        }
    }
    
    const recentRisksEl = document.getElementById('recentRisks');
    if (!latestScan || latestScan.total_findings === 0) {
        recentRisksEl.innerHTML = `<div class="empty-state">${t('noRisksYet')}</div>`;
    } else {
        // Show summary of latest scan
        recentRisksEl.innerHTML = `
            <div class="risk-item info" onclick="showScanDetails(${latestScan.id})" style="cursor: pointer;">
                <div class="risk-content">
                    <div class="risk-title">${escapeHtml(latestScan.url)}</div>
                    <div class="risk-detail">${latestScan.total_findings} finding${latestScan.total_findings !== 1 ? 's' : ''} detected in latest scan</div>
                    <div class="severity-badges" style="margin-top: 8px;">
                        ${latestScan.severity_counts.critical ? `<span class="mini-badge critical">${latestScan.severity_counts.critical} Critical</span>` : ''}
                        ${latestScan.severity_counts.high ? `<span class="mini-badge high">${latestScan.severity_counts.high} High</span>` : ''}
                        ${latestScan.severity_counts.medium ? `<span class="mini-badge medium">${latestScan.severity_counts.medium} Medium</span>` : ''}
                        ${latestScan.severity_counts.low ? `<span class="mini-badge low">${latestScan.severity_counts.low} Low</span>` : ''}
                        ${latestScan.severity_counts.info ? `<span class="mini-badge info">${latestScan.severity_counts.info} Info</span>` : ''}
                    </div>
                </div>
            </div>
            <div style="text-align: center; margin-top: 12px;">
                <small style="color: var(--text-secondary); font-size: 11px;">
                    Кликните для просмотра всех находок этого скана
                </small>
            </div>
        `;
    }
}

async function loadAllRisks(scans) {
    const allRisks = [];
    
    for (const scan of scans.filter(s => s.status === 'completed')) {
        try {
            const response = await fetch(`${API_BASE}/scans/${scan.id}`);
            const data = await response.json();
            
            if (data.findings) {
                data.findings.forEach(finding => {
                    allRisks.push({
                        ...finding,
                        scan_url: scan.url,
                        scan_id: scan.id
                    });
                });
            }
        } catch (error) {
            console.error(`Failed to load scan ${scan.id}:`, error);
        }
    }
    
    const allRisksEl = document.getElementById('allRisks');
    if (allRisks.length === 0) {
        allRisksEl.innerHTML = `<div class="empty-state" data-i18n="noRisksYet">${t('noRisksYet')}</div>`;
    } else {
        renderFilteredRisks(allRisks);
    }
    
    // Store for filtering
    window.allRisksData = allRisks;
}

function renderFilteredRisks(risks) {
    const filtered = currentFilter === 'all' ? 
        risks : 
        risks.filter(r => r.severity === currentFilter);
    
    const allRisksEl = document.getElementById('allRisks');
    if (filtered.length === 0) {
        allRisksEl.innerHTML = `<div class="empty-state">${t('noRisksYet')}</div>`;
    } else {
        allRisksEl.innerHTML = filtered.map(risk => `
            <div class="risk-item ${risk.severity}">
                <span class="risk-severity ${risk.severity}">${risk.severity}</span>
                <div class="risk-content">
                    <div class="risk-title">${escapeHtml(risk.title)}</div>
                    <div class="risk-detail">${escapeHtml(risk.detail).substring(0, 150)}</div>
                    <div class="risk-detail" style="margin-top: 4px;">
                        <strong>Module:</strong> ${risk.module} • 
                        <strong>Target:</strong> ${escapeHtml(risk.scan_url)}
                    </div>
                </div>
            </div>
        `).join('');
    }
}

function filterRisks(severity) {
    currentFilter = severity;
    
    // Update active tab
    document.querySelectorAll('.filter-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Re-render
    if (window.allRisksData) {
        renderFilteredRisks(window.allRisksData);
    }
}

async function showScanDetails(scanId) {
    try {
        const response = await fetch(`${API_BASE}/scans/${scanId}`);
        const scan = await response.json();
        
        document.getElementById('detailsTitle').textContent = `Scan: ${scan.url}`;
        
        let content = `
            <div class="details-section">
                <h3>Scan Information</h3>
                <div style="color: var(--text-secondary); font-size: 14px;">
                    <p><strong>Profile:</strong> ${scan.profile}</p>
                    <p><strong>Status:</strong> ${scan.status}</p>
                    <p><strong>Started:</strong> ${scan.start_time ? new Date(scan.start_time).toLocaleString('ru-RU') : 'N/A'}</p>
                    ${scan.end_time ? `<p><strong>Completed:</strong> ${new Date(scan.end_time).toLocaleString('ru-RU')}</p>` : ''}
                    <p><strong>Total Findings:</strong> ${scan.total_findings || 0}</p>
                    <p><strong>Evasion:</strong> ${scan.evasion ? 'on' : 'off'}</p>
                    <p><strong>Modules Used:</strong> ${(scan.modules_used || []).join(', ')}</p>
                </div>
            </div>
        `;
        
        if (scan.findings && scan.findings.length > 0) {
            content += `
                <div class="details-section">
                    <h3>Findings (${scan.findings.length})</h3>
                    <div class="findings-grid">
                        ${scan.findings.map(f => `
                            <div class="risk-item ${f.severity}">
                                <span class="risk-severity ${f.severity}">${f.severity}</span>
                                <div class="risk-content">
                                    <div class="risk-title">${escapeHtml(f.title)}</div>
                                    <div class="risk-detail">${escapeHtml(f.detail)}</div>
                                    <div class="risk-detail" style="margin-top: 4px;">
                                        <strong>Module:</strong> ${f.module}
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        } else if (scan.status === 'running') {
            content += '<div class="empty-state">Scan is still running...</div>';
        } else {
            content += '<div class="empty-state">No findings detected.</div>';
        }
        
        document.getElementById('scanDetailsContent').innerHTML = content;
        document.getElementById('scanDetailsModal').classList.add('active');
        
    } catch (error) {
        console.error('Failed to load scan details:', error);
        alert('Failed to load scan details');
    }
}

function closeScanDetailsModal() {
    document.getElementById('scanDetailsModal').classList.remove('active');
}

// View switching
function showScansView() {
    document.getElementById('dashboardView').style.display = 'none';
    document.getElementById('scansView').style.display = 'block';
    document.getElementById('risksView').style.display = 'none';
    
    document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
    document.querySelectorAll('nav a')[1].classList.add('active');
    
    const headerTitle = document.getElementById('headerTitle');
    if (headerTitle) {
        headerTitle.textContent = t('scans');
    }
}

function showRisksView() {
    document.getElementById('dashboardView').style.display = 'none';
    document.getElementById('scansView').style.display = 'none';
    document.getElementById('risksView').style.display = 'block';
    
    document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
    document.querySelectorAll('nav a')[2].classList.add('active');
    
    const headerTitle = document.getElementById('headerTitle');
    if (headerTitle) {
        headerTitle.textContent = t('risks');
    }
}

function showDashboard() {
    document.getElementById('dashboardView').style.display = 'block';
    document.getElementById('scansView').style.display = 'none';
    document.getElementById('risksView').style.display = 'none';
    
    document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
    document.querySelectorAll('nav a')[0].classList.add('active');
    
    const headerTitle = document.getElementById('headerTitle');
    if (headerTitle) {
        headerTitle.textContent = t('dashboard');
    }
}

// New scan modal
function showNewScanModal() {
    document.getElementById('newScanModal').classList.add('active');
}

function closeNewScanModal() {
    document.getElementById('newScanModal').classList.remove('active');
    document.getElementById('newScanForm').reset();
}

async function submitNewScan(event) {
    event.preventDefault();
    
    const url = document.getElementById('scanUrl').value.trim();
    const profile = document.getElementById('scanProfile').value;
    const modules = document.getElementById('scanModules').value.trim();
    const maxRps = parseInt(document.getElementById('scanRps').value);
    const evasion = document.getElementById('scanEvasion') ? document.getElementById('scanEvasion').checked : false;
    
    if (!url) {
        alert('Please enter a target URL');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url,
                profile,
                modules,
                max_rps: maxRps,
                evasion
            })
        });
        
        if (response.ok) {
            closeNewScanModal();
            loadScans();
            alert('Scan started successfully!');
        } else {
            const error = await response.json();
            alert(`Failed to start scan: ${error.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Failed to start scan:', error);
        alert('Failed to start scan. Please check the console for details.');
    }
}

// Utility
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Make navigation work
document.querySelectorAll('nav a')[0].addEventListener('click', (e) => {
    e.preventDefault();
    showDashboard();
});
