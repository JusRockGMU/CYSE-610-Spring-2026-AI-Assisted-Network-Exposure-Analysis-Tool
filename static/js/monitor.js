// Get scan ID from backend, URL parameter, or localStorage
const urlParams = new URLSearchParams(window.location.search);
let scanId = window.INITIAL_SCAN_ID || urlParams.get('scan_id') || localStorage.getItem('activeScanId');

if (!scanId) {
    // No active scan
    document.getElementById('noActiveScan').style.display = 'block';
    document.getElementById('progressSection').style.display = 'none';
} else {
    // Show scan ID
    document.getElementById('displayScanId').textContent = scanId;
    
    // Show progress section
    document.getElementById('progressSection').style.display = 'block';
    document.getElementById('noActiveScan').style.display = 'none';
    
    // Initialize monitoring
    initializeMonitoring(scanId);
}

function initializeMonitoring(scanId) {
    let progressInterval = null;
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const statusBadge = document.getElementById('statusBadge');
    const timerText = document.getElementById('timerText');
    const stepTimes = document.getElementById('stepTimes');
    const activityLogBtn = document.getElementById('activityLogBtn');
    const activityLogFlyout = document.getElementById('activityLogFlyout');
    const closeActivityLog = document.getElementById('closeActivityLog');
    const activityLogContent = document.getElementById('activityLogContent');
    const activityCount = document.getElementById('activityCount');
    const cancelScanBtn = document.getElementById('cancelScanBtn');
    
    let activityHistory = [];
    let lastStep = '';
    
    // Initialize pipeline roadmap
    const pipelineSteps = document.getElementById('pipelineSteps');
    const fileCounter = document.getElementById('fileCounter');
    
    const pipeline = [
        { id: 'upload', icon: '📤', title: 'Upload Files', description: 'Receiving scan files' },
        { id: 'parse', icon: '📋', title: 'Parse Scan Data', description: 'Extracting host and service information' },
        { id: 'process', icon: '⚙️', title: 'Process Data', description: 'Normalizing and structuring data' },
        { id: 'ai-enhance', icon: '🤖', title: 'AI Enhancement', description: 'Validating CPE and generating keywords', aiStep: true },
        { id: 'nvd-query', icon: '🔍', title: 'Query NVD Database', description: 'Searching for CVEs' },
        { id: 'ai-filter', icon: '🎯', title: 'AI Filtering', description: 'Removing false positives', aiStep: true },
        { id: 'generate', icon: '📊', title: 'Generate Report', description: 'Creating vulnerability report' },
        { id: 'complete', icon: '✅', title: 'Complete', description: 'Analysis finished' }
    ];
    
    function initializePipeline() {
        pipelineSteps.innerHTML = pipeline.map(step => `
            <div class="pipeline-step pending" id="step-${step.id}">
                <div class="step-icon">${step.icon}</div>
                <div class="step-content">
                    <div class="step-title">${step.title}</div>
                    <div class="step-description">${step.description}</div>
                </div>
                <div class="step-status">
                    <span class="step-time" id="time-${step.id}">--</span>
                    <div class="step-check">○</div>
                </div>
            </div>
        `).join('');
    }
    
    function updatePipelineStep(stepId, state, time) {
        const stepEl = document.getElementById(`step-${stepId}`);
        const timeEl = document.getElementById(`time-${stepId}`);
        const checkEl = stepEl?.querySelector('.step-check');
        
        if (!stepEl) return;
        
        // Check if state actually changed to avoid restarting animations
        const currentState = stepEl.classList.contains('completed') ? 'completed' :
                           stepEl.classList.contains('ai-active') ? 'ai-active' :
                           stepEl.classList.contains('active') ? 'active' : 'pending';
        
        // Only update classes if state changed
        if (currentState !== state) {
            // console.log(`🔄 Pipeline step ${stepId}: ${currentState} → ${state}`);
            // Remove all state classes
            stepEl.classList.remove('pending', 'active', 'completed', 'ai-active');
            
            // Add new state
            stepEl.classList.add(state);
            
            // Update check mark
            if (state === 'completed') {
                checkEl.textContent = '✓';
            } else if (state === 'active' || state === 'ai-active') {
                checkEl.textContent = '⟳';
            }
        } else {
            // console.log(`⏭️ Pipeline step ${stepId}: no change (${state})`);
        }
        
        // Always update time (doesn't affect animation)
        if (time && timeEl) {
            timeEl.textContent = time + 's';
        }
    }
    
    function matchStepToProgress(progressStep, status) {
        const stepLower = progressStep.toLowerCase();
        
        if (stepLower.includes('upload')) return 'upload';
        else if (stepLower.includes('pars')) return 'parse';
        else if (stepLower.includes('process')) return 'process';
        else if (stepLower.includes('ai enhancing') || stepLower.includes('ai enhancement') || status === 'AI Processing') return 'ai-enhance';
        else if (stepLower.includes('nvd') || stepLower.includes('querying') || stepLower.includes('fetching cve') || status === 'NVD Query') return 'nvd-query';
        else if (stepLower.includes('ai filter') || status === 'AI Filtering') return 'ai-filter';
        else if (stepLower.includes('generat')) return 'generate';
        else if (stepLower.includes('complete') || status === 'Complete') return 'complete';
        else if (stepLower.includes('analyz')) return 'nvd-query';
        
        return null;
    }
    
    // Initialize pipeline
    initializePipeline();
    
    // Activity log button click handler
    activityLogBtn.addEventListener('click', () => {
        activityLogFlyout.classList.toggle('open');
    });
    
    closeActivityLog.addEventListener('click', () => {
        activityLogFlyout.classList.remove('open');
    });
    
    cancelScanBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to stop this scan?')) return;
        
        try {
            const response = await fetch(`/api/scans/${scanId}/cancel`, { method: 'POST' });
            if (response.ok) {
                stopLiveTimer();
                clearInterval(progressInterval);
                localStorage.removeItem('activeScanId');
                sessionStorage.removeItem(stateKey);
                alert('Scan cancelled successfully');
                window.location.href = '/';
            } else {
                alert('Failed to cancel scan');
            }
        } catch (error) {
            console.error('Cancel error:', error);
            alert('Failed to cancel scan');
        }
    });
    
    // Close on outside click
    activityLogFlyout.addEventListener('click', (e) => {
        if (e.target === activityLogFlyout) {
            activityLogFlyout.classList.remove('open');
        }
    });
    
    function updateActivityLog() {
        if (activityHistory.length === 0) {
            activityLogContent.innerHTML = '<p style="color: #95a5a6; text-align: center; padding: 20px;">No activity yet...</p>';
            return;
        }
        
        let html = '';
        
        // Add pass metrics summary at top if we have multi-pass data
        if (passMetrics.length > 0) {
            html += '<div class="pass-metrics-summary">';
            html += '<h4 style="margin: 0 0 1rem 0; color: #2c3e50; font-size: 0.9rem;">📊 Multi-Pass Analysis Summary</h4>';
            passMetrics.forEach((metric, idx) => {
                html += `
                    <div class="pass-metric-item">
                        <div class="pass-metric-header">
                            <span class="pass-badge">PASS ${metric.pass}</span>
                            <span class="pass-port">Port ${metric.port || 'Unknown'}</span>
                        </div>
                        <div class="pass-metric-details">
                            <span>🎯 ${metric.cves_found || 0} CVEs found</span>
                            <span>⏱ ${metric.duration}s</span>
                        </div>
                    </div>
                `;
            });
            html += '</div><div style="border-top: 2px solid #e9ecef; margin: 1rem 0;"></div>';
        }
        
        // Add activity history
        html += activityHistory.map((activity) => {
            let statusClass = activity.status.toLowerCase().replace(/ /g, '-');
            
            // Special handling: if step mentions "NVD returned", treat as NVD query
            if (activity.step.includes('NVD returned') || activity.step.includes('Querying NVD')) {
                statusClass = 'nvd-query';
            }
            
            const statusColors = {
                'ai-processing': '#3498db',
                'nvd-query': '#f39c12',
                'ai-filtering': '#16a085',
                'analyzing': '#8e44ad',
                'complete': '#27ae60',
                'processing': '#95a5a6'
            };
            const color = statusColors[statusClass] || '#95a5a6';
            
            return `
                <div class="activity-item ${statusClass}">
                    <div class="activity-timestamp">${activity.timestamp}</div>
                    <div class="activity-step">${activity.step}</div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="activity-status" style="background: ${color}20; color: ${color};">
                            ${activity.status}
                        </span>
                        <span class="activity-duration">⏱ ${activity.duration}s</span>
                    </div>
                </div>
            `;
        }).reverse().join('');
        
        activityLogContent.innerHTML = html;
    }
    
    let currentPipelineStep = null;
    let completedSteps = new Set();
    let stepStartTime = null;
    let liveTimerInterval = null;
    let stepPassCounts = {};
    let passHistory = [];
    let passMetrics = [];
    
    // Live port analysis state
    let totalFound = 0;
    let totalFiltered = 0;
    let totalFinal = 0;
    let discoveredPorts = [];
    let portAnalysis = {};
    let portCollapseState = {}; // Track which ports are expanded/collapsed
    let lastPortDataHash = ''; // Track if port data actually changed
    let updateTimeout = null; // Debounce timer for updates
    let isDeepAnalysis = false; // Track if multi-pass analysis is enabled
    
    // Try to restore state from sessionStorage
    const stateKey = `monitor_state_${scanId}`;
    const savedState = sessionStorage.getItem(stateKey);
    if (savedState) {
        try {
            const state = JSON.parse(savedState);
            portAnalysis = state.portAnalysis || {};
            discoveredPorts = state.discoveredPorts || [];
            totalFound = state.totalFound || 0;
            totalFiltered = state.totalFiltered || 0;
            totalFinal = state.totalFinal || 0;
            savedStepStartTime = state.stepStartTime || null;
            savedCurrentStep = state.currentStep || null;
            
            // Show panel if we have ports
            if (discoveredPorts.length > 0) {
                document.getElementById('liveResultsPanel').style.display = 'block';
                updateLivePortAnalysis();
            }
        } catch (e) {
            console.error('Failed to restore state:', e);
        }
    }
    
    let lastProcessedStep = null;
    let currentPass = 1;
    
    // Function to save state
    function saveState() {
        try {
            // Create a lightweight version of state (without large CVE arrays during scan)
            const lightPortAnalysis = {};
            for (const port in portAnalysis) {
                lightPortAnalysis[port] = {
                    found: portAnalysis[port].found,
                    filtered: portAnalysis[port].filtered,
                    final: portAnalysis[port].final,
                    status: portAnalysis[port].status,
                    // Only save CVE IDs, not full objects
                    cves: portAnalysis[port].cves?.map(c => ({ id: c.id, filtered: c.filtered })) || []
                };
            }
            
            sessionStorage.setItem(stateKey, JSON.stringify({
                portAnalysis: lightPortAnalysis,
                discoveredPorts,
                totalFound,
                totalFiltered,
                totalFinal,
                stepStartTime: stepStartTime,
                currentStep: currentPipelineStep
            }));
        } catch (e) {
            // Likely quota exceeded - just log and continue
            if (e.name === 'QuotaExceededError') {
                console.warn('SessionStorage quota exceeded - state not saved');
            } else {
                console.error('Failed to save state:', e.message || e);
            }
        }
    }
    
    function startLiveTimer(stepId, resuming = false) {
        if (liveTimerInterval) {
            clearInterval(liveTimerInterval);
        }
        
        // If resuming the same step, use saved start time
        if (resuming && savedCurrentStep === stepId && savedStepStartTime) {
            stepStartTime = savedStepStartTime;
        } else {
            stepStartTime = Date.now();
        }
        
        // Update less frequently (500ms instead of 100ms) to reduce repaints
        liveTimerInterval = setInterval(() => {
            const timeEl = document.getElementById(`time-${stepId}`);
            if (timeEl) {
                const elapsed = (Date.now() - stepStartTime) / 1000;
                const newText = elapsed.toFixed(1) + 's';
                // Only update if text actually changed to avoid unnecessary repaints
                if (timeEl.textContent !== newText) {
                    timeEl.textContent = newText;
                }
            }
        }, 500); // Reduced from 100ms to 500ms
    }
    
    function stopLiveTimer() {
        if (liveTimerInterval) {
            clearInterval(liveTimerInterval);
            liveTimerInterval = null;
        }
    }
    
    function togglePortDetails(port) {
        const details = document.getElementById(`port-details-${port}`);
        const icon = document.getElementById(`expand-icon-${port}`);
        
        if (details) {
            const isCurrentlyVisible = details.style.display !== 'none';
            
            if (isCurrentlyVisible) {
                details.style.display = 'none';
                icon.textContent = '▶';
                portCollapseState[port] = false;
            } else {
                details.style.display = 'block';
                icon.textContent = '▼';
                portCollapseState[port] = true;
            }
            
            saveState();
        }
    }
    
    // Make toggle function global so it can be called from HTML
    window.togglePortDetails = togglePortDetails;
    
    async function fetchRealCVEData(scanId) {
        try {
            console.log('Fetching real CVE data for scan:', scanId);
            const response = await fetch(`/api/results/${scanId}`);
            if (!response.ok) {
                console.error('Failed to fetch results:', response.status);
                return;
            }
            
            const data = await response.json();
            console.log('Received scan results:', data);
            
            // Extract CVEs per port from results
            if (data.results && data.results.length > 0) {
                const webData = data.results[0].data?.web_data;
                console.log('Web data:', webData);
                
                if (webData && webData.hosts) {
                    webData.hosts.forEach(host => {
                        host.ports.forEach(portData => {
                            const port = portData.port.toString();
                            console.log(`Port ${port}: ${portData.vulnerabilities?.length || 0} CVEs`);
                            
                            if (portAnalysis[port]) {
                                // Get real CVE IDs
                                const cves = portData.vulnerabilities || [];
                                portAnalysis[port].cves = cves.map(vuln => ({
                                    id: vuln.cve_id,
                                    filtered: false  // All in final results are not filtered
                                }));
                                console.log(`Updated port ${port} with ${cves.length} CVEs`);
                            }
                        });
                    });
                    
                    // Force display update by resetting hash
                    lastPortDataHash = '';
                    updateLivePortAnalysis();
                    saveState();
                    console.log('CVE data updated successfully');
                }
            }
        } catch (error) {
            console.error('Failed to fetch real CVE data:', error);
        }
    }
    
    function sortCVEs(cves) {
        return cves.sort((a, b) => {
            // Primary sort: validated (2+) before filtered (0-1)
            const aValidated = a.passCount >= 2 ? 1 : 0;
            const bValidated = b.passCount >= 2 ? 1 : 0;
            
            if (aValidated !== bValidated) {
                return bValidated - aValidated;  // Validated first
            }
            
            // Secondary sort: by CVE ID (alphabetical)
            return a.id.localeCompare(b.id);
        });
    }
    
    function updateLivePortAnalysis() {
        // console.log('📞 updateLivePortAnalysis called');
        // Debounce updates to prevent rapid refreshing
        if (updateTimeout) {
            clearTimeout(updateTimeout);
        }
        
        updateTimeout = setTimeout(() => {
            updateLivePortAnalysisImmediate();
            updateTimeout = null;
        }, 100); // 100ms debounce
    }
    
    function updateLivePortAnalysisImmediate() {
        const content = document.getElementById('liveResultsContent');
        
        if (discoveredPorts.length === 0) {
            content.innerHTML = `
                <div class="live-placeholder">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">🔍</div>
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Discovering Ports...</div>
                    <div style="font-size: 0.9rem;">Parsing XML scan data</div>
                </div>
            `;
            return;
        }
        
        // Check if data actually changed to avoid unnecessary re-renders
        // Create a stable hash based on actual data values
        const currentHash = discoveredPorts.map(port => {
            const analysis = portAnalysis[port] || {};
            const cveIds = (analysis.cves || []).map(c => `${c.id}:${c.filtered}`).join(',');
            return `${port}:${analysis.found}:${analysis.filtered}:${analysis.final}:${analysis.status}:${cveIds}`;
        }).join('|');
        
        if (currentHash === lastPortDataHash) {
            // console.log('🔄 Skipping port update - no data changes');
            return; // No changes, skip update
        }
        
        // console.log('✅ Updating port UI - data changed');
        // console.log('Old hash:', lastPortDataHash.substring(0, 100));
        // console.log('New hash:', currentHash.substring(0, 100));
        lastPortDataHash = currentHash;
        
        // Save current scroll position
        const scrollContainer = content.closest('.live-results-panel');
        const scrollTop = scrollContainer ? scrollContainer.scrollTop : 0;
        
        // Add note about count differences
        const noteHtml = `
            <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem; font-size: 0.85rem;">
                <strong>ℹ️ Note:</strong> Counts shown are per-port. The final report may show fewer vulnerabilities after deduplicating CVEs that appear on multiple ports.
            </div>
        `;
        
        // Update header stats
        document.getElementById('totalPorts').textContent = discoveredPorts.length;
        document.getElementById('totalFound').textContent = totalFound;
        document.getElementById('totalFinal').textContent = totalFinal;
        
        // Build port cards
        let html = noteHtml;
        discoveredPorts.forEach(port => {
            const analysis = portAnalysis[port] || {found: 0, filtered: 0, final: 0, status: 'pending'};
            const statusClass = analysis.status === 'complete' ? 'complete' : 
                               analysis.status === 'analyzing' ? 'analyzing' : 
                               analysis.status === 'waiting' ? 'waiting' : 'pending';
            
            const hasCVEs = analysis.cves && analysis.cves.length > 0;
            const isExpanded = portCollapseState[port] === true; // Default collapsed
            
            html += `
                <div class="port-card ${statusClass}" onclick="window.togglePortDetails('${port}')" style="cursor: pointer;">
                    <div class="port-header">
                        <div class="port-number">
                            <span class="port-expand-icon" id="expand-icon-${port}">${isExpanded ? '▼' : '▶'}</span>
                            Port ${port}
                        </div>
                        <div class="port-status-badge ${statusClass}">
                            ${analysis.status === 'complete' ? '✓' : 
                              analysis.status === 'analyzing' ? '⏳' : 
                              analysis.status === 'waiting' ? '⏸' : '⏸'}
                            ${analysis.status === 'waiting' ? 'Waiting' : analysis.status}
                        </div>
                    </div>
                    <div class="port-stats">
                        <div class="port-stat">
                            <span class="port-stat-label">Found</span>
                            <span class="port-stat-value">${analysis.found}</span>
                        </div>
                        <div class="port-stat-arrow">→</div>
                        <div class="port-stat">
                            <span class="port-stat-label">Filtered Out</span>
                            <span class="port-stat-value filtered">${Math.abs(analysis.filtered)}</span>
                        </div>
                        <div class="port-stat-arrow">→</div>
                        <div class="port-stat">
                            <span class="port-stat-label">Final</span>
                            <span class="port-stat-value final">${analysis.final}</span>
                        </div>
                    </div>
                    <div class="port-details" id="port-details-${port}" style="display: ${portCollapseState[port] === true ? 'block' : 'none'};">
                        ${hasCVEs ? `
                        <div class="cve-list">
                            <h4 style="margin: 0 0 0.5rem 0; font-size: 0.9rem; color: #7f8c8d;">CVE Details:</h4>
                            ${sortCVEs(analysis.cves).map(cve => {
                                let statusClass, statusText;
                                
                                if (isDeepAnalysis) {
                                    // Multi-pass mode - use status from backend
                                    if (cve.status === 'pending_ai') {
                                        statusClass = 'pending-cve';
                                        statusText = `⏳ Waiting for AI (${cve.passCount}/${cve.totalPasses})`;
                                    } else if (cve.status === 'passed_ai') {
                                        statusClass = 'pending-cve';
                                        statusText = `✓ Passed AI (${cve.passCount}/${cve.totalPasses})`;
                                    } else if (cve.status === 'failed_ai') {
                                        statusClass = 'pending-cve';
                                        statusText = `✗ Failed AI (${cve.passCount}/${cve.totalPasses})`;
                                    } else if (cve.status === 'validated') {
                                        statusClass = 'validated-cve';
                                        statusText = `✓ Validated (${cve.passCount}/3)`;
                                    } else if (cve.status === 'filtered') {
                                        statusClass = 'filtered-cve';
                                        statusText = `🚫 Filtered (${cve.passCount}/3)`;
                                    } else {
                                        // Validating
                                        statusClass = 'pending-cve';
                                        statusText = `⏳ Validating (${cve.passCount}/${cve.totalPasses})`;
                                    }
                                } else {
                                    // Single-pass mode (existing logic)
                                    if (cve.filtered) {
                                        statusClass = 'filtered-cve';
                                        statusText = '🚫 Filtered';
                                    } else {
                                        statusClass = 'validated-cve';
                                        statusText = '✓ Validated';
                                    }
                                }
                                
                                return `
                                <div class="cve-item ${statusClass}">
                                    <span class="cve-id">${cve.id}</span>
                                    <span class="cve-status">${statusText}</span>
                                </div>
                                `;
                            }).join('')}
                        </div>
                        ` : `
                        <div style="padding: 1rem; text-align: center; color: #95a5a6; font-size: 0.9rem;">
                            ${analysis.status === 'complete' && analysis.final > 0 ? 
                                `✓ ${analysis.final} CVE${analysis.final !== 1 ? 's' : ''} identified - Details will load when all ports complete` : 
                                analysis.status === 'complete' ? 
                                '✓ No vulnerabilities found' : 
                                '⏳ Analyzing...'}
                        </div>
                        `}
                    </div>
                </div>
            `;
        });
        
        content.innerHTML = html;
        
        // Restore scroll position
        if (scrollContainer) {
            scrollContainer.scrollTop = scrollTop;
        }
    }
    
    function sortCVEs(cves) {
        if (!cves || cves.length === 0) return [];
        
        // IMPORTANT: Create a copy to avoid mutating the original array
        // Mutating would change the hash and trigger infinite re-renders!
        return [...cves].sort((a, b) => {
            // First sort by filtered status (false before true)
            if (a.filtered !== b.filtered) {
                return a.filtered ? 1 : -1;
            }
            // Then sort alphabetically by CVE ID
            return a.id.localeCompare(b.id);
        });
    }
    
    // Initial state check - get current progress immediately to rebuild state
    async function checkInitialState() {
        try {
            const progressResponse = await fetch(`/api/progress/${scanId}`);
            const progressData = await progressResponse.json();
            
            // If scan is in progress, show the panel immediately
            if (progressData.percent > 0 && progressData.percent < 100) {
                document.getElementById('liveResultsPanel').style.display = 'block';
            }
            
            // Restore active step and timer if we have saved state
            if (savedCurrentStep && savedStepStartTime) {
                currentPipelineStep = savedCurrentStep;
                const stepInfo = pipeline.find(s => s.id === savedCurrentStep);
                const state = stepInfo && stepInfo.aiStep ? 'ai-active' : 'active';
                updatePipelineStep(savedCurrentStep, state);
                startLiveTimer(savedCurrentStep, true); // Resume with saved time
            }
        } catch (err) {
            console.error('Initial state check error:', err);
        }
    }
    
    checkInitialState();
    
    progressInterval = setInterval(async () => {
        try {
            const progressResponse = await fetch(`/api/progress/${scanId}`);
            const progressData = await progressResponse.json();
            
            // Update filename display if available
            if (progressData.filenames && progressData.filenames.length > 0) {
                const filenameEl = document.getElementById('displayFilename');
                if (filenameEl) {
                    if (progressData.filenames.length === 1) {
                        filenameEl.textContent = progressData.filenames[0];
                    } else {
                        filenameEl.textContent = `${progressData.filenames.length} files: ${progressData.filenames.join(', ')}`;
                    }
                }
            }
            
            // Pre-build all port cards when we receive discovered_ports
            if (progressData.discovered_ports && progressData.discovered_ports.length > 0) {
                console.log(`📋 Pre-building ${progressData.discovered_ports.length} port cards:`, progressData.discovered_ports);
                let portsAdded = false;
                progressData.discovered_ports.forEach(port => {
                    if (!discoveredPorts.includes(port)) {
                        discoveredPorts.push(port);
                        portAnalysis[port] = {
                            found: 0, 
                            filtered: 0, 
                            final: 0, 
                            status: 'waiting',  // New status: waiting for analysis
                            cves: []
                        };
                        portsAdded = true;
                    }
                });
                discoveredPorts.sort((a, b) => parseInt(a) - parseInt(b));
                console.log(`✅ Port cards created for: ${discoveredPorts.join(', ')}`);
                
                // Update display to show the port cards
                if (portsAdded) {
                    updateLivePortAnalysis();
                }
            }
            
            // Track if this is a deep analysis (multi-pass) scan
            if (progressData.deep_analysis !== undefined) {
                isDeepAnalysis = progressData.deep_analysis && progressData.use_ai;
            }
            
            // Check if multi-pass is complete FOR THE ENTIRE SCAN (not just one port)
            // Only set complete when the overall scan status is Complete
            // Don't set complete just because ONE port finished Pass 3/3
            if (progressData.status === 'Complete') {
                isMultiPassComplete = true;
            }
            
            // Update progress bar
            progressFill.style.width = progressData.percent + '%';
            progressText.textContent = progressData.step;
            
            // Update status badge - override "Complete" if still in multi-pass analysis
            let status = progressData.status || 'Processing';
            
            // Don't show "Complete" until truly done (not just after one port's passes)
            if (status === 'Complete' && progressData.percent < 100) {
                status = 'Processing';
            }
            
            // If we're in multi-pass mode and see pass numbers, show that
            const passMatch = progressData.step.match(/Pass (\d+)\/3/);
            if (passMatch && isDeepAnalysis) {
                status = `Pass ${passMatch[1]}/3`;
            }
            
            statusBadge.textContent = status;
            statusBadge.className = 'status-badge ' + status.toLowerCase().replace(/ /g, '-');
            
            // Update timer
            if (progressData.elapsed_time !== undefined) {
                timerText.textContent = progressData.elapsed_time.toFixed(1) + 's';
            }
            
            // Update file counter
            if (progressData.current_file !== undefined && progressData.total_files !== undefined) {
                fileCounter.textContent = `File ${progressData.current_file + 1} of ${progressData.total_files}`;
            }
            
            // Show live results panel after parsing completes
            const liveResultsPanel = document.getElementById('liveResultsPanel');
            
            // Extract port discovery from parsing step
            const portsDiscoveredMatch = progressData.step.match(/(\d+)\s+ports?/i);
            if (portsDiscoveredMatch && discoveredPorts.length === 0) {
                liveResultsPanel.style.display = 'block';
                updateLivePortAnalysis();
            }
            
            // Check for CVE data in progress - NEW STAGE-BASED HANDLING
            if (progressData.port_cves) {
                let newPortsAdded = false;
                for (const port in progressData.port_cves) {
                    if (!discoveredPorts.includes(port)) {
                        discoveredPorts.push(port);
                        discoveredPorts.sort((a, b) => parseInt(a) - parseInt(b));
                        portAnalysis[port] = {found: 0, filtered: 0, final: 0, status: 'pending', cves: [], pass: 0};
                        newPortsAdded = true;
                        console.log(`📋 Port ${port} discovered via CVE data`);
                    }
                    
                    const portCVEs = progressData.port_cves[port];
                    
                    console.log(`🔍 Port ${port} update - status: ${portCVEs.status}, has consensus_data: ${!!portCVEs.consensus_data}, has pass_data: ${!!portCVEs.pass_data}, has nvd_cves: ${!!portCVEs.nvd_cves}`);
                    
                    // Initialize working data if needed
                    if (!portAnalysis[port].workingData) {
                        portAnalysis[port].workingData = {
                            nvd_cves: [],
                            ai_passed: [],
                            ai_failed: []
                        };
                    }
                    
                    // Process all stages, but only update DISPLAY array when stage completes
                    // Use else-if to ensure only ONE stage processes per update
                    
                    // Stage 4: Final consensus (after all 3 passes) - HIGHEST PRIORITY
                    // This stage contains CUMULATIVE data from all 3 passes
                    // consensus_score = how many passes the CVE appeared in (0-3)
                    if ((portCVEs.status === 'consensus' || portCVEs.status === 'complete') && 
                        portCVEs.consensus_data && portCVEs.found) {
                        console.log(`✅ CONSENSUS STAGE - Port ${port}:`);
                        console.log(`   Found CVEs: ${portCVEs.found.length}`, portCVEs.found);
                        console.log(`   Final CVEs: ${portCVEs.final?.length}`, portCVEs.final);
                        console.log(`   Consensus data:`, portCVEs.consensus_data);
                        
                        const finalSet = new Set(portCVEs.final || []);
                        
                        // Build display array with cumulative pass counts from all 3 passes
                        portAnalysis[port].cves = portCVEs.found.map(cveId => {
                            const consensus = portCVEs.consensus_data[cveId];
                            const passCount = consensus?.consensus_score || 0;  // Cumulative count from all passes
                            const isValidated = finalSet.has(cveId);
                            
                            const cveObj = {
                                id: cveId,
                                passCount: passCount,
                                totalPasses: 3,
                                status: isValidated ? 'validated' : 'filtered',
                                filtered: !isValidated
                            };
                            
                            console.log(`   ${cveId}: passCount=${passCount}, isValidated=${isValidated}, status=${cveObj.status}`);
                            return cveObj;
                        });
                        
                        portAnalysis[port].found = portCVEs.found.length;
                        portAnalysis[port].final = portCVEs.final?.length || 0;
                        portAnalysis[port].filtered = portCVEs.filtered_count || 0;
                        portAnalysis[port].status = 'complete';
                        
                        console.log(`✅ Analysis complete: ${portAnalysis[port].final} validated, ${portAnalysis[port].filtered} filtered`);
                        console.log(`   CVEs: ${portAnalysis[port].cves.map(c => `${c.id}(${c.status})`).join(', ')}`);
                        
                        // UPDATE DISPLAY ARRAY - this is what the user sees
                        updateLivePortAnalysis();
                    }
                    // Stage 3: Cumulative update after pass completes
                    // Shows progressive pass counts: after Pass 1 (X/1), Pass 2 (X/2), Pass 3 (X/3)
                    // pass_count = how many times CVE has appeared SO FAR (0 to current pass number)
                    else if (portCVEs.status === 'analyzing' && portCVEs.pass_data && portCVEs.all_cves) {
                        console.log(`📊 CUMULATIVE STAGE - Port ${port} Pass ${portCVEs.pass}: ${portCVEs.all_cves.length} CVEs`);
                        portAnalysis[port].status = 'analyzing';
                        portAnalysis[port].pass = portCVEs.pass || 1;
                        
                        // Update display array with cumulative pass counts from backend
                        portAnalysis[port].cves = portCVEs.all_cves.map(cveId => {
                            const passData = portCVEs.pass_data[cveId];
                            return {
                                id: cveId,
                                passCount: passData?.pass_count || 0,  // Cumulative count up to this pass
                                totalPasses: passData?.total_passes || portCVEs.pass,
                                status: passData?.status || 'validating',
                                filtered: passData?.status === 'filtered'
                            };
                        });
                        
                        // Calculate counts
                        const validated = portAnalysis[port].cves.filter(c => c.passCount >= 2);
                        const filtered = portAnalysis[port].cves.filter(c => c.status === 'filtered');
                        
                        portAnalysis[port].found = portCVEs.all_cves.length;
                        portAnalysis[port].final = validated.length;
                        portAnalysis[port].filtered = filtered.length;
                        
                        console.log(`📊 Pass ${portCVEs.pass}/3 complete: ${validated.length} validated, ${filtered.length} filtered`);
                        
                        // UPDATE DISPLAY ARRAY - this is what the user sees
                        updateLivePortAnalysis();
                    }
                    // Stage 2: AI filtering complete - update working data only
                    else if (portCVEs.status === 'ai_complete' && portCVEs.passed && portCVEs.failed) {
                        // Store in working data, don't update display yet
                        portAnalysis[port].workingData.ai_passed = portCVEs.passed;
                        portAnalysis[port].workingData.ai_failed = portCVEs.failed;
                        
                        console.log(`🤖 AI filtered: ${portCVEs.passed.length} passed, ${portCVEs.failed.length} failed (working data only)`);
                        // Don't call updateLivePortAnalysis() - wait for pass to complete
                    }
                    // Stage 1: NVD returned CVEs - update working data only
                    else if (portCVEs.status === 'nvd_complete' && portCVEs.nvd_cves) {
                        // Store in working data, don't update display yet
                        portAnalysis[port].workingData.nvd_cves = portCVEs.nvd_cves;
                        portAnalysis[port].pass = portCVEs.pass || 1;
                        
                        console.log(`📥 NVD returned ${portCVEs.nvd_cves.length} CVEs for port ${port} (working data only)`);
                        // Don't call updateLivePortAnalysis() - wait for pass to complete
                    }
                }
                
                // Update global totals
                totalFound = Object.values(portAnalysis).reduce((sum, p) => sum + p.found, 0);
                totalFiltered = Object.values(portAnalysis).reduce((sum, p) => sum + p.filtered, 0);
                totalFinal = Object.values(portAnalysis).reduce((sum, p) => sum + p.final, 0);
                
                if (liveResultsPanel.style.display === 'none') {
                    liveResultsPanel.style.display = 'block';
                }
                
                // If new ports were discovered, update display to show them
                if (newPortsAdded) {
                    updateLivePortAnalysis();
                }
            }
            
            // Check for port-specific progress
            const portMatch = progressData.step.match(/port (\d+)/i);
            if (portMatch) {
                const port = portMatch[1];
                
                if (liveResultsPanel.style.display === 'none') {
                    liveResultsPanel.style.display = 'block';
                }
                
                if (!discoveredPorts.includes(port)) {
                    discoveredPorts.push(port);
                    discoveredPorts.sort((a, b) => parseInt(a) - parseInt(b));
                    portAnalysis[port] = {found: 0, filtered: 0, final: 0, status: 'pending', cves: []};
                    saveState();
                }
                
                // Set status to analyzing during processing
                // In multi-pass mode, check if we're still in Pass 1 or 2
                const passMatch = progressData.step.match(/Pass (\d+)\/3/);
                const currentPass = passMatch ? parseInt(passMatch[1]) : null;
                
                if (status === 'NVD Query' || progressData.step.includes('Querying NVD')) {
                    // During Pass 1 or 2, always set to analyzing (even if briefly set to complete)
                    if (!isDeepAnalysis || !currentPass || currentPass < 3) {
                        portAnalysis[port].status = 'analyzing';
                    }
                } else if (status === 'AI Processing' || progressData.step.includes('enhancing')) {
                    if (!isDeepAnalysis || !currentPass || currentPass < 3) {
                        portAnalysis[port].status = 'analyzing';
                    }
                } else if (status === 'AI Filtering' || progressData.step.includes('filtering')) {
                    if (!isDeepAnalysis || !currentPass || currentPass < 3) {
                        portAnalysis[port].status = 'analyzing';
                    }
                }
                
                const cvesMatch = progressData.step.match(/(\d+) CVEs/);
                if (cvesMatch) {
                    const cveCount = parseInt(cvesMatch[1]);
                    const stepLower = progressData.step.toLowerCase();
                    
                    // Check if this is the initial "found" count
                    if (stepLower.includes('found') || stepLower.includes('querying') || stepLower.includes('nvd')) {
                        portAnalysis[port].found = cveCount;
                        totalFound = Object.values(portAnalysis).reduce((sum, p) => sum + p.found, 0);
                        
                        // Don't generate placeholder CVEs - wait for real data after scan completes
                        if (!portAnalysis[port].cves) {
                            portAnalysis[port].cves = [];
                        }
                        
                        saveState();
                    } 
                    // Check if this is the final filtered count
                    else if (stepLower.includes('filtering') || stepLower.includes('filtered') || stepLower.includes('final')) {
                        // Only update if we have a found count already
                        if (portAnalysis[port].found > 0) {
                            // Only update if values actually changed
                            if (portAnalysis[port].final !== cveCount || portAnalysis[port].status !== 'complete') {
                                portAnalysis[port].final = cveCount;
                                portAnalysis[port].filtered = portAnalysis[port].found - cveCount;
                                
                                // Only mark complete if we're on Pass 3 or in single-pass mode
                                const passMatch = progressData.step.match(/Pass (\d+)\/3/);
                                const currentPass = passMatch ? parseInt(passMatch[1]) : null;
                                
                                // In multi-pass, REQUIRE Pass 3 confirmation (don't assume)
                                // Only mark complete if we explicitly see Pass 3
                                const isPass3 = currentPass === 3;
                                
                                if (!isDeepAnalysis || isPass3) {
                                    portAnalysis[port].status = 'complete';
                                    
                                    // When marking complete after Pass 3, ensure all validated CVEs show 3/3
                                    if (isDeepAnalysis && isPass3 && portAnalysis[port].cves) {
                                        portAnalysis[port].cves.forEach(cve => {
                                            // If CVE is validated (not filtered), it passed all 3 passes
                                            if (!cve.filtered && cve.passCount < 3) {
                                                cve.passCount = 3;
                                                console.log(`  ✓ Updated ${cve.id} to 3/3 passes (was ${cve.passCount})`);
                                            }
                                        });
                                    }
                                } else if (isDeepAnalysis) {
                                    // In multi-pass mode, keep as analyzing if not Pass 3
                                    portAnalysis[port].status = 'analyzing';
                                }
                                
                                totalFinal = Object.values(portAnalysis).reduce((sum, p) => sum + p.final, 0);
                                
                                // Mark filtered CVEs IN PLACE
                                const numToFilter = portAnalysis[port].found - cveCount;
                                if (portAnalysis[port].cves && portAnalysis[port].cves.length > 0) {
                                    for (let i = 0; i < numToFilter && i < portAnalysis[port].cves.length; i++) {
                                        portAnalysis[port].cves[i].filtered = true;
                                    }
                                }
                                
                                saveState();
                            }
                        } else {
                            // If no found count yet, this might be the found count
                            portAnalysis[port].found = cveCount;
                            portAnalysis[port].final = cveCount;
                            totalFound = Object.values(portAnalysis).reduce((sum, p) => sum + p.found, 0);
                            totalFinal = Object.values(portAnalysis).reduce((sum, p) => sum + p.final, 0);
                            
                            // Don't generate placeholder CVEs - wait for real data
                            if (!portAnalysis[port].cves) {
                                portAnalysis[port].cves = [];
                            }
                            
                            saveState();
                        }
                    }
                }
                
                // Don't automatically update display - let stages control when to update
                // This prevents flashing during intermediate stages
            }
            
            // Update pipeline roadmap
            const matchedStep = matchStepToProgress(progressData.step, status);
            if (matchedStep) {
                const stepKey = `${matchedStep}-${progressData.step}`;
                const isNewStep = lastProcessedStep !== stepKey;
                
                if (isNewStep) {
                    lastProcessedStep = stepKey;
                    
                    const stepIndex = pipeline.findIndex(s => s.id === matchedStep);
                    for (let i = 0; i < stepIndex; i++) {
                        if (!completedSteps.has(pipeline[i].id)) {
                            updatePipelineStep(pipeline[i].id, 'completed', progressData.elapsed_time.toFixed(1));
                            completedSteps.add(pipeline[i].id);
                        }
                    }
                }
                
                if (currentPipelineStep !== matchedStep) {
                    const isRevisit = completedSteps.has(matchedStep);
                    
                    if (currentPipelineStep) {
                        stopLiveTimer();
                        const finalTime = progressData.elapsed_time.toFixed(1);
                        updatePipelineStep(currentPipelineStep, 'completed', finalTime);
                        
                        if (!isRevisit) {
                            completedSteps.add(currentPipelineStep);
                        }
                    }
                    
                    if (matchedStep === 'ai-filter' && progressData.step.includes('port')) {
                        const portMatch = progressData.step.match(/for port (\d+)/);
                        const cvesMatch = progressData.step.match(/(\d+) CVEs/);
                        const passNumberMatch = progressData.step.match(/Pass (\d+)\/3/);
                        
                        if (portMatch) {
                            const port = portMatch[1];
                            // Extract actual pass number from step text (1-3 per port)
                            const passNumber = passNumberMatch ? parseInt(passNumberMatch[1]) : 1;
                            
                            passMetrics.push({
                                pass: passNumber,  // Now correctly 1-3 per port
                                port: port,
                                cves_found: cvesMatch ? parseInt(cvesMatch[1]) : 0,
                                duration: progressData.elapsed_time.toFixed(1),
                                timestamp: new Date().toLocaleTimeString('en-US', { hour12: false })
                            });
                            
                            // Don't show pass indicator badge on the step itself - it's shown in activity log instead
                            // This avoids confusion between port numbers and pass numbers
                            
                            updateActivityLog();
                        }
                    }
                    
                    currentPipelineStep = matchedStep;
                    const stepInfo = pipeline.find(s => s.id === matchedStep);
                    const state = stepInfo && stepInfo.aiStep ? 'ai-active' : 'active';
                    updatePipelineStep(matchedStep, state, progressData.elapsed_time.toFixed(1));
                    startLiveTimer(matchedStep);
                }
            }
            
            // Track activity history
            if (progressData.step !== lastStep) {
                const now = new Date();
                const timestamp = now.toLocaleTimeString('en-US', { hour12: false });
                
                activityHistory.push({
                    timestamp: timestamp,
                    step: progressData.step,
                    status: status,
                    duration: progressData.elapsed_time ? progressData.elapsed_time.toFixed(1) : '0.0',
                    percent: progressData.percent
                });
                
                lastStep = progressData.step;
                activityCount.textContent = `(${activityHistory.length})`;
                updateActivityLog();
            }
            
            // Update step time markers
            if (progressData.step_times && progressData.step_times.length > 0) {
                stepTimes.innerHTML = '';
                progressData.step_times.forEach(step => {
                    const marker = document.createElement('div');
                    marker.className = 'step-time-marker';
                    marker.style.left = step.percent + '%';
                    marker.textContent = step.duration + 's';
                    stepTimes.appendChild(marker);
                });
            }
            
            // If complete, show completion section and fetch real CVE data
            if (progressData.percent >= 100) {
                stopLiveTimer();
                clearInterval(progressInterval);
                localStorage.removeItem('activeScanId');
                sessionStorage.removeItem(stateKey);
                
                const completionSection = document.getElementById('completionSection');
                const viewSummaryBtn = document.getElementById('viewSummaryBtn');
                
                completionSection.style.display = 'block';
                
                viewSummaryBtn.onclick = () => {
                    window.location.href = `/results/${scanId}`;
                };
                
                document.getElementById('completionVulnCount').textContent = totalFinal;
                document.getElementById('completionHostCount').textContent = '1';
                
                // Fetch real CVE data from results
                fetchRealCVEData(scanId);
                
                // Trigger navigation state update with delay to allow backend to update
                if (window.checkNavAvailability) {
                    // Check immediately
                    window.checkNavAvailability();
                    // Check again after 1 second
                    setTimeout(() => window.checkNavAvailability(), 1000);
                    // Check again after 3 seconds
                    setTimeout(() => window.checkNavAvailability(), 3000);
                }
            }
        } catch (err) {
            console.error('Progress poll error:', err);
            console.error('Error details:', err.message, err.stack);
        }
    }, 2000); // Reduced from 300ms to 2000ms to prevent excessive updates
}
