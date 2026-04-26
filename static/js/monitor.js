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
                            <span class="pass-badge">PASS ${idx + 1}</span>
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
            const statusClass = activity.status.toLowerCase().replace(/ /g, '-');
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
    let isMultiPassComplete = false; // Track if all passes are done
    let cvePassCounts = {}; // Track how many passes each CVE appeared in: {port: {cve_id: count}}
    let lastProcessedPass = {}; // Track last pass processed per port to avoid double-counting
    
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
                                // Determine status: filtered, validated (consensus reached), or pending
                                let statusClass, statusText;
                                if (cve.filtered) {
                                    statusClass = 'filtered-cve';
                                    statusText = '🚫 Filtered';
                                } else if (isDeepAnalysis) {
                                    // Multi-pass mode: validate when CVE appears in 2+ passes
                                    if (cve.passCount >= 2) {
                                        statusClass = 'validated-cve';
                                        statusText = `✓ Validated (${cve.passCount}/3)`;
                                    } else {
                                        statusClass = 'pending-cve';
                                        statusText = `⏳ Pending (${cve.passCount}/3)`;
                                    }
                                } else {
                                    // Single-pass mode: validate when analysis complete
                                    if (analysis.status === 'complete') {
                                        statusClass = 'validated-cve';
                                        statusText = '✓ Validated';
                                    } else {
                                        statusClass = 'pending-cve';
                                        statusText = '⏳ Pending';
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
                    }
                });
                discoveredPorts.sort((a, b) => parseInt(a) - parseInt(b));
                console.log(`✅ Port cards created for: ${discoveredPorts.join(', ')}`);
            }
            
            // Track if this is a deep analysis (multi-pass) scan
            if (progressData.deep_analysis !== undefined) {
                isDeepAnalysis = progressData.deep_analysis && progressData.use_ai;
            }
            
            // Check if multi-pass is complete
            // Complete when: status is Complete, OR we see "Pass 3/3", OR we see filtering/final steps after passes
            if (progressData.status === 'Complete' || 
                progressData.step.includes('Pass 3/3') ||
                (isDeepAnalysis && (progressData.step.includes('filtering') || progressData.step.includes('AI Filtering')))) {
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
            
            // Check for CVE data in progress
            if (progressData.port_cves) {
                for (const port in progressData.port_cves) {
                    if (!discoveredPorts.includes(port)) {
                        discoveredPorts.push(port);
                        discoveredPorts.sort((a, b) => parseInt(a) - parseInt(b));
                        portAnalysis[port] = {found: 0, filtered: 0, final: 0, status: 'pending', cves: []};
                    }
                    
                    // Update status from waiting to analyzing when CVE data arrives
                    if (portAnalysis[port].status === 'waiting') {
                        portAnalysis[port].status = 'analyzing';
                        console.log(`🔄 Port ${port}: Status changed from waiting to analyzing`);
                    }
                    
                    const portCVEs = progressData.port_cves[port];
                    const currentPass = portCVEs.pass || 1; // Get current pass number (should be 1-3 per port)
                    
                    if (portCVEs.found && portCVEs.found.length > 0) {
                        // Initialize trackers for this port
                        if (!cvePassCounts[port]) {
                            cvePassCounts[port] = {};
                            console.log(`🆕 Initialized tracking for Port ${port}`);
                        }
                        if (!lastProcessedPass[port]) {
                            lastProcessedPass[port] = 0;
                        }
                        
                        console.log(`🔍 Port ${port}: currentPass=${currentPass}, lastProcessedPass=${lastProcessedPass[port]}, CVEs=${portCVEs.found.length}`);
                        
                        // Only update pass counts if this is a new pass (not a duplicate update)
                        if (currentPass > lastProcessedPass[port]) {
                            console.log(`✅ Port ${port}: NEW Pass ${currentPass} detected (previous was ${lastProcessedPass[port]})`);
                            lastProcessedPass[port] = currentPass;
                            
                            // Increment pass count for CVEs in this NEW pass
                            portCVEs.found.forEach(cveId => {
                                // Initialize to 0 if not seen before, then increment
                                if (!cvePassCounts[port][cveId]) {
                                    cvePassCounts[port][cveId] = 0;
                                }
                                cvePassCounts[port][cveId]++;
                                console.log(`  ✓ ${cveId}: now at ${cvePassCounts[port][cveId]}/3 passes`);
                            });
                            
                            // Force UI update to show new pass counts
                            lastPortDataHash = '';
                        } else {
                            console.log(`⏭️  Port ${port}: Skipping duplicate update for Pass ${currentPass}`);
                        }
                        
                        // Merge new CVEs with existing ones (accumulate across passes)
                        const existingIds = new Set(portAnalysis[port].cves.map(c => c.id));
                        const newCVEs = portCVEs.found
                            .filter(id => !existingIds.has(id))
                            .map(id => ({
                                id, 
                                filtered: false,
                                passCount: cvePassCounts[port][id] || 1
                            }));
                        
                        // Update pass counts for existing CVEs
                        portAnalysis[port].cves.forEach(cve => {
                            if (cvePassCounts[port][cve.id]) {
                                cve.passCount = cvePassCounts[port][cve.id];
                            }
                        });
                        
                        portAnalysis[port].cves = [...portAnalysis[port].cves, ...newCVEs];
                        portAnalysis[port].found = portAnalysis[port].cves.length;
                        totalFound = Object.values(portAnalysis).reduce((sum, p) => sum + p.found, 0);
                        
                        // In multi-pass mode, count CVEs with 2+ passes as final
                        if (isDeepAnalysis) {
                            const validatedCount = portAnalysis[port].cves.filter(c => !c.filtered && c.passCount >= 2).length;
                            portAnalysis[port].final = validatedCount;
                            totalFinal = Object.values(portAnalysis).reduce((sum, p) => sum + p.final, 0);
                        }
                    }
                    if (portCVEs.final && portCVEs.final.length > 0) {
                        // In multi-pass mode, only update final counts after all passes complete
                        // In single-pass mode, update immediately
                        const shouldUpdateFinal = !isDeepAnalysis || isMultiPassComplete;
                        
                        if (shouldUpdateFinal) {
                            // Only update if values actually changed
                            const newFinal = portCVEs.final.length;
                            const newFiltered = portAnalysis[port].found - newFinal;
                            
                            if (portAnalysis[port].final !== newFinal || portAnalysis[port].filtered !== newFiltered) {
                                portAnalysis[port].final = newFinal;
                                portAnalysis[port].filtered = newFiltered;
                                
                                // Mark filtered CVEs IN PLACE (don't create new array)
                                const finalIds = new Set(portCVEs.final);
                                portAnalysis[port].cves.forEach(cve => {
                                    cve.filtered = !finalIds.has(cve.id);
                                });
                                
                                portAnalysis[port].status = 'complete';
                                totalFinal = Object.values(portAnalysis).reduce((sum, p) => sum + p.final, 0);
                            }
                        }
                    }
                }
                
                if (liveResultsPanel.style.display === 'none') {
                    liveResultsPanel.style.display = 'block';
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
                
                // Only update status if it actually changed to prevent animation restarts
                if (status === 'NVD Query' || progressData.step.includes('Querying NVD')) {
                    if (portAnalysis[port].status !== 'analyzing' && portAnalysis[port].status !== 'complete') {
                        portAnalysis[port].status = 'analyzing';
                    }
                } else if (status === 'AI Processing' || progressData.step.includes('enhancing')) {
                    if (portAnalysis[port].status !== 'analyzing' && portAnalysis[port].status !== 'complete') {
                        portAnalysis[port].status = 'analyzing';
                    }
                } else if (status === 'AI Filtering' || progressData.step.includes('filtering')) {
                    if (portAnalysis[port].status !== 'analyzing' && portAnalysis[port].status !== 'complete') {
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
                                portAnalysis[port].status = 'complete';
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
                
                // Always call updateLivePortAnalysis - it has its own hash check
                // This ensures we use the same hash calculation everywhere
                updateLivePortAnalysis();
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
                        
                        if (portMatch) {
                            const port = portMatch[1];
                            const passNumber = passMetrics.length + 1;
                            
                            passMetrics.push({
                                pass: passNumber,
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
