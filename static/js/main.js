// Global state
let currentAnalysis = null;

// DOM Elements
const cveForm = document.getElementById('cveForm');
const loadingState = document.getElementById('loadingState');
const resultsContainer = document.getElementById('resultsContainer');
const errorContainer = document.getElementById('errorContainer');
const componentSelect = document.getElementById('component');

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    loadComponents();
});

function initializeApp() {
    // No default CVE value - let user enter their own
}

function setupEventListeners() {
    // Form submission
    cveForm.addEventListener('submit', handleFormSubmit);
    
    // Tab switching
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.addEventListener('click', () => switchTab(button.dataset.tab));
    });
    
    // Navigation links
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
        });
    });
}

async function loadComponents() {
    try {
        const response = await fetch('/api/components');
        const components = await response.json();
        
        componentSelect.innerHTML = '<option value="">Select a component...</option>';
        components.forEach(component => {
            const option = document.createElement('option');
            option.value = component.name;
            option.textContent = component.name;
            componentSelect.appendChild(option);
        });
    } catch (error) {
        console.warn('Failed to load components:', error);
    }
}

async function handleFormSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(cveForm);
    const cveId = formData.get('cveId').trim();
    const component = formData.get('component') || null;
    const aiAnalysis = formData.get('aiAnalysis') === 'on';
    
    if (!cveId) {
        showError('Please enter a CVE identifier');
        return;
    }
    
    // Validate CVE format
    const cvePattern = /^CVE-\d{4}-\d{4,7}$/i;
    if (!cvePattern.test(cveId)) {
        showError('Invalid CVE format. Use CVE-YYYY-NNNNN format');
        return;
    }
    
    await performAnalysis({
        cve_id: cveId.toUpperCase(),
        component: component,
        ai_analysis: aiAnalysis
    });
}

async function performAnalysis(data) {
    showLoadingState(data.ai_analysis);
    hideError();
    hideResults();
    
    const steps = ['nvd', 'epss', 'kev', 'github'];
    if (data.ai_analysis) {
        steps.push('ai');
        document.querySelector('[data-step="ai"]').style.display = 'block';
    }
    
    try {
        // Simulate step progression
        let currentStep = 0;
        const stepInterval = setInterval(() => {
            if (currentStep < steps.length) {
                updateLoadingStep(steps[currentStep], 'active');
                currentStep++;
            }
        }, 500);
        
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        clearInterval(stepInterval);
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Analysis failed');
        }
        
        const result = await response.json();
        currentAnalysis = result;
        
        // Mark all steps as completed
        steps.forEach(step => updateLoadingStep(step, 'completed'));
        
        // Show results after a brief delay
        setTimeout(() => {
            hideLoadingState();
            displayResults(result);
        }, 1000);
        
    } catch (error) {
        hideLoadingState();
        showError(error.message);
    }
}

function showLoadingState(showAiStep = false) {
    loadingState.style.display = 'block';
    
    // Reset all steps
    const steps = document.querySelectorAll('.step');
    steps.forEach(step => {
        step.classList.remove('active', 'completed');
    });
    
    // Show/hide AI step
    const aiStep = document.querySelector('[data-step="ai"]');
    aiStep.style.display = showAiStep ? 'block' : 'none';
}

function hideLoadingState() {
    loadingState.style.display = 'none';
}

function updateLoadingStep(stepName, status) {
    const step = document.querySelector(`[data-step="${stepName}"]`);
    if (step) {
        step.classList.remove('active', 'completed');
        step.classList.add(status);
    }
}

function displayResults(data) {
    resultsContainer.style.display = 'block';
    
    // Populate CVE header
    const cve = data.nvd?.vulnerabilities?.[0]?.cve;
    if (cve) {
        populateCVEHeader(cve, data.cve_id);
        populateOverviewTab(cve, data);
        populateTechnicalTab(cve);
        populateImpactTab(cve);
        populateMitigationTab(cve);
        populateSidebar(cve, data);
        
        if (data.ai_analysis) {
            populateAITab(data.ai_analysis);
        }
    }
}

function populateCVEHeader(cve, cveId) {
    const title = document.getElementById('cveTitle');
    const badge = document.getElementById('cveId');
    const nvdButton = document.querySelector('.cve-actions .btn');
    
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';
    const firstLine = description.split('.')[0] + '.';
    
    // Include CVE number in the title
    title.textContent = `${cveId}: ${firstLine}`;
    badge.textContent = cveId;
    
    nvdButton.onclick = () => {
        window.open(`https://nvd.nist.gov/vuln/detail/${cveId}`, '_blank');
    };
}

function populateOverviewTab(cve, data) {
    const description = document.getElementById('cveDescription');
    const publishedDate = document.getElementById('publishedDate');
    const lastModified = document.getElementById('lastModified');
    const vulnStatus = document.getElementById('vulnStatus');
    const affectedTech = document.getElementById('affectedTech');
    const references = document.getElementById('references');
    
    // Description
    const descText = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';
    description.textContent = descText;
    
    // Dates
    publishedDate.textContent = formatDate(cve.published);
    lastModified.textContent = formatDate(cve.lastModified);
    
    // Status
    vulnStatus.textContent = cve.vulnStatus || 'Unknown';
    vulnStatus.className = `status-badge status-${cve.vulnStatus?.toLowerCase().replace(' ', '-') || 'unknown'}`;
    
    // Affected technologies (extract from description and references)
    const technologies = extractTechnologies(cve);
    affectedTech.innerHTML = '';
    technologies.forEach(tech => {
        const badge = document.createElement('div');
        badge.className = 'tech-badge';
        badge.innerHTML = `<i class="fas fa-cube"></i> ${tech}`;
        affectedTech.appendChild(badge);
    });
    
    // References
    references.innerHTML = '';
    if (cve.references) {
        cve.references.forEach(ref => {
            const link = document.createElement('a');
            link.className = 'reference-link';
            link.href = ref.url;
            link.target = '_blank';
            link.innerHTML = `
                <i class="fas fa-external-link-alt"></i>
                ${getHostname(ref.url)}
            `;
            references.appendChild(link);
        });
    }
}

function populateTechnicalTab(cve) {
    const container = document.getElementById('technicalDetails');
    
    let html = '<h3>CVSS Metrics</h3>';
    
    if (cve.metrics?.cvssMetricV31) {
        const metrics = cve.metrics.cvssMetricV31[0];
        const cvss = metrics.cvssData;
        
        html += `
            <div class="technical-section">
                <div class="cvss-breakdown">
                    <div class="metric-grid">
                        <div class="metric-item">
                            <label>Attack Vector</label>
                            <span class="metric-value">${cvss.attackVector} (${cvss.attackVector === 'NETWORK' ? 'Remote' : 'Local'})</span>
                        </div>
                        <div class="metric-item">
                            <label>Attack Complexity</label>
                            <span class="metric-value">${cvss.attackComplexity}</span>
                        </div>
                        <div class="metric-item">
                            <label>Privileges Required</label>
                            <span class="metric-value">${cvss.privilegesRequired}</span>
                        </div>
                        <div class="metric-item">
                            <label>User Interaction</label>
                            <span class="metric-value">${cvss.userInteraction}</span>
                        </div>
                        <div class="metric-item">
                            <label>Scope</label>
                            <span class="metric-value">${cvss.scope}</span>
                        </div>
                        <div class="metric-item">
                            <label>Confidentiality Impact</label>
                            <span class="metric-value">${cvss.confidentialityImpact}</span>
                        </div>
                        <div class="metric-item">
                            <label>Integrity Impact</label>
                            <span class="metric-value">${cvss.integrityImpact}</span>
                        </div>
                        <div class="metric-item">
                            <label>Availability Impact</label>
                            <span class="metric-value">${cvss.availabilityImpact}</span>
                        </div>
                    </div>
                    <div class="vector-string">
                        <label>CVSS Vector</label>
                        <code>${cvss.vectorString}</code>
                    </div>
                </div>
            </div>
        `;
    }
    
    if (cve.weaknesses) {
        html += '<h3>Weakness Classification</h3>';
        html += '<div class="weakness-section">';
        cve.weaknesses.forEach(weakness => {
            weakness.description.forEach(desc => {
                html += `
                    <div class="weakness-item">
                        <strong>${desc.value}</strong>
                        <p>Type: ${weakness.type}</p>
                    </div>
                `;
            });
        });
        html += '</div>';
    }
    
    container.innerHTML = html;
}

function populateImpactTab(cve) {
    const container = document.getElementById('impactAnalysis');
    
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
    const cvssData = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    
    let html = '<h3>Impact Analysis</h3>';
    
    html += `
        <div class="impact-content">
            <p>${description}</p>
            
            <h4>Security Impact</h4>
            <div class="impact-grid">
    `;
    
    if (cvssData) {
        const impacts = [
            { label: 'Confidentiality', value: cvssData.confidentialityImpact, icon: 'fas fa-eye-slash' },
            { label: 'Integrity', value: cvssData.integrityImpact, icon: 'fas fa-shield-alt' },
            { label: 'Availability', value: cvssData.availabilityImpact, icon: 'fas fa-server' }
        ];
        
        impacts.forEach(impact => {
            html += `
                <div class="impact-item">
                    <i class="${impact.icon}"></i>
                    <div>
                        <strong>${impact.label}</strong>
                        <span class="impact-level impact-${impact.value.toLowerCase()}">${impact.value}</span>
                    </div>
                </div>
            `;
        });
    }
    
    html += `
            </div>
            
            <h4>Exploitability Factors</h4>
            <div class="exploit-factors">
    `;
    
    if (cvssData) {
        html += `
            <div class="factor">
                <strong>Attack Vector:</strong> ${cvssData.attackVector}
                <span class="factor-desc">${getAttackVectorDescription(cvssData.attackVector)}</span>
            </div>
            <div class="factor">
                <strong>Attack Complexity:</strong> ${cvssData.attackComplexity}
                <span class="factor-desc">${getAttackComplexityDescription(cvssData.attackComplexity)}</span>
            </div>
            <div class="factor">
                <strong>Privileges Required:</strong> ${cvssData.privilegesRequired}
                <span class="factor-desc">${getPrivilegesDescription(cvssData.privilegesRequired)}</span>
            </div>
        `;
    }
    
    html += '</div></div>';
    
    container.innerHTML = html;
}

function populateMitigationTab(cve) {
    const container = document.getElementById('mitigationInfo');
    
    let html = '<h3>Mitigation and Workarounds</h3>';
    
    // Extract mitigation information from description and references
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
    const patchInfo = extractPatchInfo(description, cve.references);
    
    html += `
        <div class="mitigation-content">
            <h4>Recommended Actions</h4>
            <div class="mitigation-steps">
                <div class="step-item">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong>Immediate Action Required</strong>
                        <p>Assess your environment for the presence of vulnerable versions</p>
                    </div>
                </div>
    `;
    
    if (patchInfo.version) {
        html += `
            <div class="step-item">
                <i class="fas fa-download"></i>
                <div>
                    <strong>Update Available</strong>
                    <p>Upgrade to version ${patchInfo.version} or later</p>
                </div>
            </div>
        `;
    }
    
    html += `
            </div>
            
            <h4>Vendor Resources</h4>
            <div class="vendor-links">
    `;
    
    if (cve.references) {
        cve.references.forEach(ref => {
            const hostname = getHostname(ref.url);
            html += `
                <a href="${ref.url}" target="_blank" class="vendor-link">
                    <i class="fas fa-external-link-alt"></i>
                    ${hostname}
                </a>
            `;
        });
    }
    
    html += '</div></div>';
    
    container.innerHTML = html;
}

function populateAITab(aiAnalysis) {
    const container = document.getElementById('aiAnalysisResult');
    const aiTab = document.getElementById('aiTab');
    
    aiTab.style.display = 'block';
    
    console.log('🔍 DEBUG: AI Analysis received:', aiAnalysis);
    console.log('🔍 DEBUG: Type of aiAnalysis:', typeof aiAnalysis);
    
    // Check if AI analysis is an error
    if (aiAnalysis && aiAnalysis.error) {
        container.innerHTML = `
            <div class="ai-analysis error">
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>AI Analysis Error:</strong> ${aiAnalysis.message}
                </div>
            </div>
        `;
        return;
    }
    
    // Try to parse JSON - handle both string and object with raw_response
    let parsedAnalysis = aiAnalysis;
    
    // If it's an object with a raw_response field, try to parse that first
    if (typeof aiAnalysis === 'object' && aiAnalysis !== null && aiAnalysis.raw_response) {
        console.log('🔍 DEBUG: Found raw_response field, attempting to parse...');
        try {
            const rawContent = aiAnalysis.raw_response.trim();
            console.log('🔍 DEBUG: Raw response first 300 chars:', rawContent.substring(0, 300));
            
            // Clean up the raw response
            let cleanJson = rawContent;
            
            // Remove markdown code blocks
            cleanJson = cleanJson.replace(/^```json\s*/mi, '').replace(/\s*```$/mi, '');
            cleanJson = cleanJson.replace(/^```\s*/mi, '').replace(/\s*```$/mi, '');
            cleanJson = cleanJson.replace(/```json\s*/g, '').replace(/\s*```/g, '');
            
            // Remove quotes and "json" prefix if present
            cleanJson = cleanJson.replace(/^["']json\s*/, '');
            cleanJson = cleanJson.replace(/^json\s*/, '');
            cleanJson = cleanJson.replace(/^["']/, '');
            
            // Remove any leading/trailing whitespace
            cleanJson = cleanJson.trim();
            
            // If it still doesn't start with {, try to find the JSON part
            if (!cleanJson.startsWith('{')) {
                const jsonStart = cleanJson.indexOf('{');
                const jsonEnd = cleanJson.lastIndexOf('}');
                if (jsonStart >= 0 && jsonEnd > jsonStart) {
                    cleanJson = cleanJson.substring(jsonStart, jsonEnd + 1);
                }
            }
            
            console.log('🔍 DEBUG: Cleaned JSON from raw_response first 200 chars:', cleanJson.substring(0, 200));
            
            // Try to parse the cleaned JSON from raw_response
            parsedAnalysis = JSON.parse(cleanJson);
            console.log('✅ DEBUG: Successfully parsed JSON from raw_response with keys:', Object.keys(parsedAnalysis));
        } catch (e) {
            console.error('❌ DEBUG: Failed to parse raw_response:', e);
            // Fall back to using the original object
            console.log('🔄 DEBUG: Falling back to original object structure');
        }
    }
    // Try to parse if it's a string containing JSON
    else if (typeof aiAnalysis === 'string') {
        try {
            // Clean up the string if it has extra wrapper text
            let cleanJson = aiAnalysis.trim();
            
            console.log('🔍 DEBUG: Original string first 300 chars:', cleanJson.substring(0, 300));
            
            // Remove various markdown patterns and prefixes
            cleanJson = cleanJson.replace(/^```json\s*/mi, '').replace(/\s*```$/mi, '');
            cleanJson = cleanJson.replace(/^```\s*/mi, '').replace(/\s*```$/mi, '');
            cleanJson = cleanJson.replace(/```json\s*/g, '').replace(/\s*```/g, '');
            
            // Remove quotes and "json" prefix if present
            cleanJson = cleanJson.replace(/^["']json\s*/, '');
            cleanJson = cleanJson.replace(/^json\s*/, '');
            cleanJson = cleanJson.replace(/^["']/, '');
            
            // Remove any leading/trailing whitespace
            cleanJson = cleanJson.trim();
            
            console.log('🔍 DEBUG: After markdown cleanup first 200 chars:', cleanJson.substring(0, 200));
            
            // If it still doesn't start with {, try to find the JSON part
            if (!cleanJson.startsWith('{')) {
                const jsonStart = cleanJson.indexOf('{');
                const jsonEnd = cleanJson.lastIndexOf('}');
                if (jsonStart >= 0 && jsonEnd > jsonStart) {
                    cleanJson = cleanJson.substring(jsonStart, jsonEnd + 1);
                    console.log('🔍 DEBUG: Extracted JSON substring first 200 chars:', cleanJson.substring(0, 200));
                }
            }
            
            // Try to parse the cleaned JSON
            parsedAnalysis = JSON.parse(cleanJson);
            console.log('✅ DEBUG: Successfully parsed JSON with keys:', Object.keys(parsedAnalysis));
        } catch (e) {
            console.error('❌ DEBUG: Failed to parse JSON:', e);
            console.error('❌ DEBUG: Attempted to parse:', cleanJson.substring(0, 500) + '...');
            console.error('❌ DEBUG: Original raw string:', aiAnalysis.substring(0, 500) + '...');
            
            // Last resort: try to find and extract just the JSON object manually
            try {
                const match = aiAnalysis.match(/\{[\s\S]*\}/);
                if (match) {
                    console.log('🔧 DEBUG: Found JSON match, attempting parse...');
                    parsedAnalysis = JSON.parse(match[0]);
                    console.log('✅ DEBUG: Successfully parsed matched JSON:', Object.keys(parsedAnalysis));
                } else {
                    throw new Error('No JSON object found in response');
                }
            } catch (e2) {
                console.error('❌ DEBUG: Final parsing attempt failed:', e2);
                // Fall back to treating as raw string
                parsedAnalysis = { raw_response: aiAnalysis };
            }
        }
    }
    
    // Handle structured JSON response
    if (typeof parsedAnalysis === 'object' && parsedAnalysis !== null && !parsedAnalysis.error) {
        let html = '<div class="ai-analysis structured">';
        
        // Summary Section
        if (parsedAnalysis.summary) {
            html += `
                <div class="analysis-section">
                    <h3><i class="fas fa-info-circle"></i> Executive Summary</h3>
                    <p class="summary-text">${parsedAnalysis.summary}</p>
                </div>
            `;
        }
        
        // Vulnerability Details Grid
        html += '<div class="analysis-section"><h3><i class="fas fa-bug"></i> Vulnerability Details</h3>';
        html += '<div class="detail-grid">';
        
        if (parsedAnalysis.vulnerability_type) {
            html += `
                <div class="detail-item">
                    <label>Type:</label>
                    <span class="vulnerability-type">${parsedAnalysis.vulnerability_type}</span>
                </div>
            `;
        }
        
        if (parsedAnalysis.affected_software) {
            html += `
                <div class="detail-item">
                    <label>Affected Software:</label>
                    <span>${parsedAnalysis.affected_software}</span>
                </div>
            `;
        }
        
        if (parsedAnalysis.attack_vector) {
            html += `
                <div class="detail-item">
                    <label>Attack Vector:</label>
                    <span class="attack-vector">${parsedAnalysis.attack_vector}</span>
                </div>
            `;
        }
        
        if (parsedAnalysis.attack_complexity) {
            html += `
                <div class="detail-item">
                    <label>Attack Complexity:</label>
                    <span class="attack-complexity">${parsedAnalysis.attack_complexity}</span>
                </div>
            `;
        }
        
        if (parsedAnalysis.exploitation_status) {
            const statusClass = parsedAnalysis.exploitation_status.toLowerCase().replace(/_/g, '-');
            html += `
                <div class="detail-item">
                    <label>Exploitation Status:</label>
                    <span class="exploitation-status status-${statusClass}">${parsedAnalysis.exploitation_status.replace(/_/g, ' ')}</span>
                </div>
            `;
        }
        
        html += '</div></div>'; // Close detail-grid and analysis-section
        
        // Risk Assessment Section
        if (parsedAnalysis.risk_assessment) {
            const risk = parsedAnalysis.risk_assessment;
            html += `
                <div class="analysis-section risk-assessment">
                    <h3><i class="fas fa-exclamation-triangle"></i> Risk Assessment</h3>
                    <div class="risk-grid">
            `;
            
            if (risk.immediate_threat) {
                const threatLevel = risk.immediate_threat.split(' ')[0]; // Get HIGH/MEDIUM/LOW
                html += `
                    <div class="risk-item">
                        <label>Immediate Threat:</label>
                        <span class="threat-level threat-${threatLevel.toLowerCase()}">${risk.immediate_threat}</span>
                    </div>
                `;
            }
            
            if (risk.recommendation) {
                const recClass = risk.recommendation.toLowerCase().replace(/_/g, '-');
                html += `
                    <div class="risk-item">
                        <label>Recommendation:</label>
                        <span class="recommendation rec-${recClass}">${risk.recommendation.replace(/_/g, ' ')}</span>
                    </div>
                `;
            }
            
            if (risk.business_impact) {
                html += `
                    <div class="risk-item full-width">
                        <label>Business Impact:</label>
                        <span>${risk.business_impact}</span>
                    </div>
                `;
            }
            
            if (risk.context_specific_risk) {
                html += `
                    <div class="risk-item full-width">
                        <label>Context-Specific Risk:</label>
                        <span>${risk.context_specific_risk}</span>
                    </div>
                `;
            }
            
            html += '</div></div>'; // Close risk-grid and analysis-section
        }
        
        // Versions Section
        html += '<div class="analysis-section"><h3><i class="fas fa-code-branch"></i> Version Information</h3>';
        html += '<div class="version-grid">';
        
        // Handle vulnerable versions (could be string or array)
        const vulnVersions = Array.isArray(parsedAnalysis.vulnerable_versions) 
            ? parsedAnalysis.vulnerable_versions 
            : parsedAnalysis.vulnerable_versions ? [parsedAnalysis.vulnerable_versions] : [];
            
        if (vulnVersions.length > 0) {
            html += `
                <div class="version-group">
                    <label><i class="fas fa-exclamation-circle text-red"></i> Vulnerable Versions:</label>
                    <div class="version-tags">
                        ${vulnVersions.map(v => `<span class="version-tag vulnerable">${v}</span>`).join('')}
                    </div>
                </div>
            `;
        }
        
        // Handle fixed versions (could be string or array)
        const fixedVersions = Array.isArray(parsedAnalysis.fixed_versions) 
            ? parsedAnalysis.fixed_versions 
            : parsedAnalysis.fixed_versions ? [parsedAnalysis.fixed_versions] : [];
            
        if (fixedVersions.length > 0) {
            html += `
                <div class="version-group">
                    <label><i class="fas fa-check-circle text-green"></i> Fixed Versions:</label>
                    <div class="version-tags">
                        ${fixedVersions.map(v => `<span class="version-tag fixed">${v}</span>`).join('')}
                    </div>
                </div>
            `;
        }
        
        html += '</div></div>'; // Close version-grid and analysis-section
        
        // Mitigation Steps Section
        if (parsedAnalysis.mitigation_steps && Array.isArray(parsedAnalysis.mitigation_steps) && parsedAnalysis.mitigation_steps.length > 0) {
            html += `
                <div class="analysis-section">
                    <h3><i class="fas fa-shield-alt"></i> Mitigation Steps</h3>
                    <ol class="mitigation-steps">
            `;
            
            parsedAnalysis.mitigation_steps.forEach(step => {
                html += `<li class="mitigation-step">${step}</li>`;
            });
            
            html += '</ol></div>';
        }
        
        // Raw response fallback if available
        if (parsedAnalysis.raw_response) {
            html += `
                <div class="analysis-section">
                    <details class="raw-response">
                        <summary>View Raw Analysis</summary>
                        <div class="raw-content">${parsedAnalysis.raw_response}</div>
                    </details>
                </div>
            `;
        }
        
        html += '</div>'; // Close ai-analysis
        container.innerHTML = html;
        
    } else {
        // Handle legacy string format or fallback
        let formattedAnalysis = (aiAnalysis || parsedAnalysis || '').toString();
        
        // Convert markdown-like formatting to HTML
        formattedAnalysis = formattedAnalysis
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n- /g, '</p><ul><li>')
            .replace(/\n(\d+)\. /g, '</p><ol><li>');
        
        container.innerHTML = `<div class="ai-analysis legacy"><p>${formattedAnalysis}</p></div>`;
    }
}

function populateSidebar(cve, data) {
    // Enhanced CVSS Score handling - check multiple sources
    const cvssInfo = getBestCVSSScore(cve.metrics);
    if (cvssInfo) {
        updateCVSSScore(cvssInfo.score, cvssInfo.severity, cvssInfo.source, cvssInfo.version);
    }
    
    // EPSS Data
    if (data.epss?.data?.[0]) {
        const epss = data.epss.data[0];
        document.getElementById('epssScore').textContent = (parseFloat(epss.epss) * 100).toFixed(3) + '%';
        document.getElementById('epssPercentile').textContent = (parseFloat(epss.percentile) * 100).toFixed(1) + '%';
    }
    
    // KEV Status
    const kevStatus = document.getElementById('kevStatus');
    const kevText = document.getElementById('kevText');
    const kevDetails = document.getElementById('kevDetails');
    const statusIndicator = document.querySelector('.status-indicator');
    
    if (data.kev) {
        statusIndicator.classList.add('active');
        kevText.textContent = 'Listed in KEV catalog';
        kevDetails.style.display = 'block';
        document.getElementById('kevDueDate').textContent = formatDate(data.kev.dueDate);
    }
    
    // Component Context
    if (data.component) {
        const componentCard = document.getElementById('componentCard');
        const componentInfo = document.getElementById('componentInfo');
        
        componentCard.style.display = 'block';
        componentInfo.innerHTML = `
            <h4>${data.component.name}</h4>
            <p>${data.component.description}</p>
        `;
    }
    
    // GitHub Advisory
    if (data.github) {
        const githubLink = document.getElementById('githubLink');
        githubLink.style.display = 'block';
        githubLink.onclick = () => {
            window.open(data.github.html_url, '_blank');
        };
    }
}

function getBestCVSSScore(metrics) {
    if (!metrics) return null;
    
    // Priority order: CVSS v4.0 > CVSS v3.1 Primary > CVSS v3.1 Secondary > CVSS v3.0 > CVSS v2.0
    const priorities = [
        { key: 'cvssMetricV40', version: 'CVSS v4.0', typeFilter: null },
        { key: 'cvssMetricV31', version: 'CVSS v3.1', typeFilter: 'Primary' },
        { key: 'cvssMetricV31', version: 'CVSS v3.1', typeFilter: 'Secondary' },
        { key: 'cvssMetricV30', version: 'CVSS v3.0', typeFilter: null },
        { key: 'cvssMetricV2', version: 'CVSS v2.0', typeFilter: null }
    ];
    
    for (const priority of priorities) {
        const metricArray = metrics[priority.key];
        
        if (metricArray && metricArray.length > 0) {
            // Filter by type if specified, otherwise take first available
            let metric = priority.typeFilter 
                ? metricArray.find(m => m.type === priority.typeFilter)
                : metricArray[0];
            
            // If no Primary found, fall back to any available
            if (!metric && priority.typeFilter === 'Primary') {
                metric = metricArray[0];
            }
            
            if (metric && metric.cvssData) {
                const cvssData = metric.cvssData;
                let source = 'NVD';
                
                // Determine source
                if (metric.type === 'Secondary' || (metric.source && metric.source !== 'nvd@nist.gov')) {
                    source = metric.source || 'Third Party';
                    // Clean up source display
                    if (source.includes('@')) {
                        source = 'Third Party';
                    }
                }
                
                return {
                    score: cvssData.baseScore,
                    severity: cvssData.baseSeverity,
                    version: priority.version,
                    source: source,
                    type: metric.type || 'Primary'
                };
            }
        }
    }
    
    return null;
}

function updateCVSSScore(score, severity, source = 'NVD', version = 'CVSS v3.1') {
    const scoreElement = document.getElementById('cvssScore');
    const severityBadge = document.getElementById('severityBadge');
    const scoreCircle = document.getElementById('scoreCircle');
    
    // Update the score header to show source info
    const scoreHeader = document.querySelector('.score-card h3');
    if (source !== 'NVD' || version !== 'CVSS v3.1') {
        scoreHeader.innerHTML = `CVSS Score <small>(${version} - ${source})</small>`;
        scoreHeader.querySelector('small').style.cssText = 'font-size: 0.75rem; color: #64748b; font-weight: 400;';
    } else {
        scoreHeader.textContent = 'CVSS Score';
    }
    
    scoreElement.textContent = score.toFixed(1);
    
    // Update severity badge
    severityBadge.textContent = severity;
    severityBadge.className = `severity-badge severity-${severity.toLowerCase()}`;
    
    // Update circular progress
    const circumference = 2 * Math.PI * 52; // r = 52
    const offset = circumference - (score / 10) * circumference;
    
    // Set stroke color based on severity
    const colors = {
        'LOW': '#65a30d',
        'MEDIUM': '#d97706',
        'HIGH': '#ea580c',
        'CRITICAL': '#dc2626'
    };
    
    scoreCircle.style.stroke = colors[severity] || '#64748b';
    scoreCircle.style.strokeDasharray = `${circumference} ${circumference}`;
    scoreCircle.style.strokeDashoffset = offset;
}

function switchTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(tabName).classList.add('active');
}

function showError(message) {
    const errorMessage = document.getElementById('errorMessage');
    errorMessage.textContent = message;
    errorContainer.style.display = 'block';
}

function hideError() {
    errorContainer.style.display = 'none';
}

function hideResults() {
    resultsContainer.style.display = 'none';
}

// Utility functions
function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

function getHostname(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

function extractTechnologies(cve) {
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
    const technologies = new Set();
    
    // Common technology patterns
    const patterns = [
        /\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(?:library|framework|application|software|package)/gi,
        /\b(Python|Java|JavaScript|Node\.js|React|Angular|Vue|Docker|Kubernetes|nginx|Apache|PHP|Ruby|Go|Rust|C\+\+|C#|\.NET)/gi
    ];
    
    patterns.forEach(pattern => {
        const matches = description.match(pattern);
        if (matches) {
            matches.forEach(match => technologies.add(match.trim()));
        }
    });
    
    return Array.from(technologies).slice(0, 5); // Limit to 5 technologies
}

function extractPatchInfo(description, references) {
    const info = { version: null, links: [] };
    
    // Extract version information
    const versionMatch = description.match(/version\s+([0-9.]+)/i);
    if (versionMatch) {
        info.version = versionMatch[1];
    }
    
    // Filter patch-related references
    if (references) {
        info.links = references.filter(ref => 
            ref.url.includes('patch') || 
            ref.url.includes('fix') || 
            ref.url.includes('advisory')
        );
    }
    
    return info;
}

function getAttackVectorDescription(vector) {
    const descriptions = {
        'NETWORK': 'Remotely exploitable over a network',
        'ADJACENT_NETWORK': 'Exploitable from adjacent network',
        'LOCAL': 'Requires local access',
        'PHYSICAL': 'Requires physical access'
    };
    return descriptions[vector] || '';
}

function getAttackComplexityDescription(complexity) {
    const descriptions = {
        'LOW': 'Easy to exploit',
        'HIGH': 'Difficult to exploit consistently'
    };
    return descriptions[complexity] || '';
}

function getPrivilegesDescription(privileges) {
    const descriptions = {
        'NONE': 'No authentication required',
        'LOW': 'Basic user privileges required',
        'HIGH': 'Administrative privileges required'
    };
    return descriptions[privileges] || '';
}
