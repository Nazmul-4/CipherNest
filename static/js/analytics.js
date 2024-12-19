// Analytics JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize analytics dashboard
    initializeAnalytics();
    
    // Set up refresh button if exists
    const refreshBtn = document.getElementById('refresh-analytics');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', initializeAnalytics);
    }
});

async function initializeAnalytics() {
    try {
        // Fetch all analytics data in parallel
        const [
            strengthData,
            reuseData,
            remindersData,
            vulnerabilityData,
            monthlyData
        ] = await Promise.all([
            fetch('/api/analytics/password-strength').then(r => r.json()),
            fetch('/api/analytics/reuse-analysis').then(r => r.json()),
            fetch('/api/analytics/update-reminders').then(r => r.json()),
            fetch('/api/analytics/vulnerability-rating').then(r => r.json()),
            fetch('/api/analytics/monthly-report').then(r => r.json())
        ]);
        
        // Update all sections
        updateStrengthDistribution(strengthData);
        updateReuseAnalysis(reuseData);
        updateUpdateReminders(remindersData);
        updateVulnerabilityRating(vulnerabilityData);
        updateMonthlyReport(monthlyData);
        
    } catch (error) {
        console.error('Error initializing analytics:', error);
        showError('Failed to load analytics data');
    }
}

function updateStrengthDistribution(data) {
    const strengthChart = document.querySelector('.strength-distribution');
    if (!strengthChart) return;
    
    // Calculate percentages
    const total = data.total_passwords;
    const distribution = data.strength_distribution;
    
    // Update chart
    strengthChart.innerHTML = `
        <h3>Password Strength Distribution</h3>
        <div class="chart-container">
            ${Object.entries(distribution).map(([category, count]) => `
                <div class="chart-bar ${category.toLowerCase()}">
                    <div class="bar-fill" style="height: ${(count/total*100)}%">
                        <span class="bar-label">${category}</span>
                        <span class="bar-value">${count}</span>
                    </div>
                </div>
            `).join('')}
        </div>
        <p class="total-passwords">Total Passwords: ${total}</p>
    `;
}

function updateReuseAnalysis(data) {
    const reuseSection = document.querySelector('.reuse-analysis');
    if (!reuseSection) return;
    
    const reusedPasswords = data.reused_passwords;
    
    reuseSection.innerHTML = `
        <h3>Password Reuse Analysis</h3>
        ${reusedPasswords.length > 0 ? `
            <div class="reuse-list">
                ${reusedPasswords.map(item => `
                    <div class="reuse-item">
                        <div class="reuse-header">
                            <span class="reuse-count">Used ${item.count} times</span>
                        </div>
                        <div class="reuse-websites">
                            ${item.websites.map(site => `
                                <span class="website-tag">${site}</span>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        ` : '<p class="no-reuse">No password reuse detected! 🎉</p>'}
    `;
}

function updateUpdateReminders(data) {
    const remindersSection = document.querySelector('.update-reminders');
    if (!remindersSection) return;
    
    const oldPasswords = data.passwords_to_update;
    
    remindersSection.innerHTML = `
        <h3>Password Update Reminders</h3>
        ${oldPasswords.length > 0 ? `
            <div class="reminders-list">
                ${oldPasswords.map(pwd => `
                    <div class="reminder-item">
                        <span class="website">${pwd.website}</span>
                        <span class="last-updated">Last updated: ${formatDate(pwd.last_updated)}</span>
                        <button class="update-btn" onclick="initiatePasswordUpdate('${pwd.website}')">
                            Update Now
                        </button>
                    </div>
                `).join('')}
            </div>
        ` : '<p class="no-reminders">All passwords are up to date! 🎉</p>'}
    `;
}

function updateVulnerabilityRating(data) {
    const vulnerabilitySection = document.querySelector('.vulnerability-rating');
    if (!vulnerabilitySection) return;
    
    const score = data.vulnerability_score;
    const metrics = data.metrics;
    
    vulnerabilitySection.innerHTML = `
        <h3>Account Vulnerability Rating</h3>
        <div class="score-circle">
            <svg viewBox="0 0 36 36">
                <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                      fill="none" 
                      stroke="#E5E7EB" 
                      stroke-width="3"/>
                <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                      fill="none" 
                      stroke="${getScoreColor(score)}" 
                      stroke-width="3" 
                      stroke-dasharray="${score}, 100"/>
            </svg>
            <div class="score-text">
                <span class="score-value">${score}</span>
                <span class="score-label">Security Score</span>
            </div>
        </div>
        <div class="metrics-grid">
            ${Object.entries(metrics).map(([key, value]) => `
                <div class="metric-item">
                    <span class="metric-label">${formatMetricName(key)}</span>
                    <span class="metric-value">${value}%</span>
                </div>
            `).join('')}
        </div>
    `;
}

function updateMonthlyReport(data) {
    const monthlySection = document.querySelector('.monthly-report');
    if (!monthlySection) return;
    
    const activity = data.monthly_activity;
    const status = data.security_status;
    
    monthlySection.innerHTML = `
        <h3>Monthly Security Report</h3>
        <div class="report-date">Report Date: ${formatDate(data.report_date)}</div>
        
        <div class="monthly-activity">
            <h4>Monthly Activity</h4>
            <div class="activity-grid">
                <div class="activity-item">
                    <span class="activity-label">New Passwords</span>
                    <span class="activity-value">${activity.new_passwords}</span>
                </div>
                <div class="activity-item">
                    <span class="activity-label">Updated Passwords</span>
                    <span class="activity-value">${activity.updated_passwords}</span>
                </div>
            </div>
        </div>
        
        <div class="security-status">
            <h4>Current Security Status</h4>
            <div class="status-grid">
                <div class="status-item">
                    <span class="status-label">Total Passwords</span>
                    <span class="status-value">${status.total_passwords}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Average Strength</span>
                    <span class="status-value">${status.average_strength}%</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Strong Passwords</span>
                    <span class="status-value">${status.strong_passwords}</span>
                </div>
                <div class="status-item ${status.weak_passwords > 0 ? 'warning' : ''}">
                    <span class="status-label">Weak Passwords</span>
                    <span class="status-value">${status.weak_passwords}</span>
                </div>
            </div>
        </div>
        
        ${data.recommendations.length > 0 ? `
            <div class="recommendations">
                <h4>Recommendations</h4>
                <ul>
                    ${data.recommendations.map(rec => `
                        <li>${rec}</li>
                    `).join('')}
                </ul>
            </div>
        ` : ''}
    `;
}

// Utility functions
function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function formatMetricName(metric) {
    return metric.split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

function getScoreColor(score) {
    if (score >= 80) return '#10B981'; // Green
    if (score >= 60) return '#FBBF24'; // Yellow
    return '#EF4444'; // Red
}

function initiatePasswordUpdate(website) {
    // Redirect to password update page or show modal
    window.location.href = `/vault/update?website=${encodeURIComponent(website)}`;
}

function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.textContent = message;
    
    document.body.appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 5000);
}
