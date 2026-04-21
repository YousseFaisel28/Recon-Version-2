/**
 * Extracted data handling logic for the new ReconX dashboard.
 * Connects to /get_history and fetches detailed metrics using /get_report to populate dynamic fields.
 */

document.addEventListener("DOMContentLoaded", () => {
  initDashboard();

  // Make sure Chart.js reacts to dark mode toggle for its font colors
  const darkModeBtn = document.getElementById('darkModeToggle');
  if (darkModeBtn) {
    darkModeBtn.addEventListener('click', () => {
      setTimeout(() => {
        const isDark = document.documentElement.classList.contains('dark');
        Chart.defaults.color = isDark ? '#9CA3AF' : '#6B7280';
        Chart.instances.forEach(chart => {
          if (chart.options.scales?.y?.grid) {
            chart.options.scales.y.grid.color = isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';
          }
          chart.update();
        });
      }, 50); // slight delay after class toggle
    });
  }
});

async function initDashboard() {
  const sysStatusDot = document.getElementById('system-status-dot');
  const sysStatusText = document.getElementById('system-status-text');
  
  sysStatusDot.className = 'status-dot loading';
  sysStatusText.textContent = 'Fetching data...';

  try {
    const resp = await fetch('/get_history');
    if (resp.status === 401) {
      window.location.href = '/login';
      return;
    }
    if (!resp.ok) throw new Error('Failed to load history');

    const data = await resp.json();
    const history = data.history || [];

    // Compute basic metrics from history
    const totalScansCompleted = history.length;
    
    const uniqueDomains = new Set();
    const dateCounts = {}; // Date format YYYY-MM-DD to Count
    
    // Default last 7 days chart array prep
    const activityLabels = [];
    const activityData = [];
    
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        const dStr = d.toISOString().split('T')[0];
        dateCounts[dStr] = 0;
    }
    
    history.forEach(item => {
      if (item.domain) uniqueDomains.add(item.domain);
      if (item.scanned_at) {
         const dStr = new Date(item.scanned_at).toISOString().split('T')[0];
         if (dateCounts[dStr] !== undefined) {
             dateCounts[dStr]++;
         }
      }
    });

    for (let dStr in dateCounts) {
        // Format label as Short Day (e.g., 'Mon')
        const d = new Date(dStr);
        activityLabels.push(d.toLocaleDateString("en-US", { weekday: 'short' }));
        activityData.push(dateCounts[dStr]);
    }

    removeSkeletonText('scans', totalScansCompleted);
    removeSkeletonText('visitors', uniqueDomains.size);

    // FETCH LATEST 10 REPORTS to average risk and get vulnerability breakdown
    const fetchLimit = Math.min(10, history.length);
    const recentHistory = history.slice(0, fetchLimit);
    
    let totalVulns = 0;
    let totalRiskScoreSum = 0;
    let riskCount = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    
    // We will build the most recent 3 Table rows
    const tableBody = [];

    // Fetch in parallel for speed
    const reportPromises = recentHistory.map(record => 
        fetch(`/get_report?report_id=${record.report_id}`)
          .then(res => res.ok ? res.json() : null)
          .catch(() => null) // Ignore errors so one fail doesn't break all
    );

    const reportsData = await Promise.all(reportPromises);

    for (let i = 0; i < reportsData.length; i++) {
        const reportVal = reportsData[i];
        const record = recentHistory[i];
        let maxSeverity = "Low"; 

        if (reportVal && reportVal.result) {
            const model6 = reportVal.result.model6 || [];
            totalVulns += model6.length;
            
            model6.forEach(v => {
                const cvss = v.cvss_score || v.cvss || 0;
                totalRiskScoreSum += cvss;
                
                const sev = v.risk_level || determineSeverity(cvss);
                if (sev === "Critical") riskCount.Critical++;
                else if (sev === "High") riskCount.High++;
                else if (sev === "Medium") riskCount.Medium++;
                else riskCount.Low++;
            });

            if (riskCount.Critical > 0 || model6.some(v => (v.risk_level || determineSeverity(v.cvss_score || v.cvss)) === "Critical")) maxSeverity = "Critical";
            else if (riskCount.High > 0 || model6.some(v => (v.risk_level || determineSeverity(v.cvss_score || v.cvss)) === "High")) maxSeverity = "High";
            else if (riskCount.Medium > 0 || model6.some(v => (v.risk_level || determineSeverity(v.cvss_score || v.cvss)) === "Medium")) maxSeverity = "Medium";
        } else {
             maxSeverity = "--"; // failed to fetch or empty
        }

        // Only add up to top 3 logic for tables
        if (i < 3) {
            tableBody.push(`
              <tr class="hover:bg-gray-50 dark:hover:bg-white/5 transition-colors">
                <td class="px-6 py-4">
                  <div class="flex items-center gap-3">
                    <div class="p-2 bg-gray-100 dark:bg-white/10 rounded-md"><i class="ph ph-globe text-gray-500 dark:text-gray-300"></i></div>
                    <span class="font-medium text-sm text-gray-800 dark:text-white">${escapeHtml(record.domain)}</span>
                  </div>
                </td>
                <td class="px-6 py-4">
                  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 border border-green-200 dark:border-green-800">
                    Completed
                  </span>
                </td>
                <td class="px-6 py-4">
                  <div class="flex items-center gap-2">
                    ${getRiskDot(maxSeverity)}
                    <span class="text-sm dark:text-gray-200">${maxSeverity}</span>
                  </div>
                </td>
                <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">${timeAgo(new Date(record.scanned_at))}</td>
                <td class="px-6 py-4 text-right">
                  <a href="report.html?report_id=${record.report_id}" class="text-sm font-medium text-cyber-accent hover:underline">View Report</a>
                </td>
              </tr>
            `);
        }
    }

    // Finalize metrics calculation
    const overallRiskAvg = totalVulns > 0 ? (totalRiskScoreSum / totalVulns).toFixed(1) : 0;
    
    removeSkeletonText('vulnerabilities-count', totalVulns);
    removeSkeletonText('rating', overallRiskAvg + '<span class="text-xs text-gray-500 font-normal ml-1">/ 10</span>');

    document.getElementById('legend-critical').innerText = riskCount.Critical;
    document.getElementById('legend-high').innerText = riskCount.High;
    document.getElementById('legend-medium').innerText = riskCount.Medium;
    document.getElementById('legend-low').innerText = riskCount.Low;
    document.getElementById('risk-total').innerText = totalVulns;

    // Render Recent Table
    const tbody = document.getElementById('recent-scans-body');
    if (tableBody.length > 0) {
        tbody.innerHTML = tableBody.join('');
    } else {
        tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center text-sm text-gray-500">No recent scans found. Initialize a scan to populate data.</td></tr>`;
    }
    document.getElementById('recent-scans-loader').classList.add('hidden');

    // Chart.js renderers
    renderActivityChart(activityLabels, activityData);
    renderRiskChart([riskCount.Critical, riskCount.High, riskCount.Medium, riskCount.Low]);
    
    // Status back to green
    sysStatusDot.className = 'status-dot';
    sysStatusText.textContent = 'System Operational';

  } catch (err) {
    console.error(err);
    sysStatusDot.className = 'status-dot error';
    sysStatusText.textContent = 'System Degraded';
  }
}

// ------------------------------------
// UI Render Helpers
// ------------------------------------
function removeSkeletonText(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('skeleton', 'w-16', 'h-9');
    el.innerHTML = value;
}

function getRiskDot(severity) {
    if (severity === 'Critical') return '<div class="w-2 h-2 rounded-full bg-red-500"></div>';
    if (severity === 'High') return '<div class="w-2 h-2 rounded-full bg-orange-500"></div>';
    if (severity === 'Medium') return '<div class="w-2 h-2 rounded-full bg-yellow-500"></div>';
    if (severity === 'Low') return '<div class="w-2 h-2 rounded-full bg-green-500"></div>';
    return '<div class="w-2 h-2 rounded-full bg-gray-400"></div>';
}

function determineSeverity(score) {
    // simplified from backend
    if (score >= 9.0) return "Critical";
    if (score >= 7.0) return "High";
    if (score >= 4.0) return "Medium";
    return "Low";
}

function renderActivityChart(labels, data) {
    document.getElementById('activityChart-skeleton').classList.add('hidden');
    const canvas = document.getElementById('activityChart');
    canvas.classList.remove('hidden');
    
    const ctx = canvas.getContext('2d');
    Chart.defaults.color = document.documentElement.classList.contains('dark') ? '#9CA3AF' : '#6B7280';
    Chart.defaults.font.family = 'Inter, sans-serif';

    const gradientPrimary = ctx.createLinearGradient(0, 0, 0, 300);
    gradientPrimary.addColorStop(0, 'rgba(16, 185, 129, 0.4)'); // Teal transparent
    gradientPrimary.addColorStop(1, 'rgba(16, 185, 129, 0)');

    new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Scans Initiated',
          data: data,
          borderColor: '#10B981',
          backgroundColor: gradientPrimary,
          borderWidth: 2,
          tension: 0.4,
          fill: true,
          pointBackgroundColor: '#10B981',
          pointBorderColor: '#fff',
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(17, 24, 39, 0.9)',
            titleColor: '#fff',
            bodyColor: '#fff',
            padding: 10,
            cornerRadius: 8,
            displayColors: false
          }
        },
        scales: {
          x: { grid: { display: false, drawBorder: false } },
          y: {
            grid: {
              color: document.documentElement.classList.contains('dark') ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)',
              drawBorder: false
            },
            beginAtZero: true,
            ticks: { stepSize: 1, precision: 0 }
          }
        }
      }
    });
}

function renderRiskChart(dataArr) {
    document.getElementById('riskChart-skeleton').classList.add('hidden');
    const canvas = document.getElementById('riskChart');
    canvas.classList.remove('hidden');
    document.getElementById('riskChart-overlay').classList.remove('hidden');
    document.getElementById('riskChart-overlay').classList.add('flex');
    
    const ctx = canvas.getContext('2d');
    
    // Check if empty, populate with minimal gray to not break Chart formatting entirely
    let finalData = dataArr;
    let bgColors = ['#EF4444', '#F97316', '#EAB308', '#22C55E'];
    if (dataArr.every(x => x === 0)) {
        finalData = [1];
        bgColors = ['rgba(156, 163, 175, 0.2)']; // Gray donut
    }

    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: finalData.length === 1 ? ['No Data'] : ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: finalData,
          backgroundColor: bgColors,
          borderWidth: 0,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '80%',
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(17, 24, 39, 0.9)',
            padding: 10,
            cornerRadius: 8,
            callbacks: {
                label: function(context) {
                    if (context.label === 'No Data') return ' No Vulnerabilities Found';
                    return ' ' + context.label + ': ' + context.formattedValue;
                }
            }
          }
        }
      }
    });
}

// ------------------------------------
// Utilities
// ------------------------------------
function escapeHtml(text) {
    if (!text) return "";
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function timeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    let interval = seconds / 31536000;
    if (interval > 1) return Math.floor(interval) + " years ago";
    interval = seconds / 2592000;
    if (interval > 1) return Math.floor(interval) + " months ago";
    interval = seconds / 86400;
    if (interval > 1) return Math.floor(interval) + " days ago";
    interval = seconds / 3600;
    if (interval > 1) return Math.floor(interval) + " hours ago";
    interval = seconds / 60;
    if (interval > 1) return Math.floor(interval) + " minutes ago";
    return Math.floor(seconds) + " seconds ago";
}
