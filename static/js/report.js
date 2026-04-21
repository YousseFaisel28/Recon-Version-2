document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(window.location.search);
  const domain = params.get("domain");
  const reportId = params.get("report_id");
  const domainTitle = document.getElementById("domain-title");
  const reportContent = document.getElementById("report-content");

  /* ===============================
     CHART REGISTRY (PREVENT OVERLAP)
  =============================== */
  const chartRegistry = {};

  /* ===============================
     VALIDATION
  =============================== */
  if (!domain && !reportId) {
    reportContent.innerHTML = `
      <div class="glass-card p-8 flex flex-col justify-center items-center text-center">
        <i class="ph ph-warning-circle text-4xl text-red-500 mb-4"></i>
        <h3 class="text-xl font-bold mb-2">No Report Specified</h3>
        <p class="text-gray-500">Please provide a valid domain or report ID to view the assessment.</p>
      </div>`;
    return;
  }

  domainTitle.textContent = domain ? `${domain}` : "Loading Target...";

  /* ===============================
     HELPERS
  =============================== */
  function getSeverityColor(sevStr) {
    const s = sevStr ? sevStr.toLowerCase() : '';
    if (s.includes('critical')) return 'text-red-500 bg-red-500/10 border-red-500/20';
    if (s.includes('high')) return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
    if (s.includes('medium')) return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
    if (s.includes('low')) return 'text-green-500 bg-green-500/10 border-green-500/20';
    return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
  }

  function getRiskDot(severity) {
    const s = severity ? severity.toLowerCase() : '';
    if (s.includes('critical')) return '<div class="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse"></div>';
    if (s.includes('high')) return '<div class="w-2.5 h-2.5 rounded-full bg-orange-500"></div>';
    if (s.includes('medium')) return '<div class="w-2.5 h-2.5 rounded-full bg-yellow-500"></div>';
    if (s.includes('low')) return '<div class="w-2.5 h-2.5 rounded-full bg-green-500"></div>';
    return '<div class="w-2.5 h-2.5 rounded-full bg-gray-400"></div>';
  }

  /* ===============================
     FETCH REPORT
  =============================== */
  try {
    let fetchUrl = "";
    if (reportId) {
      fetchUrl = `/get_report?report_id=${encodeURIComponent(reportId)}`;
    } else {
      fetchUrl = `/get_report?domain=${encodeURIComponent(domain)}`;
    }

    const resp = await fetch(fetchUrl);
    if (resp.status === 401 || resp.status === 403) {
      reportContent.innerHTML = `
        <div class="glass-card p-8 flex flex-col justify-center items-center text-center">
          <i class="ph ph-lock-key text-4xl text-orange-500 mb-4"></i>
          <h3 class="text-xl font-bold mb-2">Unauthorized</h3>
          <p class="text-gray-500">You must be logged in to view this intelligence report.</p>
        </div>`;
      return;
    }
    if (!resp.ok) throw new Error("Failed to load report");

    const data = await resp.json();

    // ── DEBUG: log the full structure so we can see what the API returns ──
    console.group("ReconX Report Debug");
    console.log("Top-level keys:", Object.keys(data));
    console.log("total_candidates (top):", data.total_candidates);
    console.log("result keys:", data.result ? Object.keys(data.result) : "NO RESULT");
    if (data.result) {
      console.log("raw_docs count:", (data.result.raw_docs || []).length);
      console.log("total_candidates (result):", data.result.total_candidates);
      console.log("resolved (result):", data.result.resolved);
      console.log("tech_fingerprints count:", (data.result.technology_fingerprints || []).length);
      console.log("model6 count:", (data.result.model6 || []).length);
    }
    console.groupEnd();

    if (data.domain) {
      domainTitle.textContent = `${data.domain}`;
    }

    if (!data.result) {
      reportContent.innerHTML = `
        <div class="glass-card p-12 flex flex-col justify-center items-center text-center">
          <div class="w-20 h-20 bg-gray-100 dark:bg-white/5 rounded-full flex items-center justify-center text-4xl text-gray-400 mb-6">
            <i class="ph-bold ph-shield-slash"></i>
          </div>
          <h3 class="text-xl font-bold mb-2">No Report Found</h3>
          <p class="text-gray-500">No active vulnerability assessment found for this target.</p>
        </div>`;
      return;
    }

    const r = data.result;

    /* ===============================
       METRICS CALCULATION
    =============================== */
    // Subdomain count — cascade through every available field
    const totalSubdomains =
      (r.raw_docs && r.raw_docs.length > 0)                 ? r.raw_docs.length        :
      (r.total_candidates  && r.total_candidates  > 0)      ? r.total_candidates        :
      (data.total_candidates && data.total_candidates > 0)  ? data.total_candidates     :
      (r.resolved          && r.resolved          > 0)      ? r.resolved                : 0;

    const model6Data = r.model6 || [];
    const totalVulnerabilities = model6Data.length;

    // Also count CVEs from tech fingerprints as a secondary vuln indicator
    let techCveCount = 0;
    (r.technology_fingerprints || []).forEach(tf => {
      (tf.technologies || []).forEach(t => {
        techCveCount += (t.cves || []).length;
      });
    });
    const displayVulns = totalVulnerabilities || techCveCount;

    let criticalCount = 0;
    let highCount = 0;

    model6Data.forEach(vuln => {
        const severity = ((vuln.risk_level || vuln.severity || "")).toLowerCase();
        if (severity === "critical") criticalCount++;
        else if (severity === "high") highCount++;
    });

    // If model6 is empty, fall back to CVSS-based counting from tech fingerprints
    if (!model6Data.length) {
      (r.technology_fingerprints || []).forEach(tf => {
        (tf.technologies || []).forEach(t => {
          (t.cves || []).forEach(cve => {
            const cvss = parseFloat(cve.cvss || 0);
            const sev  = (cve.severity || "").toLowerCase();
            if (sev === "critical" || cvss >= 9.0) criticalCount++;
            else if (sev === "high"     || cvss >= 7.0) highCount++;
          });
        });
      });
    }

    /* ===============================
       1. SUMMARY CARDS
    =============================== */
    const summaryCardsHTML = `
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6 mb-8">
        <!-- Subdomains -->
        <div class="glass-card p-5 flex flex-col justify-between relative overflow-hidden group">
          <div class="absolute right-0 top-0 w-24 h-24 bg-blue-500/5 rounded-bl-full group-hover:bg-blue-500/10 transition-colors"></div>
          <div class="flex items-start justify-between mb-2">
            <div class="w-10 h-10 rounded-xl bg-blue-100 dark:bg-blue-500/10 flex items-center justify-center text-blue-600 text-xl shadow-sm">
              <i class="ph-fill ph-target"></i>
            </div>
          </div>
          <div class="mt-2 text-3xl font-bold">${totalSubdomains}</div>
          <div class="text-gray-500 dark:text-gray-400 text-xs font-semibold uppercase tracking-wider mt-1">Total Subdomains</div>
        </div>
        
        <!-- Total Vulns -->
        <div class="glass-card p-5 flex flex-col justify-between relative overflow-hidden group">
          <div class="absolute right-0 top-0 w-24 h-24 bg-purple-500/5 rounded-bl-full group-hover:bg-purple-500/10 transition-colors"></div>
          <div class="flex items-start justify-between mb-2">
            <div class="w-10 h-10 rounded-xl bg-purple-100 dark:bg-purple-500/10 flex items-center justify-center text-purple-600 text-xl shadow-sm">
              <i class="ph-fill ph-bug"></i>
            </div>
          </div>
          <div class="mt-2 text-3xl font-bold">${displayVulns}</div>
          <div class="text-gray-500 dark:text-gray-400 text-xs font-semibold uppercase tracking-wider mt-1">Vulnerabilities Found</div>
        </div>

        <!-- Critical -->
        <div class="glass-card p-5 flex flex-col justify-between relative overflow-hidden group">
          <div class="absolute right-0 top-0 w-24 h-24 bg-red-500/5 rounded-bl-full group-hover:bg-red-500/10 transition-colors"></div>
          <div class="flex items-start justify-between mb-2">
            <div class="w-10 h-10 rounded-xl bg-red-100 dark:bg-red-500/10 flex items-center justify-center text-red-600 text-xl shadow-sm">
              <i class="ph-fill ph-warning-octagon"></i>
            </div>
          </div>
          <div class="mt-2 text-3xl font-bold text-red-500">${criticalCount}</div>
          <div class="text-gray-500 dark:text-gray-400 text-xs font-semibold uppercase tracking-wider mt-1">Critical Issues</div>
        </div>

        <!-- High -->
        <div class="glass-card p-5 flex flex-col justify-between relative overflow-hidden group">
          <div class="absolute right-0 top-0 w-24 h-24 bg-orange-500/5 rounded-bl-full group-hover:bg-orange-500/10 transition-colors"></div>
          <div class="flex items-start justify-between mb-2">
            <div class="w-10 h-10 rounded-xl bg-orange-100 dark:bg-orange-500/10 flex items-center justify-center text-orange-600 text-xl shadow-sm">
              <i class="ph-fill ph-fire"></i>
            </div>
          </div>
          <div class="mt-2 text-3xl font-bold text-orange-500">${highCount}</div>
          <div class="text-gray-500 dark:text-gray-400 text-xs font-semibold uppercase tracking-wider mt-1">High Risk Issues</div>
        </div>
      </div>
    `;

    /* ===============================
       2. TOPOLOGY CLUSTERS (Model 1 & 2)
    =============================== */
    const portMap = {};
    r.raw_docs?.forEach(doc => {
      portMap[doc.subdomain] = doc.open_ports || [];
    });

    let clustersHTML = "";
    if (r.clusters && r.clusters.length > 0) {
      clustersHTML = `
        <div class="report-section">
          <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
            <i class="ph-bold ph-graph text-blue-500"></i> Discovered Target Clusters
          </h2>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            ${r.clusters.map(c => {
        const items = (c.examples || []).map(sub => {
          const ports = portMap[sub] || [];
          const portTags = ports.length 
            ? ports.map(p => `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-white/5 border border-white/10 dark:text-gray-300 mr-1">${p.port}/${p.service}</span>`).join('') 
            : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-gray-100 text-gray-500 dark:bg-white/5 dark:text-gray-400 mr-1">No Open Ports</span>`;
          return `
            <div class="flex items-center justify-between p-2 hover:bg-black/5 dark:hover:bg-white/5 rounded-lg transition-colors border-b border-gray-100 dark:border-white/5 last:border-0 border-dashed">
              <span class="text-sm font-medium text-gray-800 dark:text-gray-200 truncate w-1/2" title="${sub}">${sub}</span>
              <div class="flex flex-wrap justify-end gap-1 shrink-0">${portTags}</div>
            </div>`;
        }).join("");

        return `
          <details class="glass-card group [&_summary::-webkit-details-marker]:hidden bg-white/40 dark:bg-black/20" open>
            <summary class="flex items-center justify-between px-4 py-3 cursor-pointer bg-gray-50 dark:bg-white/5 rounded-xl group-open:rounded-b-none transition-colors">
              <div class="flex items-center gap-3">
                <i class="ph ph-caret-down text-gray-400 group-open:rotate-180 transition-transform"></i>
                <span class="font-semibold text-gray-800 dark:text-white">Cluster ${c.cluster_id}</span>
              </div>
              <span class="badge bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 px-2 py-1 rounded text-xs font-medium">${c.size} nodes</span>
            </summary>
            <div class="p-3 bg-white dark:bg-transparent rounded-b-xl max-h-64 overflow-y-auto">
              ${items}
            </div>
          </details>`;
      }).join("")}
          </div>
        </div>`;
    }

    /* ===============================
       3. TECHNOLOGY & VULNERABILITIES (Model 3)
    =============================== */
    let techHTML = "";
    if (r.technology_fingerprints && r.technology_fingerprints.length > 0) {
      techHTML = `
        <div class="report-section mt-10">
          <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
            <i class="ph-bold ph-cpu text-purple-500"></i> Technology Stack & Vulnerabilities
          </h2>
          <div class="space-y-4">
            ${r.technology_fingerprints.map(t => {
              const domainRoot = t.subdomain;
              const isPrimary = t.is_root || false;
        let hasCVEs = false;
        const techTags = t.technologies.map(tech => {
          if (tech.cves && tech.cves.length > 0) hasCVEs = true;
          return `<span class="inline-flex items-center px-2 py-1 rounded-md text-xs font-semibold bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 border border-gray-200 dark:border-gray-700 mr-2 mb-2"><i class="ph-bold ph-brackets-angle mr-1 opacity-50"></i> ${tech.technology} ${tech.version || ''}</span>`;
        }).join("");

        let cveRows = "";
        t.technologies.forEach(tech => {
          if (tech.cves && tech.cves.length > 0) {
            tech.cves.forEach(cve => {
              const isRealCVE = cve.cve && cve.cve.startsWith("CVE-");
              const sevClass = getSeverityColor(cve.severity);
              const cveLink = isRealCVE ? `<a href="https://nvd.nist.gov/vuln/detail/${cve.cve}" target="_blank" class="text-blue-500 hover:text-blue-400 hover:underline font-mono">${cve.cve}</a>` : `<span class="text-gray-500 dark:text-gray-400 font-mono">${cve.cve}</span>`;
              
              cveRows += `
                <tr class="hover:bg-gray-50 dark:hover:bg-white/5 transition-colors border-b border-gray-100 dark:border-white/5 last:border-0">
                  <td class="px-4 py-3">${cveLink}</td>
                  <td class="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">${tech.technology}</td>
                  <td class="px-4 py-3 text-sm font-medium">${cve.cvss || 'N/A'}</td>
                  <td class="px-4 py-3">
                    <span class="badge ${sevClass} px-2 py-0.5 rounded text-xs font-medium">${cve.severity}</span>
                  </td>
                </tr>
              `;
            });
          }
        });

        const cveTable = hasCVEs ? `
          <div class="mt-4 border border-gray-200 dark:border-white/10 rounded-lg overflow-hidden">
            <table class="w-full text-left border-collapse">
              <thead>
                <tr class="bg-gray-50 dark:bg-white/5 text-xs uppercase tracking-wider text-gray-500 dark:text-gray-400">
                  <th class="px-4 py-2 font-medium">CVE ID</th>
                  <th class="px-4 py-2 font-medium">Affects</th>
                  <th class="px-4 py-2 font-medium">CVSS</th>
                  <th class="px-4 py-2 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody>${cveRows}</tbody>
            </table>
          </div>
        ` : `<div class="mt-3 text-sm text-gray-500 dark:text-gray-400 italic px-1"><i class="ph ph-check-circle text-green-500 mr-1"></i> No known vulnerabilities detected for this stack.</div>`;

        return `
          <div class="glass-card p-5 relative overflow-hidden ${isPrimary ? 'ring-2 ring-purple-500/30' : ''}">
            <div class="absolute left-0 top-0 bottom-0 w-1 ${hasCVEs ? 'bg-red-500' : 'bg-green-500'}"></div>
            <div class="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-3 px-2">
              <div>
                ${isPrimary ? '<span class="text-[9px] font-bold text-purple-600 dark:text-purple-400 uppercase tracking-tighter mb-0.5 block">Primary Target</span>' : ''}
                <h4 class="text-lg font-bold text-gray-800 dark:text-white break-all">${t.url || "Unknown URL"}</h4>
                <div class="flex items-center gap-2 mt-1">
                   ${hasCVEs ? '<span class="text-xs font-medium text-red-500 flex items-center bg-red-500/10 px-2 py-0.5 rounded"><i class="ph-fill ph-warning-circle mr-1"></i> Vulnerable</span>' : '<span class="text-xs font-medium text-green-500 flex items-center bg-green-500/10 px-2 py-0.5 rounded"><i class="ph-fill ph-check-circle mr-1"></i> Secure</span>'}
                </div>
              </div>
            </div>
            <div class="px-2 mt-3">
              <div class="flex flex-wrap">${techTags}</div>
              ${cveTable}
            </div>
          </div>
        `;
      }).join("")}
          </div>
        </div>`;
    }

    /* ===============================
       4. ANOMALY DETECTION (Model 4)
    =============================== */
    let anomaliesHTML = "";
    if (r.http_anomalies && r.http_anomalies.length > 0) {
      anomaliesHTML = `
        <div class="report-section mt-10">
          <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
            <i class="ph-bold ph-activity text-teal-500"></i> Traffic Anomaly Detection
          </h2>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            ${r.http_anomalies.map(a => {
              const res = a.model4_result || {};
              const signals = res.signals || [];
              const isAnom = res.status === 'suspicious';
              
              const metrics = res.traffic_data ? `
                <div class="grid grid-cols-3 gap-2 mt-3 mb-3 border-y border-gray-100 dark:border-white/5 py-3">
                   <div class="flex flex-col"><span class="text-xl font-bold">${res.traffic_data.packet_count}</span><span class="text-[10px] text-gray-400 uppercase">Packets</span></div>
                   <div class="flex flex-col"><span class="text-xl font-bold">${res.traffic_data.tcp_syn_count}</span><span class="text-[10px] text-gray-400 uppercase">SYNs</span></div>
                   <div class="flex flex-col"><span class="text-xl font-bold">${res.traffic_data.unique_ips}</span><span class="text-[10px] text-gray-400 uppercase">IPs</span></div>
                </div>
              ` : '';

              const hasSignals = signals.length > 0;
              const signalList = hasSignals ? `
                <div class="text-xs space-y-1">
                  ${signals.map(s => `<div class="flex items-start text-red-400 bg-red-500/5 px-2 py-1 rounded border border-red-500/10"><i class="ph-bold ph-warning mr-1.5 mt-0.5 text-red-500 shrink-0"></i> <span>${s}</span></div>`).join("")}
                </div>
              ` : (isAnom ? `
                <div class="text-xs text-orange-400 bg-orange-500/5 px-2 py-1 rounded border border-orange-500/10 italic">
                  <i class="ph-bold ph-chart-line-up mr-1.5"></i> ${res.justification || "Statistical anomaly detected in traffic patterns."}
                </div>
              ` : `<div class="text-xs text-gray-400 italic px-1"><i class="ph-fill ph-shield-check text-green-500"></i> No suspicious patterns detected.</div>`);

              return `
                <div class="glass-card p-4 transition-transform hover:-translate-y-1 ${res.is_root ? 'ring-2 ring-blue-500/30' : ''}">
                  <div class="flex justify-between items-start mb-2">
                    <div class="flex flex-col">
                        ${res.is_root ? '<span class="text-[9px] font-bold text-blue-500 uppercase tracking-tighter mb-0.5">Primary Target</span>' : ''}
                        <h4 class="font-mono text-sm font-bold truncate max-w-[150px]" title="${a.subdomain}">${a.subdomain}</h4>
                    </div>
                    <span class="badge ${isAnom ? 'bg-red-500/10 text-red-500 border border-red-500/20' : 'bg-green-500/10 text-green-500 border border-green-500/20'} px-2 py-0.5 rounded text-[10px] font-bold uppercase">${res.status || "Unknown"}</span>
                  </div>
                  ${metrics}
                  ${signalList}
                </div>
              `;
            }).join("")}
          </div>
        </div>
      `;
    }

    /* ===============================
       5. EXPLOITATION STRATEGIES (Model 5)
    =============================== */
    let model5HTML = "";
    if (r.model5 && r.model5.strategies && r.model5.strategies.length > 0) {
      model5HTML = `
        <div class="report-section mt-10">
          <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
            <i class="ph-bold ph-sword text-red-500"></i> Exploitation Strategy & Attack Paths
          </h2>
          <div class="space-y-4">
            ${r.model5.strategies.map(strat => {
              const sevClass = getSeverityColor(strat.severity);
              const hasChain = strat.attack_chain && strat.attack_chain.length > 0;
              
              let chainHTML = "";
              if (hasChain) {
                chainHTML = `
                  <div class="mt-4 p-4 bg-gray-50 dark:bg-white/5 rounded-lg border border-gray-100 dark:border-white/5">
                    <h5 class="text-xs font-bold uppercase text-gray-500 tracking-wider mb-3">Predicted Attack Path</h5>
                    <div class="flex flex-wrap items-center gap-2">
                      ${strat.attack_chain.map((step, idx) => `
                        <div class="flex items-center">
                          <span class="px-3 py-1.5 bg-white dark:bg-black/20 border border-gray-200 dark:border-white/10 rounded-md text-xs font-semibold text-gray-700 dark:text-gray-300 shadow-sm">${step}</span>
                          ${idx < strat.attack_chain.length - 1 ? '<i class="ph-bold ph-arrow-right text-gray-400 mx-2"></i>' : ''}
                        </div>
                      `).join('')}
                    </div>
                  </div>
                `;
              }

              let refsHTML = "";
              if (strat.exploit_db_reference && strat.exploit_db_reference.length > 0) {
                refsHTML = `
                  <div class="mt-4 pt-4 border-t border-gray-100 dark:border-white/5">
                    <h5 class="text-xs font-bold uppercase text-gray-500 tracking-wider mb-2">Exploit-DB Intelligence</h5>
                    <ul class="space-y-1">
                      ${strat.exploit_db_reference.map(ref => `
                        <li>
                          <a href="${ref.url}" target="_blank" class="text-xs text-blue-500 hover:underline flex items-start gap-1">
                            <i class="ph-bold ph-link mt-0.5"></i> <span>${ref.title || 'Exploit Reference'}</span>
                          </a>
                        </li>
                      `).join('')}
                    </ul>
                  </div>
                `;
              }

              return `
                <div class="glass-card p-5 relative overflow-hidden group">
                  <div class="absolute left-0 top-0 bottom-0 w-1 ${sevClass.includes('red') ? 'bg-red-500' : (sevClass.includes('orange') ? 'bg-orange-500' : 'bg-gray-500')}"></div>
                  <div class="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-3 pl-2">
                    <div>
                      <h4 class="text-lg font-bold font-mono text-gray-800 dark:text-gray-100 mb-1">${strat.cve_id}</h4>
                      <p class="text-sm font-medium text-gray-500">Service: <span class="text-gray-700 dark:text-gray-300">${strat.service || "N/A"}</span> | CWE: <span class="bg-gray-100 dark:bg-white/10 px-1.5 py-0.5 rounded">${strat.cwe_id || "N/A"}</span></p>
                    </div>
                    <span class="badge ${sevClass} px-3 py-1 rounded text-xs font-bold uppercase shrink-0">${strat.evidence_status}</span>
                  </div>
                  
                  <div class="mt-2 pl-2 text-sm text-gray-600 dark:text-gray-300">
                    <p class="italic">"${strat.explanation || "No explanation provided."}"</p>
                    <p class="mt-2 font-medium text-gray-700 dark:text-gray-400"><i class="ph-bold ph-crosshair mr-1"></i> MITRE TTP: <span class="font-mono text-xs">${strat.mitre_technique || 'N/A'}</span></p>
                  </div>

                  <div class="pl-2">
                    ${chainHTML}
                    ${refsHTML}
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      `;
    }

    /* ===============================
       6. FINAL RISK TABLE (Model 6)
    =============================== */
    let model6HTML = "";
    if (model6Data.length) {
      model6HTML = `
        <div class="report-section mt-10">
          <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
            <i class="ph-bold ph-shield-warning text-red-500"></i> Global Vulnerability Index
          </h2>
          <div class="glass-card overflow-hidden">
            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse">
                <thead>
                  <tr class="bg-gray-50 dark:bg-white/5 text-xs uppercase tracking-wider text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-white/10">
                    <th class="px-6 py-4 font-semibold">CVE ID</th>
                    <th class="px-6 py-4 font-semibold">Affected Service</th>
                    <th class="px-6 py-4 font-semibold">Port</th>
                    <th class="px-6 py-4 font-semibold">CVSS Score</th>
                    <th class="px-6 py-4 font-semibold">Risk Level</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-200 dark:divide-white/5">
                  ${model6Data.map(v => {
                    const portDisplay = (v.port !== undefined && v.port !== null && v.port !== "") ? v.port : "N/A";
                    const cvssDisplay = (v.cvss !== undefined && v.cvss !== null && v.cvss !== "") ? v.cvss : "N/A";
                    const sevClass = getSeverityColor(v.risk_level);
                    
                    return `
                      <tr class="hover:bg-gray-50 dark:hover:bg-white/5 transition-colors group">
                        <td class="px-6 py-4 font-mono text-sm ${v.cve_id ? 'text-blue-500 dark:text-blue-400' : 'text-gray-500'}">${v.cve_id || "N/A"}</td>
                        <td class="px-6 py-4 text-sm font-medium text-gray-800 dark:text-gray-200">${v.service || "N/A"}</td>
                        <td class="px-6 py-4">
                          <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600 dark:bg-white/10 dark:text-gray-300 border border-gray-200 dark:border-white/10">
                            ${portDisplay}
                          </span>
                        </td>
                        <td class="px-6 py-4 text-sm font-bold text-gray-700 dark:text-gray-300">${cvssDisplay}</td>
                        <td class="px-6 py-4">
                          <div class="flex items-center gap-2">
                            ${getRiskDot(v.risk_level)}
                            <span class="badge ${sevClass} px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wide">
                              ${v.risk_level || "Unknown"}
                            </span>
                          </div>
                        </td>
                      </tr>`;
                  }).join("")}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      `;
    } else {
        model6HTML = `
        <div class="report-section mt-10">
          <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
            <i class="ph-bold ph-shield-check text-green-500"></i> Global Vulnerability Index
          </h2>
          <div class="glass-card p-8 flex flex-col justify-center items-center text-center">
             <i class="ph-fill ph-check-circle text-5xl text-blue-500 mb-4 drop-shadow-[0_0_10px_rgba(59,130,246,0.5)]"></i>
             <h3 class="text-xl font-bold mb-2">No confirmed vulnerabilities based on strict validation.</h3>
             <p class="text-gray-500 dark:text-gray-400">Some findings require further verification. Check the analysis proofs for uncertain or boundary cases.</p>
          </div>
        </div>`;
    }

    /* ===============================
       6. ASYNC RECOMMENDATIONS
    =============================== */
    const recommendationsHTML = `
      <div id="recommendations-section" class="hidden mt-10 scroll-mt-24">
        <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
          <i class="ph-bold ph-wrench text-blue-500"></i> Recommended Action Plan
        </h2>
        <div id="recommendations-content">
           <div class="glass-card p-8 flex flex-col justify-center items-center text-center">
             <i class="ph ph-spinner-gap text-3xl text-cyber-accent animate-spin mb-3"></i>
             <p class="text-gray-500">Synthesizing patch priorities...</p>
           </div>
        </div>
      </div>
    `;

    /* ===============================
       EXECUTE RENDER
    =============================== */
    reportContent.innerHTML = `
      ${summaryCardsHTML}
      ${clustersHTML}
      ${techHTML}
      ${anomaliesHTML}
      ${model5HTML}
      ${model6HTML}
      ${recommendationsHTML}
    `;
    
    // Clear styles overriding structural width
    reportContent.className = ""; 
    // Wait, the parent has `glass-card p-6 md:p-8 min-h-[400px]`.
    // Actually the user wants sections with spacing. If reportContent itself is a glass-card, the summary grids inside looks like card-in-card.
    // I will dynamically remove the glass-card class from reportContent to let children format the layout beautifully!
    reportContent.classList.remove('glass-card', 'p-6', 'md:p-8', 'min-h-[400px]');
    
    /* ===============================
       BIND EVENTS
    =============================== */
    const patchBtn = document.getElementById("patch-btn");
    if (patchBtn) {
      let isRecommendationsVisible = false;
      let hasGenerated = false;

      patchBtn.onclick = async () => {
        const recSection = document.getElementById("recommendations-section");
        const recContent = document.getElementById("recommendations-content");
        const origTextHTML = '<i class="ph-bold ph-shield-check text-emerald-600 dark:text-emerald-400 text-lg"></i> Security Patches';
        
        if (isRecommendationsVisible) {
          recSection.classList.add('hidden');
          patchBtn.innerHTML = origTextHTML;
          isRecommendationsVisible = false;
          return;
        }

        if (hasGenerated) {
          recSection.classList.remove('hidden');
          patchBtn.innerHTML = '<i class="ph-bold ph-eye-slash text-gray-500 text-lg"></i> Hide Patches';
          isRecommendationsVisible = true;
          recSection.scrollIntoView({ behavior: "smooth", block: "start" });
          return;
        }

        patchBtn.innerHTML = '<i class="ph-bold ph-spinner-gap animate-spin text-lg"></i> Loading...';
        patchBtn.disabled = true;
        recSection.classList.remove('hidden');
        recSection.scrollIntoView({ behavior: "smooth", block: "start" });

        try {
          const payload = {};
          if (reportId) payload.report_id = reportId;
          if (domain) payload.domain = domain;

          const recResp = await fetch("/generate_recommendations", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          });

          if (!recResp.ok) throw new Error("Failed to generate recommendations");

          const recData = await recResp.json();
          const recArray = recData.recommendations || [];

          if (recArray.length === 0) {
            recContent.innerHTML = `
              <div class="glass-card p-8 text-center text-gray-500">
                <i class="ph-fill ph-shield-check text-4xl text-green-500 drop-shadow-[0_0_10px_rgba(34,197,94,0.5)] mb-3"></i>
                <p>No actionable vulnerabilities found to patch.</p>
              </div>`;
          } else {
            recContent.innerHTML = `
              <div class="space-y-4">
                ${recArray.map(rec => {
                  const sevClass = getSeverityColor(rec.severity || rec.risk_level);
                  
                  // Style remediation steps with bold prefixes
                  let remList = "";
                  if (Array.isArray(rec.remediation)) {
                    remList = "<ul class='list-disc pl-5 mt-2 space-y-1'>" + 
                      rec.remediation.map(step => {
                        const parts = step.split(': ');
                        if (parts.length > 1) {
                          return `<li><span class="font-bold text-gray-700 dark:text-gray-200">${parts[0]}:</span> ${parts.slice(1).join(': ')}</li>`;
                        }
                        return `<li>${step}</li>`;
                      }).join("") + "</ul>";
                  } else {
                    remList = `<p class='mt-2'>${rec.remediation || "—"}</p>`;
                  }

                  const confClass = (rec.confidence_level === "HIGH") ? "bg-green-500/10 text-green-600 border-green-200" : (rec.confidence_level === "MEDIUM" ? "bg-blue-500/10 text-blue-600 border-blue-200" : "bg-gray-500/10 text-gray-500 border-gray-200");

                  let refListHTML = "";
                  if (Array.isArray(rec.references) && rec.references.length > 0) {
                    refListHTML = `<div class="mt-4 pt-4 border-t border-gray-100 dark:border-white/5"><h5 class="text-xs font-bold uppercase text-gray-500 tracking-wider mb-2">References</h5><ul class="text-sm space-y-1">` +
                      rec.references.map(u => `<li><a href="${u}" target="_blank" rel="noopener" class="text-blue-500 hover:underline break-all">${u}</a></li>`).join("") +
                      `</ul></div>`;
                  }

                  return `
                    <div class="glass-card p-5 relative overflow-hidden group">
                      <div class="absolute left-0 top-0 bottom-0 w-1 ${sevClass.includes('red') ? 'bg-red-500' : (sevClass.includes('orange') ? 'bg-orange-500' : 'bg-gray-500')}"></div>
                      <div class="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-3 pl-2">
                          <div>
                             <div class="flex items-center gap-2 mb-1">
                               <h4 class="text-lg font-bold font-mono text-gray-800 dark:text-gray-100">${rec.cve_id || "Unknown Vulnerability"}</h4>
                               <span class="px-2 py-0.5 rounded border text-[10px] font-bold uppercase ${confClass}">${rec.confidence_level || 'N/A'} CONFIDENCE</span>
                             </div>
                             <p class="text-sm font-medium text-gray-500">Service: <span class="text-gray-700 dark:text-gray-300">${rec.service || "N/A"}</span> | Port: <span class="bg-gray-100 dark:bg-white/10 px-1.5 py-0.5 rounded">${rec.port !== undefined && rec.port !== null ? rec.port : "N/A"}</span></p>
                          </div>
                          <span class="badge ${sevClass} px-3 py-1 rounded text-xs font-bold uppercase shrink-0">${rec.priority || rec.severity || "Unknown"}</span>
                      </div>
                      
                      <div class="mt-2 pl-2 text-sm text-gray-600 dark:text-gray-300">
                        <p class="font-medium text-gray-800 dark:text-gray-100 mb-2">Confidence Justification: <span class="font-normal text-gray-500">${rec.justification || "Determined by service fingerprinting and CVSS data."}</span></p>
                        <p class="italic">"${rec.explanation || "No explanation provided."}"</p>
                        ${rec.attacker_perspective ? `<p class="mt-3 p-3 bg-red-500/5 border border-red-500/10 rounded-lg text-red-600 dark:text-red-400"><i class="ph-bold ph-skull mr-1"></i> <strong class="font-medium">Attacker Perspective:</strong> ${rec.attacker_perspective}</p>` : ''}
                      </div>

                      <div class="mt-4 pl-2">
                        <h5 class="text-xs font-bold uppercase text-emerald-600 dark:text-emerald-400 tracking-wider flex items-center gap-1"><i class="ph-bold ph-check-square"></i> Actionable Remediation</h5>
                        <div class="text-gray-700 dark:text-gray-300">${remList}</div>
                      </div>
                      
                      <div class="pl-2">
                        ${refListHTML}
                      </div>

                      <div class="mt-5 pl-2">
                          <a href="/download_fix_script?cve_id=${encodeURIComponent(rec.cve_id || "N/A")}&service=${encodeURIComponent(rec.service || "")}&port=${encodeURIComponent(rec.port || "")}&host=${encodeURIComponent(domain || "")}" class="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-gray-100 dark:bg-white/10 hover:bg-gray-200 dark:hover:bg-white/20 transition-all text-sm font-semibold border border-transparent dark:border-white/10 btn-glow">
                             <i class="ph-bold ph-terminal-window"></i> Download PowerShell Fix Matrix
                          </a>
                      </div>
                    </div>
                  `;
                }).join("")}
              </div>
            `;
          }

          hasGenerated = true;
          isRecommendationsVisible = true;
          patchBtn.innerHTML = '<i class="ph-bold ph-eye-slash text-gray-500 text-lg"></i> Hide Patches';
          patchBtn.disabled = false;

        } catch (error) {
          console.error(error);
          recContent.innerHTML = `
            <div class="glass-card p-6 bg-red-500/5 border-red-500/20 text-center">
              <p class="text-red-500 font-medium">Error loading recommendations: ${error.message}</p>
            </div>`;
          patchBtn.innerHTML = origTextHTML;
          patchBtn.disabled = false;
        }
      };

      const downloadBtn = document.getElementById("download-btn");
      if (downloadBtn) {
        downloadBtn.onclick = () => {
          let url = "/download_report?";
          if (reportId) url += `report_id=${encodeURIComponent(reportId)}`;
          else if (domain) url += `domain=${encodeURIComponent(domain)}`;
          window.location.href = url;
        };
      }
    }

  } catch (err) {
    console.error(err);
    reportContent.innerHTML = `
      <div class="glass-card p-6 bg-red-500/5 border-red-500/20 text-center">
        <p class="text-red-500 font-medium">Critical Application Error: ${err.message}</p>
      </div>`;
  }
});
