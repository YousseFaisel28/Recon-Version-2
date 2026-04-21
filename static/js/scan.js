document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector(".scan-form");
  const domainInput = document.getElementById("domain-input");
  const submitBtn = document.getElementById("scan-btn");

  // Arrays to hold scoped contexts
  let primaryDomain = "";
  let additionalDomains = [];

  const resultsContainer = document.createElement("div");
  resultsContainer.id = "scan-results";
  resultsContainer.style.margin = "20px auto";
  resultsContainer.style.maxWidth = "600px";
  resultsContainer.style.background = "rgba(0,0,0,0.4)";
  resultsContainer.style.padding = "16px";
  resultsContainer.style.borderRadius = "8px";
  resultsContainer.style.border = "1px solid rgba(255,255,255,0.1)";
  resultsContainer.style.display = "none";

  const formParent = form ? form.parentNode : document.body;
  if(formParent) formParent.appendChild(resultsContainer);

  function showMessage(msg, isError = false) {
    resultsContainer.style.display = "block";
    resultsContainer.innerHTML = `
      <p style="color:${isError ? "#ef4444" : "#10b981"}; margin:0 0 12px 0; font-weight: bold; font-family: monospace;">${msg}</p>
    `;
  }

  function hideMessage() {
    resultsContainer.style.display = "none";
    resultsContainer.innerHTML = "";
  }

  async function loadAllowedDomains() {
    try {
      const resp = await fetch("/user/profile");
      if (!resp.ok) throw new Error("Unable to load user profile.");
      const data = await resp.json();
      
      primaryDomain = String(data.primary_domain || "");
      additionalDomains = (data.additional_domains || []).map((d) => String(d));

      const primaryDisp = document.getElementById("primary-domain-display");
      if(primaryDisp) primaryDisp.textContent = primaryDomain || "None tied to account";
      
      const additionalList = document.getElementById("additional-domains-list");
      if (additionalList) {
          additionalList.innerHTML = additionalDomains.length > 0 
              ? additionalDomains.map(d => `<li><i class="ph-bold ph-caret-right text-emerald-500 mr-1"></i> ${d}</li>`).join("")
              : `<li class="text-[11px] text-gray-500 italic">No alternative scopes bound</li>`;
      }
    } catch (err) {
      console.error("Failed to load scoping domains:", err);
    }
  }

  // ============================
  // Additional Scopes Display
  // ============================
  // (Verification flow removed)

  async function postJSON(url, body) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 600000); // 10m
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return resp;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') throw new Error('Request timeout limit hit.');
      throw error;
    }
  }

  // ============================
  // SCAN BURST QUEUEING MODULE
  // ============================
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    hideMessage(); // clear previous results styling

    const inputData = domainInput.value.trim();
    if (!inputData) {
      showMessage("Please insert targets into the text area.", true);
      return;
    }

    const targets = inputData.split(/[\n,]+/).map(t => t.trim().toLowerCase()).filter(Boolean);
    const uniqueTargets = Array.from(new Set(targets));

    if (!uniqueTargets.length) return;

    submitBtn.disabled = true;
    domainInput.disabled = true;
    const oldBtnHTML = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="ph-bold ph-spinner ph-spin text-xl"></i> Scans Initiated';
    
    showMessage(`Starting burst scan for ${uniqueTargets.length} discovered target(s)...`);

    let didSucceed = false;

    let lastReportId = "";
    for (let i = 0; i < uniqueTargets.length; i++) {
        const target = uniqueTargets[i];
        try {
            resultsContainer.innerHTML = `<p style="color:#10b981; margin:0; font-family:monospace; font-weight:bold;">[${i+1}/${uniqueTargets.length}] Interrogating ${target}...</p>`;
            
            const resp = await postJSON("/scan_domain", {
              domain: target,
              include_tech_scan: true
            });

            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) {
              showMessage(`Scan halted on ${target} due to API Rejection: ${data.error || data.message}`, true);
              break; 
            } else {
              didSucceed = true;
              if (data.report_id) lastReportId = data.report_id;
            }
        } catch (err) {
            let errorMsg = err.message;
            if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
              errorMsg = 'Server unreachable drop detected. Make sure the Flask server is running.';
            }
            showMessage(`Scan halted critically on ${target}: ${errorMsg}`, true);
            break;
        }
    }
    
    if (didSucceed) {
        showMessage("✅ Execution Pipeline Completed. Redirecting to intelligence report...", false);
        setTimeout(() => {
            if (lastReportId) {
                window.location.href = `/report?report_id=${lastReportId}`;
            } else {
                window.location.href = `/history`;
            }
        }, 2000);
    }

    submitBtn.disabled = false;
    domainInput.disabled = false;
    submitBtn.innerHTML = oldBtnHTML;
  });

  // Load the scoped domains for the logged-in user
  loadAllowedDomains();

});
