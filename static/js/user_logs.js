const BASE_URL = "http://localhost:5000";

// Fetch user logs
async function fetchUserLogs() {
  try {
    const response = await fetch(`${BASE_URL}/admin/get_user_logs`);
    if (!response.ok) throw new Error("Failed to fetch logs");
    const logs = await response.json();

    const tableBody = document.getElementById("logsTableBody");
    tableBody.innerHTML = "";

    logs.forEach((log, index) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${index + 1}</td>
        <td>${log.username || "Unknown"}</td>
        <td>${log.email || "—"}</td>
        <td>${log.login_time ? new Date(log.login_time).toLocaleString() : "—"}</td>
        <td>${log.ip || "N/A"}</td>
        <td style="color: ${log.status === "Success" ? "#00ff66" : "#ff3333"};">
          ${log.status}
        </td>
      `;
      tableBody.appendChild(row);
    });

  } catch (err) {
    console.error("Error loading logs:", err);
    alert("Failed to load user logs.");
  }
}

// Auto-load logs when page loads
window.addEventListener("DOMContentLoaded", fetchUserLogs);
