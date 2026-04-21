

async function fetchPendingUsers() {
  try {
    const response = await fetch("http://localhost:5000/admin/get_pending_users");
    const data = await response.json();
    console.log("Fetched pending users:", data); // debug log

    const table = document.getElementById("pendingUsersTableBody");
    table.innerHTML = "";

    if (!data.users || data.users.length === 0) {
      table.innerHTML = `<tr><td colspan="4">No pending users</td></tr>`;
      return;
    }

    data.users.forEach(user => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${user.username}</td>
        <td>${user.email}</td>
        <td>${user.created_at ? new Date(user.created_at).toLocaleString() : "N/A"}</td>
        <td>
          <button class="action-btn approve-btn" onclick="approveUser('${user.email}', 'approve')">Approve</button>
          <button class="action-btn decline-btn" onclick="approveUser('${user.email}', 'decline')">Decline</button>

        </td>`;
      table.appendChild(row);
    });
  } catch (err) {
    console.error("Error fetching pending users:", err);
  }
}

async function approveUser(email, action) {
  try {
    const response = await fetch("http://localhost:5000/admin/approve_user", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, action })
    });

    const data = await response.json();
    alert(data.message);
    fetchPendingUsers(); // refresh table
  } catch (err) {
    console.error("Error updating user:", err);
  }
}

// Load pending users on page load
window.onload = fetchPendingUsers;
