const BASE_URL = "http://localhost:5000";

let allUsers = [];
let selectedUserId = null;

// ====================================================
// FETCH USERS
// ====================================================
async function fetchUsers() {
  try {
    const response = await fetch(`${BASE_URL}/admin/get_users`);
    if (!response.ok) throw new Error("Failed to fetch users");
    allUsers = await response.json();
    
    document.getElementById("userCountBadge").textContent = allUsers.length;
    renderUserList(allUsers);
  } catch (err) {
    console.error("Fetch error:", err);
    document.getElementById("userList").innerHTML = 
      '<div style="text-align: center; padding: 20px; color: #ef4444;">Failed to load users.</div>';
  }
}

// ====================================================
// RENDER USER LIST (LEFT SIDE)
// ====================================================
function renderUserList(users) {
  const container = document.getElementById("userList");
  container.innerHTML = "";

  if (users.length === 0) {
    container.innerHTML = '<div style="text-align: center; padding: 20px; color: #888;">No users found.</div>';
    return;
  }

  users.forEach((u) => {
    const div = document.createElement("div");
    div.className = `user-list-item ${selectedUserId === u._id ? "active" : ""}`;
    div.onclick = () => selectUser(u._id);
    
    const roleBadge = u.role === "admin" 
      ? '<span style="font-size:0.65rem; background:rgba(255,255,255,0.1); padding:2px 6px; border-radius:4px; margin-left:8px;">ADMIN</span>' 
      : "";

    div.innerHTML = `
      <div class="user-list-info">
        <h4>${u.username}${roleBadge}</h4>
        <p>${u.email}</p>
      </div>
    `;
    container.appendChild(div);
  });
}

// ====================================================
// FILTER USER LIST
// ====================================================
function filterUserList() {
  const query = document.getElementById("userSearch").value.toLowerCase();
  const filtered = allUsers.filter(u => 
    u.username.toLowerCase().includes(query) || 
    u.email.toLowerCase().includes(query)
  );
  renderUserList(filtered);
}

// ====================================================
// SELECT USER (LOAD DETAILS)
// ====================================================
async function selectUser(userId) {
  selectedUserId = userId;
  
  // Highlight in list
  renderUserList(allUsers.filter(u => 
    u.username.toLowerCase().includes(document.getElementById("userSearch").value.toLowerCase()) || 
    u.email.toLowerCase().includes(document.getElementById("userSearch").value.toLowerCase())
  ));

  // Switch UI
  document.getElementById("noUserSelected").style.display = "none";
  document.getElementById("userDashboard").style.display = "block";

  const user = allUsers.find(u => u._id === userId);
  if (!user) return;

  // Populating Basic Info
  document.getElementById("displayUsername").textContent = user.username;
  document.getElementById("displayEmail").textContent = user.email;
  document.getElementById("displayCreatedAt").textContent = user.created_at ? new Date(user.created_at).toLocaleDateString() : "—";
  
  // Status Badge
  const status = user.status || "active";
  const badgeEl = document.getElementById("userStatusBadge");
  badgeEl.className = `status-badge ${status === "active" ? "status-active" : "status-disabled"}`;
  badgeEl.textContent = status;

  // Role Select
  document.getElementById("editRole").value = user.role || "user";

  // Toggle Status Button Text
  const statusBtn = document.getElementById("toggleStatusBtn");
  if (status === "active") {
    statusBtn.textContent = "Disable Account";
    statusBtn.style.color = "#f87171";
    statusBtn.style.background = "rgba(239, 68, 68, 0.1)";
  } else {
    statusBtn.textContent = "Enable Account";
    statusBtn.style.color = "#4ade80";
    statusBtn.style.background = "rgba(34, 197, 94, 0.1)";
  }

  // Loading Domains
  loadUserDomainData(userId);
}

// ====================================================
// LOAD DOMAIN DATA
// ====================================================
async function loadUserDomainData(userId) {
  try {
    const res = await fetch(`${BASE_URL}/admin/get_user_domains/${userId}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.message);

    document.getElementById("editDomains").value = (data.allowed_domains || []).join(", ");
    
    // Scanned domains badges
    const scannedContainer = document.getElementById("scannedDomainsList");
    scannedContainer.innerHTML = "";
    if (data.scanned_domains && data.scanned_domains.length > 0) {
      data.scanned_domains.forEach(d => {
        const badge = document.createElement("span");
        badge.className = "audit-action-badge";
        badge.style.background = "rgba(255,255,255,0.08)";
        badge.textContent = d;
        scannedContainer.appendChild(badge);
      });
    } else {
      scannedContainer.innerHTML = '<span style="color:#666; font-size:0.85rem;">No scans run yet.</span>';
    }
  } catch (err) {
    console.error("Domain load error:", err);
  }
}

// ====================================================
// UPDATE ROLE
// ====================================================
async function updateUserRole() {
  if (!selectedUserId) return;
  const newRole = document.getElementById("editRole").value;
  
  try {
    const res = await fetch(`${BASE_URL}/admin/update_user_role/${selectedUserId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: newRole }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message);
    
    alert("Role updated successfully!");
    fetchUsers(); // Refresh data
  } catch (err) {
    alert("Error updating role: " + err.message);
  }
}

// ====================================================
// TOGGLE STATUS
// ====================================================
async function toggleUserStatus() {
  if (!selectedUserId) return;
  const user = allUsers.find(u => u._id === selectedUserId);
  const newStatus = (user.status || "active") === "active" ? "disabled" : "active";

  try {
    const res = await fetch(`${BASE_URL}/admin/update_user_status/${selectedUserId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message);
    
    alert(`Account ${newStatus === "active" ? "enabled" : "disabled"} successfully!`);
    await fetchUsers(); // Refresh local list
    selectUser(selectedUserId); // Refresh dashboard view
  } catch (err) {
    alert("Error updating status: " + err.message);
  }
}

// ====================================================
// UPDATE DOMAINS
// ====================================================
async function updateDomains() {
  if (!selectedUserId) return;
  const user = allUsers.find(u => u._id === selectedUserId);
  const domainsStr = document.getElementById("editDomains").value.trim();

  try {
    const res = await fetch(`${BASE_URL}/admin/update_user_domains`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: user.email, domains: domainsStr }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message);
    
    alert("Domains updated successfully!");
    loadUserDomainData(selectedUserId);
  } catch (err) {
    alert("Error updating domains: " + err.message);
  }
}

// ====================================================
// DELETE USER
// ====================================================
async function handleDeleteUser() {
  if (!selectedUserId) return;
  if (!confirm("Are you sure? This action cannot be undone!")) return;

  try {
    const res = await fetch(`${BASE_URL}/admin/delete_user/${selectedUserId}`, {
      method: "DELETE",
    });
    const data = await res.json();
    alert(data.message);
    
    selectedUserId = null;
    document.getElementById("userDashboard").style.display = "none";
    document.getElementById("noUserSelected").style.display = "flex";
    
    fetchUsers();
  } catch (err) {
    alert("Delete failed: " + err.message);
  }
}

// ====================================================
// ADD USER MODAL LOGIC
// ====================================================
function showAddUserModal() {
  document.getElementById("addUserModal").style.display = "flex";
}

function hideAddUserModal() {
  document.getElementById("addUserModal").style.display = "none";
  document.getElementById("addUserForm").reset();
}

async function addUser(event) {
  event.preventDefault();
  const username = document.getElementById("username").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();

  try {
    const res = await fetch(`${BASE_URL}/admin/add_user`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message);
    
    alert("User created successfully!");
    hideAddUserModal();
    fetchUsers();
  } catch (err) {
    alert("Error: " + err.message);
  }
}

// Auto-load
window.addEventListener("DOMContentLoaded", fetchUsers);
