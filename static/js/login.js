document.getElementById("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!email || !password) {
    return;
  }

  try {
    const response = await fetch("http://localhost:5000/login", {
      method: "POST",
      credentials: "include", 
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (response.ok) {
      // ✅ Check if account is pending
      if (data.status && data.status === "pending") {
        alert("Your account is waiting for admin verification.");
        return;
      }

      console.log("User logged in:", data);
      localStorage.setItem("userEmail", data.email);
      localStorage.setItem("role", data.role);

      if (data.role === "admin") {
        window.location.href = "/admin";
      } else {
        window.location.href = "/home";
      }
    } else {
      console.error("Login failed:", data.message);
      alert(data.message);
    }
  } catch (error) {
    console.error("Error connecting to server:", error);
  }
});

// ==========================================
// VISIBILITY TOGGLE
// ==========================================
function setupEyeToggle(inputId, toggleId) {
  const input = document.getElementById(inputId);
  const toggle = document.getElementById(toggleId);
  const icon = toggle ? toggle.querySelector("svg") : null;
  
  if (!input || !toggle || !icon) return;

  toggle.addEventListener("click", () => {
    if (input.type === "password") {
      input.type = "text";
      // Eye-off icon
      icon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 20px; height: 20px;"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24M1 1l22 22"></path></svg>`;
    } else {
      input.type = "password";
      // Eye icon
      icon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 20px; height: 20px;"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
    }
  });
}

setupEyeToggle("password", "togglePassword");
