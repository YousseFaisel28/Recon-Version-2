// FORM SUBMISSION
document.getElementById("signupForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  const name = document.getElementById("name").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;
  const domain = document.getElementById("domain").value.trim();

  if (!isPasswordValid(password)) {
    alert("Please ensure your password meets all requirements (8+ chars, uppercase, number, special char).");
    return;
  }

  if (password !== confirmPassword) {
    alert("Passwords do not match!");
    return;
  }

  try {
    const response = await fetch("/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: name,
        email: email,
        password: password,
        domain: domain,
      })
    });

    const data = await response.json();

    if (response.ok) {
      alert(
        "Account created successfully!\n\n" +
        "Your account is pending admin approval. " +
        "You will be able to log in once an admin activates your account."
      );
      window.location.href = "/login";
    } else {
      alert(data.message || "Signup failed. Please try again.");
      console.error("Signup failed:", data);
    }
  } catch (err) {
    console.error("Error connecting to server:", err);
    alert("Could not connect to the server. Please try again later.");
  }
});

// ==========================================
// VISIBILITY TOGGLES
// ==========================================
function setupEyeToggle(inputId, toggleId) {
  const input = document.getElementById(inputId);
  const toggle = document.getElementById(toggleId);
  
  if (!input || !toggle) return;

  const icon = toggle.querySelector("svg");

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
setupEyeToggle("confirmPassword", "toggleConfirmPassword");

// ==========================================
// PASSWORD REQUIREMENTS & STRENGTH
// ==========================================
const passwordInput = document.getElementById("password");
const confirmInput = document.getElementById("confirmPassword");
const matchText = document.getElementById("matchText");

const reqLength = document.getElementById("req-length");
const reqUpper = document.getElementById("req-upper");
const reqNumber = document.getElementById("req-number");
const reqSpecial = document.getElementById("req-special");

const strengthContainer = document.getElementById("strengthContainer");
const strengthFill = document.getElementById("strengthFill");
const strengthLabel = document.getElementById("strengthLabel");

// Validation regexes
const upperRegex = /[A-Z]/;
const numRegex = /[0-9]/;
const specialRegex = /[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\/;']/;

function isPasswordValid(val) {
  return val.length >= 8 && upperRegex.test(val) && numRegex.test(val) && specialRegex.test(val);
}

function updateRequirementStatus(el, isValid, text) {
  if (isValid) {
    el.classList.remove("invalid");
    el.classList.add("valid");
    el.innerHTML = `<span class="req-icon">✓</span> ${text}`;
  } else {
    el.classList.remove("valid");
    el.classList.add("invalid");
    el.innerHTML = `<span class="req-icon">✗</span> ${text}`;
  }
}

if (passwordInput) {
  passwordInput.addEventListener("input", function () {
    const val = passwordInput.value;

    if (val.length > 0) {
      strengthContainer.style.display = "block";
    } else {
      strengthContainer.style.display = "none";
    }

    // Check individual rules
    const hasLen = val.length >= 8;
    const hasUp = upperRegex.test(val);
    const hasNum = numRegex.test(val);
    const hasSpec = specialRegex.test(val);

    updateRequirementStatus(reqLength, hasLen, "At least 8 characters");
    updateRequirementStatus(reqUpper, hasUp, "At least one uppercase letter");
    updateRequirementStatus(reqNumber, hasNum, "At least one number");
    updateRequirementStatus(reqSpecial, hasSpec, "At least one special character");

    // Calculate score (0 to 4) + bonus for extra length
    let score = 0;
    if (hasLen) score++;
    if (hasUp) score++;
    if (hasNum) score++;
    if (hasSpec) score++;
    if (val.length >= 12 && score === 4) score = 5;

    // Update Strength Bar & Label
    strengthFill.className = "strength-fill"; // reset
    if (val.length === 0) {
      strengthFill.style.width = "0%";
      strengthLabel.textContent = "";
    } else if (score <= 2) {
      strengthFill.style.width = "33%";
      strengthFill.classList.add("strength-weak");
      strengthLabel.textContent = "Weak";
      strengthLabel.className = "strength-label strength-weak";
    } else if (score === 3 || score === 4) {
      strengthFill.style.width = "66%";
      strengthFill.classList.add("strength-medium");
      strengthLabel.textContent = "Medium";
      strengthLabel.className = "strength-label strength-medium";
    } else if (score === 5) {
      strengthFill.style.width = "100%";
      strengthFill.classList.add("strength-strong");
      strengthLabel.textContent = "Strong";
      strengthLabel.className = "strength-label strength-strong";
    }

    checkMatch();
  });
}

if (confirmInput) {
  confirmInput.addEventListener("input", checkMatch);
}

function checkMatch() {
  const p1 = passwordInput.value;
  const p2 = confirmInput.value;
  
  if (p2.length === 0) {
    matchText.textContent = "";
    matchText.style.color = "";
    return;
  }

  if (p1 === p2) {
    matchText.textContent = "✓ Passwords match";
    matchText.style.color = "#22c55e";
  } else {
    matchText.textContent = "✗ Passwords do not match";
    matchText.style.color = "#ef4444";
  }
}

