/**
 * Account Settings - Edit Info, Password Verification, and Change Username
 */

document.addEventListener("DOMContentLoaded", function () {
  // ===== Elements =====
  const editInfoBtn = document.getElementById("editInfoBtn");
  const usernameDisplay = document.getElementById("usernamDisplay");

  // Verify Password Modal
  const verifyPasswordModal = document.getElementById("verifyPasswordModal");
  const closeVerifyPasswordModal = document.getElementById("closeVerifyPasswordModal");
  const verifyPasswordInput = document.getElementById("verifyPasswordInput");
  const verifyPasswordError = document.getElementById("verifyPasswordError");
  const verifyPasswordSubmitBtn = document.getElementById("verifyPasswordSubmitBtn");
  const verifyPasswordCancelBtn = document.getElementById("verifyPasswordCancelBtn");

  // Account Settings Modal
  const accountSettingsModal = document.getElementById("accountSettingsModal");
  const closeAccountSettingsModal = document.getElementById("closeAccountSettingsModal");
  const changeUsernameOptionBtn = document.getElementById("changeUsernameOptionBtn");
  const changePasswordOptionBtn = document.getElementById("changePasswordOptionBtn");
  const accountSettingsCancelBtn = document.getElementById("accountSettingsCancelBtn");

  // Change Username Modal
  const changeUsernameModal = document.getElementById("changeUsernameModal");
  const closeModalBtn = document.getElementById("closeModalBtn");
  const newUsernameInput = document.getElementById("newUsernameInput");
  const usernameError = document.getElementById("usernameError");
  const usernameSuccess = document.getElementById("usernameSuccess");
  const changeUsernameSubmitBtn = document.getElementById("changeUsernameSubmitBtn");
  const changeUsernameCancelBtn = document.getElementById("changeUsernameCancelBtn");

  // ===== Load Username =====
  function loadUsername() {
    fetch("/user/profile", {
      method: "GET",
      credentials: "include"
    })
      .then(response => response.json())
      .then(data => {
        if (data.username) {
          usernameDisplay.textContent = `👤 ${data.username}`;
        }
      })
      .catch(() => {
        usernameDisplay.textContent = "👤 User";
      });
  }

  loadUsername();

  // ===== Modal Control Functions =====
  function closeAllModals() {
    verifyPasswordModal.classList.remove("show");
    accountSettingsModal.classList.remove("show");
    changeUsernameModal.classList.remove("show");
  }

  function showVerifyPasswordModal() {
    verifyPasswordModal.classList.add("show");
    verifyPasswordInput.focus();
    verifyPasswordError.classList.remove("show");
    verifyPasswordInput.value = "";
  }

  function showAccountSettingsModal() {
    verifyPasswordModal.classList.remove("show");
    accountSettingsModal.classList.add("show");
  }

  function showChangeUsernameModal() {
    accountSettingsModal.classList.remove("show");
    changeUsernameModal.classList.add("show");
    newUsernameInput.focus();
    clearMessages();
  }

  // ===== Event Listeners: Edit Info =====
  editInfoBtn.addEventListener("click", function () {
    showVerifyPasswordModal();
  });

  // ===== Event Listeners: Verify Password Modal =====
  closeVerifyPasswordModal.addEventListener("click", function () {
    closeAllModals();
  });

  verifyPasswordCancelBtn.addEventListener("click", function () {
    closeAllModals();
  });

  verifyPasswordModal.addEventListener("click", function (e) {
    if (e.target === verifyPasswordModal) {
      closeAllModals();
    }
  });

  verifyPasswordSubmitBtn.addEventListener("click", function () {
    verifyPasswordError.classList.remove("show");
    const password = verifyPasswordInput.value;

    if (!password) {
      verifyPasswordError.textContent = "Password cannot be empty";
      verifyPasswordError.classList.add("show");
      return;
    }

    verifyPasswordSubmitBtn.disabled = true;
    verifyPasswordSubmitBtn.textContent = "Verifying...";

    fetch("/verify-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ password })
    })
      .then(response => response.json())
      .then(data => {
        verifyPasswordSubmitBtn.disabled = false;
        verifyPasswordSubmitBtn.textContent = "Verify";

        if (data.success) {
          showAccountSettingsModal();
        } else {
          verifyPasswordError.textContent = data.error || "Password verification failed";
          verifyPasswordError.classList.add("show");
        }
      })
      .catch(error => {
        verifyPasswordSubmitBtn.disabled = false;
        verifyPasswordSubmitBtn.textContent = "Verify";
        verifyPasswordError.textContent = "Network error. Please try again.";
        verifyPasswordError.classList.add("show");
        console.error("Error:", error);
      });
  });

  verifyPasswordInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
      verifyPasswordSubmitBtn.click();
    }
  });

  // ===== Event Listeners: Account Settings Modal =====
  closeAccountSettingsModal.addEventListener("click", function () {
    closeAllModals();
  });

  accountSettingsCancelBtn.addEventListener("click", function () {
    closeAllModals();
  });

  accountSettingsModal.addEventListener("click", function (e) {
    if (e.target === accountSettingsModal) {
      closeAllModals();
    }
  });

  changeUsernameOptionBtn.addEventListener("click", function () {
    showChangeUsernameModal();
  });

  changePasswordOptionBtn.addEventListener("click", function () {
    // Open change password modal (account already verified)
    accountSettingsModal.classList.remove("show");
    changePasswordModal.classList.add("show");
    document.getElementById("currentPasswordInput").focus();
  });

  // ===== Event Listeners: Change Username Modal =====
  closeModalBtn.addEventListener("click", function () {
    changeUsernameModal.classList.remove("show");
    clearMessages();
    newUsernameInput.value = "";
  });

  changeUsernameCancelBtn.addEventListener("click", function () {
    changeUsernameModal.classList.remove("show");
    clearMessages();
    newUsernameInput.value = "";
  });

  changeUsernameModal.addEventListener("click", function (e) {
    if (e.target === changeUsernameModal) {
      changeUsernameModal.classList.remove("show");
      clearMessages();
    }
  });

  // ===== Helper Functions =====
  function clearMessages() {
    usernameError.classList.remove("show");
    usernameSuccess.classList.remove("show");
    usernameError.textContent = "";
    usernameSuccess.textContent = "";
  }

  function validateUsername(username) {
    if (!username) {
      return "Username cannot be empty";
    }
    if (username.length < 3 || username.length > 20) {
      return "Username must be between 3 and 20 characters";
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return "Username can only contain letters, numbers, and underscore";
    }
    if (/^\d+$/.test(username)) {
      return "Username cannot be only numbers";
    }
    if (username.toLowerCase() === "admin" || username.toLowerCase() === "reconx") {
      return "This username is reserved";
    }
    return null;
  }

  // ===== Change Username Submission =====
  changeUsernameSubmitBtn.addEventListener("click", function () {
    clearMessages();
    const newUsername = newUsernameInput.value.trim();

    const validationError = validateUsername(newUsername);
    if (validationError) {
      usernameError.textContent = validationError;
      usernameError.classList.add("show");
      return;
    }

    changeUsernameSubmitBtn.disabled = true;
    changeUsernameSubmitBtn.textContent = "Changing...";

    fetch("/change-username", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ new_username: newUsername })
    })
      .then(response => response.json())
      .then(data => {
        changeUsernameSubmitBtn.disabled = false;
        changeUsernameSubmitBtn.textContent = "Change Username";

        if (data.success) {
          usernameSuccess.textContent = data.message || "Username changed successfully";
          usernameSuccess.classList.add("show");
          newUsernameInput.value = "";

          setTimeout(() => {
            usernameDisplay.textContent = `👤 ${newUsername}`;
            changeUsernameModal.classList.remove("show");
          }, 1500);
        } else {
          usernameError.textContent = data.error || "Failed to change username";
          usernameError.classList.add("show");
        }
      })
      .catch(error => {
        changeUsernameSubmitBtn.disabled = false;
        changeUsernameSubmitBtn.textContent = "Change Username";
        usernameError.textContent = "Network error. Please try again.";
        usernameError.classList.add("show");
        console.error("Error:", error);
      });
  });

  newUsernameInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
      changeUsernameSubmitBtn.click();
    }
  });

  // ===== Event Listeners: Change Password Modal =====
  const closeChangePasswordModal = document.getElementById("closeChangePasswordModal");
  const changePasswordModal = document.getElementById("changePasswordModal");
  const currentPasswordInput = document.getElementById("currentPasswordInput");
  const newPasswordInput = document.getElementById("newPasswordInput");
  const confirmPasswordInput = document.getElementById("confirmPasswordInput");
  const changePasswordError = document.getElementById("changePasswordError");
  const changePasswordSuccess = document.getElementById("changePasswordSuccess");
  const changePasswordSubmitBtn = document.getElementById("changePasswordSubmitBtn");
  const changePasswordCancelBtn = document.getElementById("changePasswordCancelBtn");

  function clearPasswordMessages() {
    changePasswordError.classList.remove("show");
    changePasswordSuccess.classList.remove("show");
    changePasswordError.textContent = "";
    changePasswordSuccess.textContent = "";
  }

  closeChangePasswordModal.addEventListener("click", function () {
    changePasswordModal.classList.remove("show");
    clearPasswordMessages();
  });

  changePasswordCancelBtn.addEventListener("click", function () {
    changePasswordModal.classList.remove("show");
    clearPasswordMessages();
  });

  changePasswordModal.addEventListener("click", function (e) {
    if (e.target === changePasswordModal) {
      changePasswordModal.classList.remove("show");
      clearPasswordMessages();
    }
  });

  function validateNewPassword(curr, nw, conf) {
    if (!curr) return "Current password required";
    if (!nw || nw.length < 8) return "New password must be at least 8 characters";
    if (nw !== conf) return "Password confirmation does not match";
    if (nw === curr) return "New password must be different from current password";
    return null;
  }

  changePasswordSubmitBtn.addEventListener("click", function () {
    clearPasswordMessages();
    const curr = currentPasswordInput.value;
    const nw = newPasswordInput.value;
    const conf = confirmPasswordInput.value;

    const vErr = validateNewPassword(curr, nw, conf);
    if (vErr) {
      changePasswordError.textContent = vErr;
      changePasswordError.classList.add("show");
      return;
    }

    changePasswordSubmitBtn.disabled = true;
    changePasswordSubmitBtn.textContent = "Changing...";

    fetch("/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ current_password: curr, new_password: nw })
    })
      .then(res => res.json())
      .then(data => {
        changePasswordSubmitBtn.disabled = false;
        changePasswordSubmitBtn.textContent = "Change Password";
        if (data.success) {
          changePasswordSuccess.textContent = data.message || "Password changed successfully";
          changePasswordSuccess.classList.add("show");
          currentPasswordInput.value = newPasswordInput.value = confirmPasswordInput.value = "";
          setTimeout(() => {
            changePasswordModal.classList.remove("show");
            clearPasswordMessages();
          }, 1500);
        } else {
          changePasswordError.textContent = data.error || "Failed to change password";
          changePasswordError.classList.add("show");
        }
      })
      .catch(err => {
        changePasswordSubmitBtn.disabled = false;
        changePasswordSubmitBtn.textContent = "Change Password";
        changePasswordError.textContent = "Network error. Please try again.";
        changePasswordError.classList.add("show");
        console.error(err);
      });
  });
});
