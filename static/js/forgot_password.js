/**
 * forgot_password.js
 * Handles the multi-step Forgot Password flow:
 *   Step 1 → Send OTP to email
 *   Step 2 → Verify OTP (with countdown + resend)
 *   Step 3 → Reset password (with live validation)
 *   Step 4 → Success + redirect
 */

'use strict';

// ─── State ───────────────────────────────────────────────
let currentEmail  = '';
let countdownTimer = null;

// ─── DOM helpers ─────────────────────────────────────────
const $ = id => document.getElementById(id);

function showError(boxId, msg) {
  const el = $(boxId);
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideMsg(boxId) {
  const el = $(boxId);
  if (el) el.classList.add('hidden');
}

function showSuccess(boxId, msg) {
  const el = $(boxId);
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
}

function setLoading(btnId, labelId, loading, defaultText) {
  const btn   = $(btnId);
  const label = $(labelId);
  if (!btn || !label) return;
  btn.disabled  = loading;
  label.textContent = loading ? 'Please wait…' : defaultText;
}

// ─── Step navigation ─────────────────────────────────────
function goToStep(n) {
  [1, 2, 3, 4].forEach(i => {
    const el = $('step' + i);
    if (el) el.classList.toggle('active', i === n);
  });
  updateStepIndicator(n);
}

function updateStepIndicator(active) {
  // Step 4 (success) has no indicator
  const total = 3;
  for (let i = 1; i <= total; i++) {
    const dot  = $('dot-' + i);
    const line = $('line-' + i);
    if (!dot) continue;

    if (i < active) {
      dot.className = 'step-dot done';
      dot.innerHTML = '<i class="ph ph-check" style="font-size:12px;"></i>';
    } else if (i === active) {
      dot.className = 'step-dot active';
      dot.textContent = i;
    } else {
      dot.className = 'step-dot pending';
      dot.textContent = i;
    }

    if (line) {
      line.className = i < active ? 'step-line done' : 'step-line';
    }
  }

  // Hide indicator on success step
  const indicator = $('stepIndicator');
  if (indicator) indicator.style.display = active === 4 ? 'none' : 'flex';
}

// ─── STEP 1: Send OTP ────────────────────────────────────
$('emailForm').addEventListener('submit', async e => {
  e.preventDefault();
  hideMsg('emailError');
  hideMsg('emailSuccess');

  const email = $('emailInput').value.trim().toLowerCase();
  if (!email) { showError('emailError', 'Please enter your email address.'); return; }

  currentEmail = email;
  setLoading('sendCodeBtn', 'sendCodeLabel', true, 'Send Code');

  try {
    const res  = await fetch('/forgot-password/send-otp', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showSuccess('emailSuccess', 'Code sent! Check your inbox (and spam folder).');
      // Brief pause so the user sees the message, then advance
      setTimeout(() => {
        $('emailDisplay').textContent = currentEmail;
        goToStep(2);
        startCountdown();
      }, 1200);
    } else {
      showError('emailError', data.error || 'Something went wrong. Please try again.');
    }
  } catch {
    showError('emailError', 'Network error. Please check your connection.');
  } finally {
    setLoading('sendCodeBtn', 'sendCodeLabel', false, 'Send Code');
  }
});

// ─── OTP Countdown (10 min = 600 s) ──────────────────────
function startCountdown(seconds = 600) {
  clearInterval(countdownTimer);
  $('resendBtn').disabled = true;
  let remaining = seconds;

  function tick() {
    const m = String(Math.floor(remaining / 60)).padStart(2, '0');
    const s = String(remaining % 60).padStart(2, '0');
    $('otpCountdown').textContent = `Code expires in ${m}:${s}`;
    if (remaining <= 0) {
      clearInterval(countdownTimer);
      $('otpCountdown').textContent = 'Code expired. Please request a new one.';
      $('otpCountdown').style.color = '#F87171';
      $('resendBtn').disabled = false;
    }
    remaining--;
  }

  tick();
  countdownTimer = setInterval(tick, 1000);
}

// ─── Resend button ────────────────────────────────────────
$('resendBtn').addEventListener('click', async () => {
  hideMsg('otpError');
  $('resendBtn').disabled = true;

  try {
    const res  = await fetch('/forgot-password/send-otp', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: currentEmail })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      $('otpInput').value = '';
      $('otpCountdown').style.color = '';
      startCountdown();
    } else {
      showError('otpError', data.error || 'Failed to resend. Please try again.');
      $('resendBtn').disabled = false;
    }
  } catch {
    showError('otpError', 'Network error. Please check your connection.');
    $('resendBtn').disabled = false;
  }
});

// ─── STEP 2: Verify OTP ──────────────────────────────────
$('otpForm').addEventListener('submit', async e => {
  e.preventDefault();
  hideMsg('otpError');

  const otp = $('otpInput').value.trim();
  if (otp.length !== 6 || !/^\d{6}$/.test(otp)) {
    showError('otpError', 'Please enter the 6-digit code from your email.');
    return;
  }

  setLoading('verifyBtn', 'verifyLabel', true, 'Verify Code');

  try {
    const res  = await fetch('/forgot-password/verify-otp', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: currentEmail, otp })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      clearInterval(countdownTimer);
      goToStep(3);
    } else {
      showError('otpError', data.error || 'Invalid code. Please try again.');
    }
  } catch {
    showError('otpError', 'Network error. Please check your connection.');
  } finally {
    setLoading('verifyBtn', 'verifyLabel', false, 'Verify Code');
  }
});

// ─── Only allow digits in OTP input ──────────────────────
$('otpInput').addEventListener('input', function () {
  this.value = this.value.replace(/\D/g, '').slice(0, 6);
});

// ─── STEP 3: Live password validation ────────────────────
const rules = [
  { id: 'check-length',  test: p => p.length >= 8 },
  { id: 'check-upper',   test: p => /[A-Z]/.test(p) },
  { id: 'check-number',  test: p => /\d/.test(p) },
  { id: 'check-special', test: p => /[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\/;']/.test(p) },
];

$('newPassword').addEventListener('input', function () {
  const val = this.value;
  rules.forEach(r => {
    const el = $(r.id);
    if (!el) return;
    if (r.test(val)) {
      el.classList.replace('invalid', 'valid');
    } else {
      el.classList.replace('valid', 'invalid');
    }
  });
});

// ─── Password eye toggles ─────────────────────────────────
function setupToggle(inputId, iconId) {
  const btn  = document.querySelector(`button[id="toggle${inputId.charAt(0).toUpperCase() + inputId.slice(1).replace('Password', '')}"]`);
  // Simpler: use dedicated toggle IDs
}

function bindEyeToggle(toggleBtnId, inputId, iconId) {
  const btn   = $(toggleBtnId);
  const input = $(inputId);
  const icon  = $(iconId);
  if (!btn || !input || !icon) return;

  btn.addEventListener('click', () => {
    const showing = input.type === 'text';
    input.type    = showing ? 'password' : 'text';
    icon.className = showing ? 'ph ph-eye text-lg' : 'ph ph-eye-slash text-lg';
  });
}

bindEyeToggle('toggleNew',     'newPassword',     'eyeNew');
bindEyeToggle('toggleConfirm', 'confirmPassword', 'eyeConfirm');

// ─── STEP 3: Reset password submit ───────────────────────
$('resetForm').addEventListener('submit', async e => {
  e.preventDefault();
  hideMsg('resetError');

  const newPassword     = $('newPassword').value;
  const confirmPassword = $('confirmPassword').value;

  if (!newPassword) { showError('resetError', 'Please enter a new password.'); return; }
  if (newPassword !== confirmPassword) { showError('resetError', 'Passwords do not match.'); return; }

  // Client-side strength check
  const failed = rules.filter(r => !r.test(newPassword));
  if (failed.length > 0) {
    showError('resetError', 'Your password does not meet all requirements above.');
    return;
  }

  setLoading('resetBtn', 'resetLabel', true, 'Reset Password');

  try {
    const res  = await fetch('/forgot-password/reset-password', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email:            currentEmail,
        new_password:     newPassword,
        confirm_password: confirmPassword
      })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      goToStep(4);
      startRedirectCountdown();
    } else {
      showError('resetError', data.error || 'Failed to reset password. Please try again.');
    }
  } catch {
    showError('resetError', 'Network error. Please check your connection.');
  } finally {
    setLoading('resetBtn', 'resetLabel', false, 'Reset Password');
  }
});

// ─── STEP 4: Redirect countdown ──────────────────────────
function startRedirectCountdown(seconds = 5) {
  let remaining = seconds;
  const el = $('redirectCountdown');

  const tick = () => {
    if (el) el.textContent = remaining;
    if (remaining <= 0) {
      window.location.href = '/login';
    }
    remaining--;
  };

  tick();
  setInterval(tick, 1000);
}
