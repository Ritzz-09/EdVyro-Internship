/**
 * CampusPortal - Client Utilities
 * 100% Local Vanilla JavaScript - Zero External CDNs or Trackers.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Quick-fill demo credentials on the login screen
  const demoButtons = document.querySelectorAll(".demo-user-btn");
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");

  if (demoButtons.length && usernameInput && passwordInput) {
    demoButtons.forEach(btn => {
      btn.addEventListener("click", () => {
        const u = btn.getAttribute("data-username");
        const p = btn.getAttribute("data-password");
        if (u && p) {
          usernameInput.value = u;
          passwordInput.value = p;
          // Visual highlight to confirm autofill
          usernameInput.focus();
        }
      });
    });
  }

  // Dismiss flash alerts
  const alertCloseButtons = document.querySelectorAll(".alert-close");
  alertCloseButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const alertBox = btn.closest(".alert");
      if (alertBox) {
        alertBox.style.display = "none";
      }
    });
  });
});
