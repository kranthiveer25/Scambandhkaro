// ═══════════════════════════════════════════════════════════════════
//  AUTH.JS — ScamBandhKaro
//  • Watches Firebase auth state on every page
//  • Updates navbar to show user avatar + logout when signed in
//  • Exposes SBKSignIn() and SBKSignOut() globally
// ═══════════════════════════════════════════════════════════════════

(function () {

  // ── Sign in with Google popup ──────────────────────────────────
  window.SBKSignIn = function () {
    if (!window.fbAuth) return;
    fbAuth.signInWithPopup(window.googleProvider)
      .then(function (result) {
        // On login.html / signup.html → go home after sign in
        if (window.location.pathname.includes('login') ||
            window.location.pathname.includes('signup')) {
          window.location.href = 'index.html';
        }
      })
      .catch(function (err) {
        console.error('Sign in error:', err);
        const errEl = document.getElementById('loginError');
        if (errEl) {
          errEl.classList.remove('hidden');
          errEl.textContent = 'Sign-in failed: ' + (err.message || 'Please try again.');
        }
      });
  };

  // ── Sign out ───────────────────────────────────────────────────
  window.SBKSignOut = function () {
    if (!window.fbAuth) return;
    fbAuth.signOut().then(function () {
      window.location.href = 'index.html';
    });
  };

  // ── Build the navbar HTML for a logged-in user ─────────────────
  function loggedInNav(user) {
    const photo = user.photoURL
      ? `<img src="${user.photoURL}" alt=""
           style="width:32px;height:32px;border-radius:50%;border:2px solid var(--primary);
                  object-fit:cover;flex-shrink:0;">`
      : `<div style="width:32px;height:32px;border-radius:50%;background:rgba(16,185,129,0.2);
              border:2px solid var(--primary);display:flex;align-items:center;justify-content:center;
              font-size:0.85rem;font-weight:700;color:var(--primary);flex-shrink:0;">
           ${(user.displayName || user.email || 'U')[0].toUpperCase()}
         </div>`;

    return `
      <div style="display:flex;align-items:center;gap:8px;">
        ${photo}
        <span style="font-size:0.82rem;color:var(--text-secondary);max-width:100px;
                     white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
          ${user.displayName || user.email.split('@')[0]}
        </span>
        <button onclick="SBKSignOut()" class="btn btn-outline btn-sm">Logout</button>
      </div>
      <button class="hamburger" onclick="toggleNav()" aria-label="Menu">
        <span></span><span></span><span></span>
      </button>`;
  }

  // ── Build the navbar HTML for a logged-out user ────────────────
  function loggedOutNav() {
    return `
      <a href="login.html" class="btn btn-outline btn-sm">Login</a>
      <a href="signup.html" class="btn btn-primary btn-sm">Sign Up</a>
      <button class="hamburger" onclick="toggleNav()" aria-label="Menu">
        <span></span><span></span><span></span>
      </button>`;
  }

  // ── Watch auth state ───────────────────────────────────────────
  function initAuthUI() {
    if (typeof firebase === 'undefined' || !window.fbAuth) return;

    fbAuth.onAuthStateChanged(function (user) {
      // Store current user globally so report.html can access it
      window.currentUser = user || null;

      const navActions = document.querySelector('.navbar-actions');
      if (navActions) {
        navActions.innerHTML = user ? loggedInNav(user) : loggedOutNav();
      }
    });
  }

  // Run once DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAuthUI);
  } else {
    initAuthUI();
  }

})();
