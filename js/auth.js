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
      <div style="display:flex;align-items:center;gap:8px;min-width:0;">
        ${photo}
        <span class="nav-user-name" style="font-size:0.82rem;color:var(--text-secondary);
                     white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100px;">
          ${user.displayName || user.email.split('@')[0]}
        </span>
        <button onclick="SBKSignOut()" class="btn btn-outline btn-sm nav-logout-btn">
          <span class="nav-logout-text">Logout</span>
          <i class="fa-solid fa-right-from-bracket nav-logout-icon" style="display:none;"></i>
        </button>
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

  // ── Mobile nav: overlay + outside-click to close ─────────────
  function initMobileNav() {
    // Inject overlay div once
    if (!document.getElementById('navOverlay')) {
      const overlay = document.createElement('div');
      overlay.id = 'navOverlay';
      overlay.className = 'nav-overlay';
      overlay.addEventListener('click', closeNav);
      document.body.appendChild(overlay);
    }
  }

  function closeNav() {
    const nav = document.getElementById('navLinks');
    const overlay = document.getElementById('navOverlay');
    if (nav) nav.classList.remove('open');
    if (overlay) overlay.classList.remove('visible');
  }

  // Override toggleNav globally so all pages use this version
  window.toggleNav = function() {
    const nav = document.getElementById('navLinks');
    const overlay = document.getElementById('navOverlay');
    if (!nav) return;
    const isOpen = nav.classList.toggle('open');
    if (overlay) overlay.classList.toggle('visible', isOpen);
  };

  // Run once DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      initAuthUI();
      initMobileNav();
    });
  } else {
    initAuthUI();
    initMobileNav();
  }

})();
