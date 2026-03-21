// ═══════════════════════════════════════════════════════════════════
//  FIREBASE CONFIG — ScamBandhKaro
//
//  HOW TO SET UP (5 minutes):
//  1. Go to console.firebase.google.com
//  2. Click "Add project" → name it "scambandhkaro" → Create
//  3. In the left menu: Authentication → Get started → Google → Enable → Save
//  4. In the left menu: Firestore Database → Create database → Start in test mode → Next
//  5. Click the gear icon (Project Settings) → scroll down to "Your apps"
//  6. Click the </> Web icon → register app → copy the firebaseConfig object
//  7. Paste the values below, replacing each "YOUR_..." placeholder
// ═══════════════════════════════════════════════════════════════════

const firebaseConfig = {
  apiKey:            "AIzaSyBdlMQctWAdXQUBIxGYyq2E2n8gpG5I5Ds",
  authDomain:        "scambandhkaro.firebaseapp.com",
  projectId:         "scambandhkaro",
  storageBucket:     "scambandhkaro.firebasestorage.app",
  messagingSenderId: "265295514944",
  appId:             "1:265295514944:web:869e447f8955f66b583ea5",
  measurementId:     "G-F4DPRT8C2P"
};

// ── Init (guard against double-init) ───────────────────────────────
if (!firebase.apps.length) {
  firebase.initializeApp(firebaseConfig);
}

// ── Expose globally so all pages can use them ──────────────────────
window.fbAuth         = firebase.auth();
window.fbDb           = firebase.firestore();
window.googleProvider = new firebase.auth.GoogleAuthProvider();

// Always show the Google account picker (even if already signed in)
window.googleProvider.setCustomParameters({ prompt: 'select_account' });
