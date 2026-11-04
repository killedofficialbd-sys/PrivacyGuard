import { initializeApp } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js";
import { getAuth, GoogleAuthProvider, setPersistence, browserLocalPersistence } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js";
import { getFirestore, initializeFirestore, persistentLocalCache, persistentMultipleTabManager } from "https://www.gstatic.com/firebasejs/13.2.0/firebase-firestore.js";

// Публичная конфигурация Firebase Web App. Это не серверный секрет.
const firebaseConfig = {
  apiKey: "AIzaSyAQ6OogORrBdlH_lYM0VsOkyP273HE27cg",
  authDomain: "privacyguard-929ec.firebaseapp.com",
  projectId: "privacyguard-929ec",
  storageBucket: "privacyguard-929ec.firebasestorage.app",
  messagingSenderId: "934051353809",
  appId: "1:934051353809:web:31b0e15a73d9a696e761f0",
  measurementId: "G-QJCR70VR1V"
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
// Persistent Firestore cache is opt-in and device-local. It is intended only for a trusted device.
// Firebase warns that web cache survives sign-out; do not enable it on shared/public devices.
const trustedOfflineCache = (() => {
  try { return localStorage.getItem("privacyguard:trusted-offline-cache") === "true"; }
  catch { return false; }
})();
let firestoreDb;
if (trustedOfflineCache) {
  try {
    firestoreDb = initializeFirestore(app, {
      localCache: persistentLocalCache({ tabManager: persistentMultipleTabManager() })
    });
  } catch (error) {
    console.warn("Persistent Firestore cache unavailable; using memory cache:", error);
    firestoreDb = getFirestore(app);
  }
} else {
  firestoreDb = getFirestore(app);
}
export const db = firestoreDb;
export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: "select_account" });

setPersistence(auth, browserLocalPersistence).catch((error) => {
  console.warn("Не удалось включить постоянную сессию Firebase:", error);
});
