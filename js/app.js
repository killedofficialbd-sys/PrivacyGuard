import { auth, db, googleProvider } from "./firebase.js";
import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  onAuthStateChanged,
  sendPasswordResetEmail,
  sendEmailVerification,
  updateProfile,
  signOut
} from "https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js";
import {
  doc,
  getDoc,
  getDocFromCache,
  setDoc,
  updateDoc,
  collection,
  addDoc,
  getDocs,
  getDocsFromCache,
  query,
  orderBy,
  limit,
  serverTimestamp,
  deleteDoc
} from "https://www.gstatic.com/firebasejs/13.2.0/firebase-firestore.js";

// Restored the IPinfo Lite token from the supplied PrivacyGuard 2.3 project.
// This is a browser-visible token; restrict its quota/referrers in the IPinfo dashboard.
const IPINFO_TOKEN = "e95bb532b1f3b9";
const IPINFO_BASE = "https://api.ipinfo.io/lite";
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const TASKS = ["uniquePasswords", "twoFactor", "recovery", "sessions", "updates", "privacy"];
const PAGE_TITLES = {
  overview: "Обзор", ip: "IP Intelligence", domains: "Домены и DNS",
  identifiers: "BIN / VIN / IBAN", username: "Username OSINT",
  phone: "Телефон и email", url: "URL-анализ", tools: "Инструменты",
  history: "История", recommendations: "Центр защиты", profile: "Мой профиль",
  projects: "Мои проекты", assets: "Мои активы", monitoring: "Мониторинг", reports: "Отчёты",
  notifications: "Уведомления", favorites: "Избранное", settings: "Настройки", academy: "Справка и источники", labs: "Security Lab", legal: "Документы и соглашения"
};
const state = {
  user: null, profile: null, history: [], domains: [], completedTasks: [],
  activePage: "overview", historyFilter: "", accountLoadVersion: 0
};

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}
function toast(message, type = "success") {
  const box = $("#toastContainer");
  if (!box) return;
  const el = document.createElement("div");
  el.className = `toast ${type === "error" ? "error" : ""}`;
  el.innerHTML = `<svg><use href="#${type === "error" ? "i-alert" : "i-check"}"></use></svg><span>${escapeHtml(message)}</span>`;
  box.append(el);
  setTimeout(() => el.remove(), 4300);
}
function friendlyAuthError(error) {
  const messages = {
    "auth/invalid-email": "Проверь email.",
    "auth/user-disabled": "Этот аккаунт отключён.",
    "auth/user-not-found": "Аккаунт не найден.",
    "auth/wrong-password": "Неверный email или пароль.",
    "auth/invalid-credential": "Неверный email или пароль.",
    "auth/email-already-in-use": "Этот email уже зарегистрирован.",
    "auth/weak-password": "Пароль слишком простой. Нужно минимум 8 символов.",
    "auth/too-many-requests": "Слишком много попыток. Попробуй позже.",
    "auth/network-request-failed": "Нет соединения. Проверь интернет.",
    "auth/popup-closed-by-user": "Окно Google закрыто до входа.",
    "auth/popup-blocked": "Браузер заблокировал окно Google.",
    "auth/unauthorized-domain": "Добавь этот адрес в Firebase Authentication → Authorized domains."
  };
  return messages[error?.code] || error?.message || "Не удалось выполнить действие. Проверь настройки Firebase.";
}
function setBusy(button, busy, text = "Выполняется…") {
  if (!button) return;
  if (busy) {
    button.dataset.oldHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="button-spinner"></span>${escapeHtml(text)}`;
  } else {
    button.disabled = false;
    button.innerHTML = button.dataset.oldHtml || button.innerHTML;
    delete button.dataset.oldHtml;
  }
}
function setAuthTab(tab) {
  const register = tab === "register";
  $("#loginForm").hidden = register;
  $("#registerForm").hidden = !register;
  $$(".auth-tab").forEach((b) => b.classList.toggle("active", b.dataset.authTab === tab));
  $("#authTitle").textContent = register ? "Создай свой аккаунт" : "С возвращением";
  $("#authSubtitle").textContent = register
    ? "Зарегистрируйся, чтобы сохранять историю OSINT-исследований."
    : "Войди, чтобы открыть свою OSINT-панель.";
  $("#authBottom").innerHTML = register
    ? 'Уже есть аккаунт? <button type="button" class="text-button" data-auth-tab="login">Войти</button>'
    : 'Нет аккаунта? <button type="button" class="text-button" data-auth-tab="register">Создать аккаунт</button>';
}
function showAuth() {
  $("#bootScreen").hidden = true;
  $("#appView").hidden = true;
  $("#authView").hidden = false;
  closeMobileSidebar();
}
function showApplication() {
  $("#bootScreen").hidden = true;
  $("#authView").hidden = true;
  $("#appView").hidden = false;
  renderProfile();
  goToPage("overview");
}
function closeMobileSidebar() {
  $("#sidebar")?.classList.remove("open");
  $("#sidebarScrim")?.classList.remove("show");
}
function openMobileSidebar() {
  $("#sidebar")?.classList.add("open");
  $("#sidebarScrim")?.classList.add("show");
}
function goToPage(page) {
  if (!PAGE_TITLES[page]) return;
  state.activePage = page;
  $$(".page-panel").forEach((panel) => panel.classList.toggle("active", panel.id === `page-${page}`));
  $$(".nav-item[data-page]").forEach((button) => button.classList.toggle("active", button.dataset.page === page));
  $("#breadcrumbTitle").textContent = PAGE_TITLES[page];
  closeMobileSidebar();
  if (page === "history") renderHistory();
  if (page === "domains") renderDomains();
  if (page === "recommendations") renderChecklist();
  window.location.hash = page;
  window.dispatchEvent(new CustomEvent("pg:navigate", { detail: { page } }));
}

async function ensureUserDocument(user) {
  const ref = doc(db, "users", user.uid);
  let snap;
  const fallback = user.displayName || (user.email ? user.email.split("@")[0] : "Пользователь");
  try { snap = await getDoc(ref); }
  catch (error) {
    try { snap = await getDocFromCache(ref); }
    catch {
      if (navigator.onLine === false || error?.code === "unavailable") {
        return { uid:user.uid, displayName:fallback, email:user.email || "", photoURL:user.photoURL || "", completedTasks:[], offlineFallback:true };
      }
      throw error;
    }
  }
  if (!snap.exists()) {
    const profile = {
      uid: user.uid, displayName: fallback, email: user.email || "",
      photoURL: user.photoURL || "", completedTasks: [],
      createdAt: serverTimestamp(), updatedAt: serverTimestamp()
    };
    try { await setDoc(ref, profile, { merge: true }); }
    catch (error) {
      if (navigator.onLine === false || error?.code === "unavailable") return { ...profile, createdAt: new Date(), offlineFallback:true };
      throw error;
    }
    return { ...profile, createdAt: new Date() };
  }
  const profile = snap.data();
  if (!profile.displayName && fallback) {
    await updateDoc(ref, { displayName: fallback, updatedAt: serverTimestamp() });
    profile.displayName = fallback;
  }
  return profile;
}
async function loadHistory(user = state.user) {
  if (!user) return;
  const ref = collection(db, "users", user.uid, "scans");
  let snap;
  try { snap = await getDocs(query(ref, orderBy("createdAt", "desc"), limit(100))); }
  catch (error) { try { snap = await getDocsFromCache(query(ref, orderBy("createdAt", "desc"), limit(100))); } catch { if (navigator.onLine === false || error?.code === "unavailable") { if (state.user?.uid === user.uid) state.history = []; return; } throw error; } }
  if (state.user?.uid === user.uid) state.history = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}
async function loadDomains(user = state.user) {
  if (!user) return;
  const ref = collection(db, "users", user.uid, "domains");
  let snap;
  try { snap = await getDocs(ref); }
  catch (error) { try { snap = await getDocsFromCache(ref); } catch { if (navigator.onLine === false || error?.code === "unavailable") { if (state.user?.uid === user.uid) state.domains = []; return; } throw error; } }
  if (state.user?.uid === user.uid) {
    state.domains = snap.docs.map((d) => ({ id: d.id, ...d.data() })).sort((a, b) => (a.domain || "").localeCompare(b.domain || ""));
  }
}
async function loadAccountData(user, version = state.accountLoadVersion) {
  const isCurrent = () => state.user?.uid === user.uid && state.accountLoadVersion === version;
  try {
    const profile = await ensureUserDocument(user);
    if (!isCurrent()) return;
    state.profile = profile;
    state.completedTasks = Array.isArray(profile.completedTasks)
      ? profile.completedTasks.filter((id) => TASKS.includes(id)) : [];
    await Promise.all([loadHistory(user), loadDomains(user)]);
    if (!isCurrent()) return;
    showApplication();
    renderEverything();
  } catch (error) {
    console.error("PrivacyGuard account load:", error);
    if (!isCurrent()) return;
    showAuth();
    toast("Вход выполнен, но Firestore недоступен. Проверь Firestore Rules и базу данных.", "error");
  }
}
async function loginWithEmail(event) {
  event.preventDefault();
  const email = $("#loginEmail").value.trim().toLowerCase();
  const password = $("#loginPassword").value;
  if (!/^\S+@\S+\.\S+$/.test(email) || !password) return toast("Введи корректный email и пароль.", "error");
  const btn = $("#loginSubmit"); setBusy(btn, true, "Входим…");
  try { await signInWithEmailAndPassword(auth, email, password); $("#loginForm").reset(); toast("Вход выполнен."); }
  catch (error) { console.error(error); toast(friendlyAuthError(error), "error"); }
  finally { setBusy(btn, false); }
}
async function registerWithEmail(event) {
  event.preventDefault();
  const name = $("#registerName").value.trim().slice(0, 48);
  const email = $("#registerEmail").value.trim().toLowerCase();
  const password = $("#registerPassword").value;
  const confirm = $("#registerPasswordConfirm").value;
  if (name.length < 2) return toast("Имя должно содержать минимум 2 символа.", "error");
  if (!/^\S+@\S+\.\S+$/.test(email)) return toast("Проверь email.", "error");
  if (password.length < 8) return toast("Пароль должен содержать минимум 8 символов.", "error");
  if (password !== confirm) return toast("Пароли не совпадают.", "error");
  const btn = $("#registerSubmit"); setBusy(btn, true, "Создаём аккаунт…");
  try {
    const credential = await createUserWithEmailAndPassword(auth, email, password);
    await updateProfile(credential.user, { displayName: name });
    await sendEmailVerification(credential.user);
    await setDoc(doc(db, "users", credential.user.uid), {
      uid: credential.user.uid, displayName: name, email,
      photoURL: credential.user.photoURL || "", completedTasks: [],
      createdAt: serverTimestamp(), updatedAt: serverTimestamp()
    }, { merge: true });
    $("#registerForm").reset();
    toast("Аккаунт создан. Письмо подтверждения отправлено на почту.");
  } catch (error) { console.error(error); toast(friendlyAuthError(error), "error"); }
  finally { setBusy(btn, false); }
}
async function loginWithGoogle() {
  const btn = $("#googleSignIn"); setBusy(btn, true, "Подключаем Google…");
  try { await signInWithPopup(auth, googleProvider); }
  catch (error) {
    console.error(error);
    if (["auth/popup-blocked", "auth/operation-not-supported-in-this-environment"].includes(error?.code)) {
      try { await signInWithRedirect(auth, googleProvider); return; }
      catch (redirectError) { toast(friendlyAuthError(redirectError), "error"); }
    } else toast(friendlyAuthError(error), "error");
  } finally { btn.disabled = false; btn.innerHTML = '<svg><use href="#i-google"></use></svg> Google'; }
}
async function resetPassword() {
  const email = $("#loginEmail").value.trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) { $("#loginEmail").focus(); return toast("Сначала введи email в поле входа.", "error"); }
  try { await sendPasswordResetEmail(auth, email); toast("Письмо для сброса пароля отправлено."); }
  catch (error) { toast(friendlyAuthError(error), "error"); }
}
async function logout() {
  try { await signOut(auth); toast("Ты вышел из аккаунта."); }
  catch (error) { toast(friendlyAuthError(error), "error"); }
}
function renderProfile() {
  const user = state.user;
  if (!user) return;
  const name = state.profile?.displayName || user.displayName || user.email?.split("@")[0] || "Пользователь";
  const initials = name.trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
  $("#topAvatar").textContent = initials || "PG";
  $("#topUserName").textContent = name;
  $("#topUserEmail").textContent = user.email || "";
  $("#profileAvatar").textContent = initials || "PG";
  $("#profileDisplayName").textContent = name;
  $("#profileDisplayEmail").textContent = user.email || "";
  $("#profileName").value = name;
  $("#profileEmail").value = user.email || "";
  $("#profileUid").textContent = user.uid;
  $("#profileProvider").textContent = user.providerData?.map((p) => p.providerId).join(", ") || "Email / Password";
  const created = user.metadata?.creationTime ? new Date(user.metadata.creationTime) : null;
  $("#profileCreated").textContent = created ? created.toLocaleDateString("ru-RU") : "—";
  $("#welcomeName").textContent = name;
}
async function saveProfile(event) {
  event.preventDefault();
  const name = $("#profileName").value.trim().slice(0, 48);
  if (name.length < 2) return toast("Имя должно содержать минимум 2 символа.", "error");
  try {
    await updateProfile(state.user, { displayName: name });
    await setDoc(doc(db, "users", state.user.uid), { uid: state.user.uid, displayName: name, email: state.user.email || "", updatedAt: serverTimestamp() }, { merge: true });
    state.profile = { ...state.profile, displayName: name };
    renderProfile(); toast("Профиль сохранён.");
  } catch (error) { toast(`Не удалось сохранить профиль: ${error.message || "ошибка Firestore"}`, "error"); }
}
async function saveScan(kind, target, summary) {
  const owner = state.user;
  if (!owner) return false;
  const allowedKinds = ["ip", "domain", "bin", "vin", "iban", "username", "phone", "email", "url", "mac", "hash", "file", "password", "cve", "cidr", "jwt", "convert", "timestamp", "json", "passwordgen", "hashid", "uuid", "mailheader"];
  if (!allowedKinds.includes(kind)) kind = "tool";
  const safeTarget = String(target).slice(0, 120);
  const safeSummary = String(summary).slice(0, 500);
  try {
    const createdAt = new Date();
    const ref = await addDoc(collection(db, "users", owner.uid, "scans"), {
      kind, target: safeTarget, summary: safeSummary, createdAt: serverTimestamp()
    });
    // Do not let a delayed request from one account mutate another account's UI.
    if (state.user?.uid === owner.uid) {
      state.history.unshift({ id: ref.id, kind, target: safeTarget, summary: safeSummary, createdAt });
      state.history = state.history.slice(0, 100);
      renderHistory(); renderOverview();
      loadHistory(owner).then(() => {
        if (state.user?.uid === owner.uid) { renderHistory(); renderOverview(); }
      }).catch((error) => console.warn("History refresh failed:", error));
    }
    return true;
  } catch (error) {
    console.warn("Could not save scan to Firestore:", error);
    if (state.user?.uid === owner.uid) toast("Проверка выполнена, но запись в историю не сохранена. Проверь Firestore Rules.", "error");
    return false;
  }
}

function formatDate(value) {
  let date = null;
  if (value?.toDate) date = value.toDate();
  else if (value instanceof Date) date = value;
  else if (typeof value === "number" || typeof value === "string") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) date = parsed;
  }
  return date && !Number.isNaN(date.getTime())
    ? date.toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" })
    : "Только что";
}
function renderHistory() {
  const total = state.history.length;
  const ip = state.history.filter((x) => x.kind === "ip").length;
  const domains = state.history.filter((x) => x.kind === "domain").length;
  const other = total - ip - domains;
  $("#historyTotal").textContent = total;
  $("#historyIp").textContent = ip;
  $("#historyDomains").textContent = domains;
  $("#historyOther").textContent = other;
  const host = $("#historyList");
  const filter = (state.historyFilter || "").trim().toLocaleLowerCase("ru-RU");
  const items = filter ? state.history.filter((item) => [item.kind, item.target, item.summary].some((value) => String(value || "").toLocaleLowerCase("ru-RU").includes(filter))) : state.history;
  if (!items.length) {
    host.innerHTML = total
      ? '<div class="empty-state"><span class="empty-icon"><svg><use href="#i-search"/></svg></span><b>Совпадений нет</b><p>Измени поисковый запрос и попробуй ещё раз.</p></div>'
      : '<div class="empty-state"><span class="empty-icon"><svg><use href="#i-clock"/></svg></span><b>История пуста</b><p>После первого исследования появится запись.</p></div>';
    return;
  }
  host.innerHTML = items.map((item) => `<div class="history-row"><span class="history-type ${escapeHtml(item.kind)}">${escapeHtml((item.kind || "tool").toUpperCase())}</span><div class="history-copy"><b>${escapeHtml(item.target || "Исследование")}</b><small>${escapeHtml(item.summary || "Завершено")}</small></div><span class="history-status">${escapeHtml(formatDate(item.createdAt))}</span></div>`).join("");
}
function renderOverview() {
  $("#statScans").textContent = state.history.length;
  $("#statDomains").textContent = state.domains.length;
  const since = Date.now() - 7 * 24 * 60 * 60 * 1000;
  $("#statRecent").textContent = state.history.filter((item) => {
    const raw = item.createdAt?.toDate ? item.createdAt.toDate() : item.createdAt;
    const date = raw instanceof Date ? raw.getTime() : new Date(raw || 0).getTime();
    return Number.isFinite(date) && date >= since;
  }).length;
  $("#statTasks").innerHTML = `${state.completedTasks.length}<span class="stat-total">/ 6</span>`;
  $("#taskProgress").style.width = `${state.completedTasks.length / 6 * 100}%`;
  $("#todayLabel").textContent = new Date().toLocaleDateString("ru-RU", { day: "numeric", month: "long", year: "numeric" });
  const recent = state.history.slice(0, 4);
  $("#overviewActivity").innerHTML = recent.length ? recent.map((item) => `<div class="activity-row"><span class="activity-dot"></span><div><b>${escapeHtml(item.target || item.kind || "Исследование")}</b><small>${escapeHtml(item.summary || "Выполнено")} · ${escapeHtml(formatDate(item.createdAt))}</small></div></div>`).join("") : '<div class="empty-state compact"><span class="empty-icon"><svg><use href="#i-clock"/></svg></span><b>Пока нет исследований</b><p>Запусти первую проверку — события появятся здесь.</p></div>';
}
function renderChecklist() {
  $$("#recommendChecklist input[data-task]").forEach((input) => { input.checked = state.completedTasks.includes(input.dataset.task); });
  const count = state.completedTasks.length;
  const percent = Math.round(count / TASKS.length * 100);
  $("#recommendCount").textContent = `${count} из ${TASKS.length}`;
  $("#recommendPercent").textContent = `${percent}%`;
  $("#recommendCircle").style.setProperty("--progress", percent);
}
async function updateTask(id, checked) {
  const owner = state.user;
  if (!TASKS.includes(id) || !owner) return;
  const previous = [...state.completedTasks];
  const next = new Set(previous);
  checked ? next.add(id) : next.delete(id);
  state.completedTasks = [...next];
  renderChecklist(); renderOverview();
  try {
    await updateDoc(doc(db, "users", owner.uid), { completedTasks: state.completedTasks, updatedAt: serverTimestamp() });
  } catch (error) {
    if (state.user?.uid !== owner.uid) return;
    state.completedTasks = previous;
    renderChecklist(); renderOverview();
    toast(`Не удалось сохранить чек-лист: ${error.message}`, "error");
  }
}
function renderEverything() { renderProfile(); renderOverview(); renderHistory(); renderDomains(); renderChecklist(); }

// Shared HTTP helper with a timeout and clear user-facing errors.
async function fetchJson(url, options = {}, timeoutMs = 14000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Источник не ответил вовремя.");
    if (error instanceof TypeError) throw new Error("Источник недоступен из браузера (сеть или CORS). Открой ссылку источника напрямую.");
    throw error;
  } finally { clearTimeout(timer); }
}
function setResults(id, html) { const el = $(id); el.innerHTML = html; el.hidden = false; }
function kv(label, value) { return `<div class="result-kv"><span>${escapeHtml(label)}</span><b>${escapeHtml(value ?? "—")}</b></div>`; }
function resultBlock(title, body, tone = "") { return `<div class="result-section ${tone}"><div class="result-section-title">${escapeHtml(title)}</div>${body}</div>`; }
function resultLinks(items) { return `<div class="result-links">${items.map(([label, url]) => `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)} ↗</a>`).join("")}</div>`; }
function showError(id, message, externalUrl = "") {
  setResults(id, `<div class="result-alert"><b>Источник не вернул данные</b><p>${escapeHtml(message)}</p>${externalUrl ? resultLinks([["Открыть источник", externalUrl]]) : ""}</div>`);
}
function isValidIPv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function isValidIPv6(value) {
  if (!value.includes(":")) return false;
  try { const url = new URL(`http://[${value}]/`); return url.hostname.length > 2; } catch { return false; }
}
function isPrivateIp(ip) {
  if (isValidIPv4(ip)) {
    const p = ip.split(".").map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || (p[0] === 192 && p[1] === 0) || p[0] >= 224;
  }
  const s = ip.toLowerCase();
  return s === "::1" || s === "::" || s.startsWith("fc") || s.startsWith("fd")
    || /^fe[89ab]/.test(s) || s.startsWith("ff") || s.startsWith("2001:db8:")
    || s.startsWith("2001:10:") || s.startsWith("2001:2:");
}
function ipv4Ptr(ip) { return ip.split(".").reverse().join(".") + ".in-addr.arpa"; }
function ipv6Ptr(ip) {
  try {
    const hex = ipv6ToBigInt(ip).toString(16).padStart(32, "0");
    return `${hex.split("").reverse().join(".")}.ip6.arpa`;
  } catch { return ""; }
}
async function lookupIp(ip, myIp = false) {
  const normalized = ip.trim();
  if (!myIp && !isValidIPv4(normalized) && !isValidIPv6(normalized)) throw new Error("Введи корректный IPv4 или IPv6 адрес.");
  const isLocal = !myIp && isPrivateIp(normalized);
  if (isLocal) {
    setResults("#ipResults", `${resultBlock("Локальный / специальный IP", `${kv("IP", normalized)}${kv("Тип", "Частный или зарезервированный диапазон")}${kv("Внешняя геолокация", "Не выполнялась")}${kv("Публичные сервисы", "Не запрашивались")}`, "positive")}<p class="result-footnote">Частные адреса RFC1918 и локальные диапазоны не маршрутизируются как публичные адреса. Для них IPinfo/RDAP/Shodan не дадут обычный публичный профиль.</p>`);
    await saveScan("ip", "IP Intelligence", "Распознан локальный или специальный IP-диапазон");
    return;
  }
  const safe = myIp ? "me" : normalized;
  const ipUrl = `${IPINFO_BASE}/${encodeURIComponent(safe)}`;
  const tasks = [];
  tasks.push(fetchJson(ipUrl, { headers: { Authorization: `Bearer ${IPINFO_TOKEN}` } }).then((data) => ({ source: "IPinfo", data })));
  if (!isLocal && !myIp) {
    tasks.push(fetchJson(`https://internetdb.shodan.io/${encodeURIComponent(normalized)}`).then((data) => ({ source: "InternetDB", data })));
    tasks.push(fetchJson(`https://rdap.org/ip/${encodeURIComponent(normalized)}`).then((data) => ({ source: "RDAP", data })));
    const ptrName = isValidIPv4(normalized) ? ipv4Ptr(normalized) : ipv6Ptr(normalized);
    if (ptrName) tasks.push(fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(ptrName)}&type=PTR`).then((data) => ({ source: "PTR", data })));
  }
  const settled = await Promise.allSettled(tasks);
  const results = {};
  settled.forEach((item) => { if (item.status === "fulfilled") results[item.value.source] = item.value.data; else console.warn("IP source failed:", item.reason); });
  const info = results.IPinfo;
  if (!info) throw new Error(`IPinfo Lite не ответил. Проверь токен или доступность сервиса. ${settled[0]?.reason?.message || ""}`);
  // For "My IP", discover the public IP first, then request passive enrichment sources.
  if (myIp && info.ip && (isValidIPv4(info.ip) || isValidIPv6(info.ip)) && !isPrivateIp(info.ip)) {
    const extra = await Promise.allSettled([
      fetchJson(`https://internetdb.shodan.io/${encodeURIComponent(info.ip)}`).then((data) => ({ source: "InternetDB", data })),
      fetchJson(`https://rdap.org/ip/${encodeURIComponent(info.ip)}`).then((data) => ({ source: "RDAP", data })),
      ...(isValidIPv4(info.ip) || isValidIPv6(info.ip) ? [fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(isValidIPv4(info.ip) ? ipv4Ptr(info.ip) : ipv6Ptr(info.ip))}&type=PTR`).then((data) => ({ source: "PTR", data }))] : [])
    ]);
    extra.forEach((item) => { if (item.status === "fulfilled") results[item.value.source] = item.value.data; else console.warn("Self-IP enrichment failed:", item.reason); });
  }
  const internet = results.InternetDB;
  const targetIp = info.ip || normalized;
  const ptr = results.PTR?.Answer?.map((x) => x.data).join(", ") || "Не найден";
  const rdap = results.RDAP;
  const recordCount = (internet?.ports || []).length;
  const body = [
    resultBlock("IPinfo Lite · страна и ASN", [
      kv("IP", info.ip || normalized), kv("ASN", info.asn), kv("Провайдер / организация", info.as_name),
      kv("Домен ASN", info.as_domain), kv("Страна", `${info.country || "—"} (${info.country_code || "—"})`),
      kv("Континент", `${info.continent || "—"} (${info.continent_code || "—"})`),
      kv("Обратный DNS (PTR)", ptr)
    ].join(""), "positive"),
    internet ? resultBlock("Shodan InternetDB · ранее замеченные сервисы", [
      kv("Порты", (internet.ports || []).join(", ") || "Не указаны"),
      kv("Хостнеймы", (internet.hostnames || []).join(", ") || "Не указаны"),
      kv("Теги", (internet.tags || []).join(", ") || "Нет"),
      kv("CPE", (internet.cpes || []).slice(0, 6).join(" · ") || "Нет")
    ].join("") + ((internet.vulns || []).length ? `<div class="vuln-list">${internet.vulns.map((cve) => `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank" rel="noopener">${escapeHtml(cve)}</a>`).join("")}</div>` : "")) : resultBlock("Shodan InternetDB", "<p>Данные не получены: запись отсутствует или браузер заблокировал запрос. Можно открыть источник напрямую.</p>"),
    rdap ? resultBlock("RDAP · регистрационные данные IP-блока", [
      kv("Сеть", rdap.name || rdap.handle || "—"), kv("Тип", rdap.type || "—"),
      kv("Начало диапазона", rdap.startAddress || "—"), kv("Конец диапазона", rdap.endAddress || "—"),
      kv("Страна", rdap.country || "—"), kv("Портал", (rdap.links || []).find((x) => x.rel === "self")?.href || "—")
    ].join("")) : ""
  ].filter(Boolean).join("");
  const links = [
    ["IPinfo", `https://ipinfo.io/${encodeURIComponent(targetIp)}`],
    ["Shodan", `https://www.shodan.io/host/${encodeURIComponent(targetIp)}`],
    ["AbuseIPDB", `https://www.abuseipdb.com/check/${encodeURIComponent(targetIp)}`],
    ["RIPEstat", `https://stat.ripe.net/${encodeURIComponent(targetIp)}`],
    ["RDAP", `https://rdap.org/ip/${encodeURIComponent(targetIp)}`]
  ];
  setResults("#ipResults", `<div class="result-header"><div><span class="eyebrow">IP LOOKUP REPORT</span><h3>${escapeHtml(info.ip || normalized)}</h3><p>${isLocal ? "Локальный / специальный диапазон" : "Публичная адресация"}</p></div><button type="button" class="btn btn-ghost btn-small" id="copyIpReport">Копировать отчёт</button></div>${body}${resultLinks(links)}<p class="result-footnote">Lite показывает страну и ASN, а не точный адрес или личность пользователя. InternetDB — пассивная историческая выборка; CVE-метки требуют ручной проверки.</p>`);
  $("#copyIpReport")?.addEventListener("click", () => copyText(`IP: ${info.ip || normalized}\nASN: ${info.asn || "—"}\nAS name: ${info.as_name || "—"}\nCountry: ${info.country || "—"}\nPorts: ${(internet?.ports || []).join(", ")}\nPTR: ${ptr}`));
  await saveScan("ip", "IP Intelligence", `IPinfo: ${info.country || "страна не определена"}, ${info.asn || "ASN неизвестен"}; портов в InternetDB: ${recordCount}`);
}
async function ipSubmit(event, myIp = false) {
  event?.preventDefault();
  const ip = myIp ? "" : $("#ipInput").value.trim();
  const button = myIp ? $("#myIpButton") : $("#ipSubmit");
  setBusy(button, true, "Собираем публичные данные…");
  $("#ipResults").hidden = false; $("#ipResults").innerHTML = '<div class="loading-state">Запрашиваем источники…</div>';
  try { await lookupIp(ip, myIp); }
  catch (error) { showError("#ipResults", error.message, ip ? `https://ipwho.is/${encodeURIComponent(ip)}` : "https://ipwho.is/"); toast(error.message, "error"); }
  finally { setBusy(button, false); }
}

function normalizeDomain(input) {
  let value = input.trim().replace(/^https?:\/\//i, "").split(/[/?#]/)[0].toLowerCase().replace(/\.$/, "");
  if (!value || value.length > 253 || value.includes("@")) throw new Error("Введи домен, например example.com.");
  try { value = new URL(`https://${value}`).hostname; } catch { throw new Error("Некорректное доменное имя."); }
  if (!value.includes(".") || value.split(".").some((p) => !p || p.length > 63)) throw new Error("Проверь формат домена.");
  return value;
}
async function dnsQuery(name, type) {
  const data = await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&do=true`);
  return { status: data.Status, ad: data.AD === true, answers: data.Answer || [], authority: data.Authority || [] };
}
function recordValues(entry) { return (entry?.answers || []).map((row) => row.data); }
async function auditDomain(domain) {
  const types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA", "SOA", "DS", "DNSKEY", "SRV", "TLSA", "HTTPS"];
  const queries = await Promise.allSettled(types.map((type) => dnsQuery(domain, type)));
  const dns = {};
  types.forEach((type, index) => { dns[type] = queries[index].status === "fulfilled" ? queries[index].value : null; });
  const dmarc = await dnsQuery(`_dmarc.${domain}`, "TXT").catch(() => null);
  let rdap = null, certs = null;
  try { rdap = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`); } catch (error) { console.warn("RDAP domain:", error); }
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const raw = await fetchJson(url, {}, 18000);
    certs = Array.isArray(raw) ? raw.slice(0, 250) : [];
  } catch (error) { console.warn("crt.sh:", error); }
  const txt = recordValues(dns.TXT);
  const dmarcTxt = recordValues(dmarc);
  const spf = txt.find((v) => /^"?v=spf1\b/i.test(v)) || "Не найден";
  const dmarcRec = dmarcTxt.find((v) => /^"?v=DMARC1\b/i.test(v)) || "Не найден";
  const summary = {
    a: recordValues(dns.A), aaaa: recordValues(dns.AAAA), cname: recordValues(dns.CNAME), mx: recordValues(dns.MX),
    txt, ns: recordValues(dns.NS), caa: recordValues(dns.CAA), soa: recordValues(dns.SOA), ds: recordValues(dns.DS),
    dnskey: recordValues(dns.DNSKEY), srv: recordValues(dns.SRV), tlsa: recordValues(dns.TLSA), https: recordValues(dns.HTTPS),
    dmarc: dmarcTxt, spf, dmarcRecord: dmarcRec,
    dnssec: Object.values(dns).some((r) => r?.ad),
    rdap: rdap ? {
      ldhName: rdap.ldhName || domain,
      handle: rdap.handle || "",
      status: rdap.status || [],
      events: (rdap.events || []).map((e) => ({ action: e.eventAction, date: e.eventDate })),
      nameservers: (rdap.nameservers || []).map((n) => n.ldhName),
      entities: (rdap.entities || []).map((e) => ({ roles: e.roles || [], handle: e.handle || "" }))
    } : null,
    certificates: certs ? [...new Map(certs.map((c) => [c.common_name || c.name_value, c])).values()].slice(0, 12).map((c) => ({ name: c.common_name || c.name_value || "—", issuer: c.issuer_name || "—", notBefore: c.not_before || "", notAfter: c.not_after || "" })) : null
  };
  const fingerprint = await sha256Hex(JSON.stringify({ dns: summary, certNames: (summary.certificates || []).map((c) => [c.name, c.notAfter]) }));
  return { ...summary, fingerprint, sources: { rdap: Boolean(rdap), crt: Array.isArray(certs) } };
}
async function domainSubmit(event) {
  event.preventDefault();
  const owner = state.user;
  if (!owner) return toast("Сначала войди в аккаунт.", "error");
  let domain;
  try { domain = normalizeDomain($("#domainInput").value); }
  catch (error) { return toast(error.message, "error"); }
  const btn = $("#domainSubmit"); setBusy(btn, true, "Проверяем DNS / RDAP / CT…");
  $("#domainResults").hidden = false; $("#domainResults").innerHTML = '<div class="loading-state">Собираем публичные данные домена…</div>';
  try {
    const data = await auditDomain(domain);
    if (state.user?.uid !== owner.uid) return;
    const previous = state.domains.find((d) => d.domain === domain);
    const changed = Boolean(previous?.fingerprint && previous.fingerprint !== data.fingerprint);
    renderDomainReport(domain, data, changed);
    $("#domainInput").value = "";
    try {
      await setDoc(doc(db, "users", owner.uid, "domains", domain), {
        domain, monitoring: true, lastAudit: data, fingerprint: data.fingerprint,
        monitorStatus: changed ? "changed" : "stable", lastChecked: serverTimestamp(), updatedAt: serverTimestamp()
      }, { merge: true });
      if (state.user?.uid === owner.uid) { await loadDomains(owner); renderDomains(); renderOverview(); }
    } catch (storageError) {
      console.warn("Domain audit could not be saved:", storageError);
      toast("Аудит завершён, но сохранить домен в Firestore не удалось. Проверь Rules.", "error");
    }
    if (state.user?.uid === owner.uid) await saveScan("domain", "Domain audit", `${domain}: ${data.a.length} A, ${data.aaaa.length} AAAA, ${data.mx.length} MX; SPF ${data.spf === "Не найден" ? "не найден" : "найден"}`);
    toast(changed ? "Найдены изменения относительно предыдущего аудита." : "Аудит домена завершён.");
  } catch (error) {
    console.error(error);
    showError("#domainResults", error.message, `https://crt.sh/?q=%25.${encodeURIComponent(domain)}`);
    toast(error.message, "error");
  } finally { setBusy(btn, false); }
}
function renderDomainReport(domain, data, changed = false) {
  const rdapDates = data.rdap?.events?.map((e) => `${e.action || "event"}: ${e.date || "—"}`).join(" · ") || "Не получены";
  const certRows = data.certificates?.length ? data.certificates.map((c) => `<div class="mini-data-row"><b>${escapeHtml(c.name)}</b><small>${escapeHtml(c.issuer)} · до ${escapeHtml(c.notAfter || "—")}</small></div>`).join("") : "<p>Certificate Transparency не вернул данные или запрос заблокирован.</p>";
  const dnsCards = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA", "SOA", "DS", "DNSKEY", "SRV", "TLSA", "HTTPS"].map((type) => {
    const rawValues = data[type.toLowerCase()];
    const vals = Array.isArray(rawValues) ? rawValues : recordValues(rawValues);
    return resultBlock(`DNS ${type} (${vals.length})`, vals.length ? `<div class="record-list">${vals.slice(0, 10).map((x) => `<code>${escapeHtml(x)}</code>`).join("")}</div>` : "<p>Нет записей или источник не ответил.</p>");
  }).join("");
  const alerts = [
    ["SPF", data.spf], ["DMARC", data.dmarcRecord],
    ["DNSSEC AD flag", data.dnssec ? "Подтверждён DNS-ответом с AD" : "Не подтверждён этим запросом"],
    ["RDAP события", rdapDates], ["NS из RDAP", (data.rdap?.nameservers || []).join(", ") || "Не получены"]
  ].map(([k, v]) => kv(k, v)).join("");
  setResults("#domainResults", `<div class="result-header"><div><span class="eyebrow">DOMAIN AUDIT REPORT</span><h3>${escapeHtml(domain)}</h3><p>${changed ? "Обнаружены изменения с прошлого аудита" : "Публичный DNS и регистрационный аудит"}</p></div><span class="status-badge ${changed ? "warning" : "positive"}">${changed ? "CHANGED" : "CHECKED"}</span></div>${resultBlock("Почтовая защита и регистрация", alerts)}<div class="result-two-col">${dnsCards}</div>${resultBlock("Certificate Transparency · crt.sh", certRows)}${resultLinks([["Открыть домен", `https://${domain}`], ["RDAP", `https://rdap.org/domain/${domain}`], ["crt.sh", `https://crt.sh/?q=%25.${domain}`], ["DNSViz", `https://dnsviz.net/d/${domain}/dnssec/`]])}<p class="result-footnote">Отсутствие записи в ответе не всегда означает ошибку конфигурации. DNS-кэш, делегация, DNSSEC и ограничения публичного резолвера могут влиять на результат.</p>`);
}
function renderDomains() {
  const host = $("#domainList"); $("#domainCount").textContent = state.domains.length;
  if (!state.domains.length) {
    host.innerHTML = '<div class="empty-state"><span class="empty-icon"><svg><use href="#i-globe"/></svg></span><b>Список пуст</b><p>Проведи аудит домена — он появится здесь.</p></div>'; return;
  }
  host.innerHTML = state.domains.map((d) => `<div class="domain-row"><span class="domain-row-icon"><svg><use href="#i-globe"/></svg></span><div class="domain-row-copy"><b>${escapeHtml(d.domain)}</b><small>Последняя проверка: ${escapeHtml(formatDate(d.lastChecked))}</small></div><span class="status-badge ${d.monitorStatus === "changed" ? "warning" : "positive"}">${d.monitorStatus === "changed" ? "CHANGED" : "MONITORED"}</span><div class="domain-row-actions"><button class="btn btn-ghost btn-small" data-domain-action="audit" data-domain="${escapeHtml(d.domain)}">Проверить</button><button class="btn btn-ghost btn-small" data-domain-action="view" data-domain="${escapeHtml(d.domain)}">Отчёт</button><button class="btn btn-ghost btn-small danger-button" data-domain-action="delete" data-domain="${escapeHtml(d.domain)}" aria-label="Удалить">×</button></div></div>`).join("");
}
async function handleDomainAction(event) {
  const btn = event.target.closest("[data-domain-action]"); if (!btn) return;
  const domain = btn.dataset.domain, action = btn.dataset.domainAction;
  if (!domain || !state.user) return;
  if (action === "view") {
    const saved = state.domains.find((d) => d.domain === domain);
    if (saved?.lastAudit) renderDomainReport(domain, saved.lastAudit, saved.monitorStatus === "changed");
    else toast("Сохранённый отчёт не найден.", "error");
  } else if (action === "delete") {
    if (!confirm(`Удалить ${domain} из мониторинга?`)) return;
    try { await deleteDoc(doc(db, "users", state.user.uid, "domains", domain)); await loadDomains(); renderDomains(); renderOverview(); toast("Домен удалён."); }
    catch (error) { toast(`Не удалось удалить домен: ${error.message}`, "error"); }
  } else if (action === "audit") {
    $("#domainInput").value = domain;
    await domainSubmit(new Event("submit", { cancelable: true }));
  }
}

async function binSubmit(event) {
  event.preventDefault();
  const bin = $("#binInput").value.trim();
  if (!/^\d{6,8}$/.test(bin)) return toast("Укажи только BIN из 6–8 цифр. Полный номер карты вводить нельзя.", "error");
  const link = `https://lookup.binlist.net/${bin}`;
  const btn = event.submitter || $("#binForm button[type=submit]"); setBusy(btn, true, "Ищем BIN…");
  try {
    const data = await fetchJson(link, { headers: { "Accept-Version": "3", Accept: "application/json" } });
    const parts = [kv("Платёжная система", data.scheme), kv("Бренд", data.brand), kv("Тип", data.type), kv("Предоплаченная", data.prepaid == null ? "—" : data.prepaid ? "Да" : "Нет"), kv("Страна", `${data.country?.emoji || ""} ${data.country?.name || "—"}`), kv("Банк", data.bank?.name), kv("Сайт банка", data.bank?.url), kv("Телефон банка", data.bank?.phone) ].join("");
    setResults("#binResults", `${resultBlock(`BIN ${bin}`, parts, "positive")}${resultLinks([["Открыть ответ Binlist", link], ["Binlist", "https://binlist.net/"]])}<p class="result-footnote">BIN идентифицирует диапазон эмитента, а не владельца карты. Значения могут быть неполными или устаревшими.</p>`);
    await saveScan("bin", "BIN lookup", `${data.scheme || "Схема не определена"} · ${data.country?.name || "страна не определена"}`);
  } catch (error) {
    showError("#binResults", `${error.message} У Binlist строгий публичный лимит запросов и возможны CORS-ограничения. Открой API в новой вкладке; он покажет JSON-ответ.`, link);
    toast("Не удалось встроить ответ Binlist в браузер. Есть прямая ссылка на источник.", "error");
  } finally { setBusy(btn, false); }
}
async function vinSubmit(event) {
  event.preventDefault();
  const vin = $("#vinInput").value.trim().toUpperCase();
  if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(vin)) return toast("VIN должен содержать 17 символов без I, O и Q.", "error");
  const btn = event.submitter || $("#vinForm button[type=submit]"); setBusy(btn, true, "Декодируем VIN…");
  try {
    const data = await fetchJson(`https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValuesExtended/${encodeURIComponent(vin)}?format=json`);
    const row = data.Results?.[0]; if (!row) throw new Error("NHTSA не вернул результат для этого VIN.");
    const mapping = [
      ["Производитель", "Manufacturer"], ["Марка", "Make"], ["Модель", "Model"], ["Год модели", "ModelYear"],
      ["Тип ТС", "VehicleType"], ["Кузов", "BodyClass"], ["Двигатель", "EngineModel"], ["Цилиндры", "EngineCylinders"],
      ["Объём двигателя", "DisplacementL"], ["Топливо", "FuelTypePrimary"], ["Привод", "DriveType"],
      ["Страна сборки", "PlantCountry"], ["Завод", "PlantCompanyName"], ["WMI", "SuggestedVIN"]
    ];
    const html = mapping.map(([label, key]) => row[key] && row[key] !== "Not Applicable" ? kv(label, row[key]) : "").join("");
    const errors = row.ErrorText && row.ErrorText !== "0 - VIN decoded cleanly." ? `<p class="result-warning">${escapeHtml(row.ErrorText)}</p>` : "";
    setResults("#vinResults", `${resultBlock(`VIN ${vin}`, html || "<p>Данные для VIN не найдены.</p>", "positive")}${errors}${resultLinks([["Официальная база NHTSA", `https://vpic.nhtsa.dot.gov/`]])}<p class="result-footnote">Результат получен из базы производителей NHTSA vPIC; наличие отдельных характеристик зависит от марки и года выпуска.</p>`);
    await saveScan("vin", "VIN decoder", `${row.Make || "Марка неизвестна"} ${row.Model || ""} ${row.ModelYear || ""}`.trim());
  } catch (error) { showError("#vinResults", error.message, `https://vpic.nhtsa.dot.gov/decoder/`); toast(error.message, "error"); }
  finally { setBusy(btn, false); }
}
function ibanValidate(value) {
  const iban = value.replace(/[\s-]/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return { iban, valid: false, reason: "Формат не похож на IBAN." };
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const digits = char >= "A" && char <= "Z" ? String(char.charCodeAt(0) - 55) : char;
    for (const digit of digits) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return { iban, valid: remainder === 1, country: iban.slice(0, 2), check: iban.slice(2, 4), remainder };
}
async function ibanSubmit(event) {
  event.preventDefault();
  const result = ibanValidate($("#ibanInput").value);
  const output = result.valid
    ? resultBlock("IBAN: контрольная сумма корректна", `${kv("Страна", result.country)}${kv("Контрольные цифры", result.check)}${kv("Длина", `${result.iban.length} символов`)}`, "positive")
    : resultBlock("IBAN не прошёл локальную проверку", `${kv("Причина", result.reason || "Контрольная сумма не совпала.")}${kv("Остаток MOD 97", result.remainder ?? "—")}`, "negative");
  setResults("#ibanResults", `${output}<p class="result-footnote">Проверяется только формат/контрольная сумма. Банковский счёт, его существование, баланс и владелец не проверяются. Значение не отправлялось и не сохранялось.</p>`);
  await saveScan("iban", "IBAN checksum", result.valid ? "Контрольная сумма прошла" : "Формат или контрольная сумма не прошли");
}

function usernameSubmit(event) {
  event.preventDefault();
  const username = $("#usernameInput").value.trim().replace(/^@/, "");
  if (!/^[a-zA-Z0-9._-]{2,64}$/.test(username)) return toast("Никнейм: 2–64 символа, латиница, цифры, точка, дефис или _.", "error");
  const q = encodeURIComponent(`"${username}"`);
  const platforms = [
    ["GitHub", `https://github.com/${encodeURIComponent(username)}`],
    ["Reddit", `https://www.reddit.com/user/${encodeURIComponent(username)}/`],
    ["Telegram", `https://t.me/${encodeURIComponent(username)}`],
    ["X / Twitter", `https://x.com/${encodeURIComponent(username)}`],
    ["Instagram", `https://www.instagram.com/${encodeURIComponent(username)}/`],
    ["TikTok", `https://www.tiktok.com/@${encodeURIComponent(username)}`],
    ["YouTube", `https://www.youtube.com/@${encodeURIComponent(username)}`],
    ["Twitch", `https://www.twitch.tv/${encodeURIComponent(username)}`],
    ["Pinterest", `https://www.pinterest.com/${encodeURIComponent(username)}/`]
  ];
  const search = [
    ["Google exact phrase", `https://www.google.com/search?q=${q}`],
    ["Bing exact phrase", `https://www.bing.com/search?q=${q}`],
    ["DuckDuckGo exact phrase", `https://duckduckgo.com/?q=${q}`]
  ];
  setResults("#usernameResults", `${resultBlock(`Публичные профили · ${username}`, `<div class="profile-link-grid">${platforms.map(([label, url]) => `<a class="profile-link" href="${escapeHtml(url)}" target="_blank" rel="noopener">${escapeHtml(label)} <span>↗</span></a>`).join("")}</div>`)}${resultBlock("Поиск по публичному индексу", resultLinks(search))}<p class="result-footnote">Переходы открывают сайты-источники. PrivacyGuard не проверяет автоматически наличие аккаунта и не обходит настройки приватности.</p>`);
  saveScan("username", "Username search", "Сформированы ссылки на публичные поисковые страницы").catch((e) => console.warn(e));
}
function dorkSubmit(event) {
  event.preventDefault();
  const domainRaw = $("#dorkDomain").value.trim();
  const term = $("#dorkTerm").value.trim();
  if (!domainRaw && !term) return toast("Укажи домен или ключевые слова.", "error");
  let queryText = "";
  if (domainRaw) { try { queryText += `site:${normalizeDomain(domainRaw)} `; } catch (e) { return toast(e.message, "error"); } }
  if (term) queryText += term;
  const url = `https://www.google.com/search?q=${encodeURIComponent(queryText.trim())}`;
  setResults("#dorkResults", `${resultBlock("Поисковый оператор", `<code class="query-code">${escapeHtml(queryText.trim())}</code>${resultLinks([["Открыть запрос в Google", url], ["Открыть в Bing", `https://www.bing.com/search?q=${encodeURIComponent(queryText.trim())}`]])}`)}<p class="result-footnote">Используй запросы для собственных сайтов и публичной информации. Не пытайся получать закрытые данные.</p>`);
  saveScan("username", "Search operator", "Создан поисковый оператор").catch((e) => console.warn(e));
}
function phoneSubmit(event) {
  event.preventDefault();
  let input = $("#phoneInput").value.trim();
  let digits = input.replace(/[^\d]/g, "");
  if (input.startsWith("00")) digits = digits.slice(2);
  const normalized = `+${digits}`;
  const valid = /^\+[1-9]\d{7,14}$/.test(normalized);
  const display = valid ? normalized : "Формат не похож на E.164";
  setResults("#phoneResults", `${resultBlock(valid ? "Формат номера" : "Проверь формат", `${kv("Нормализованный номер", display)}${kv("Длина цифр", digits.length)}${kv("Проверка", valid ? "Похож на международный формат E.164" : "Нужен код страны и 8–15 цифр")}`, valid ? "positive" : "negative")}<p class="result-footnote">Это синтаксическая проверка, не подтверждение существования/активности SIM-карты или личности владельца. Обратный поиск по частным телефонным номерам не выполняется.</p>`);
  saveScan("phone", "Phone format", valid ? "Формат E.164 похож на корректный" : "Формат номера требует проверки").catch((e) => console.warn(e));
}
async function emailSubmit(event) {
  event.preventDefault();
  const value = $("#emailInput").value.trim();
  if (!/^\S+@[^\s@]+\.[^\s@]+$/.test(value)) return toast("Проверь формат email.", "error");
  const domain = value.split("@").pop().toLowerCase();
  const [mx, txt, dmarc] = await Promise.allSettled([dnsQuery(domain, "MX"), dnsQuery(domain, "TXT"), dnsQuery(`_dmarc.${domain}`, "TXT")]);
  const mxVals = mx.status === "fulfilled" ? recordValues(mx.value) : [];
  const txtVals = txt.status === "fulfilled" ? recordValues(txt.value) : [];
  const dmarcVals = dmarc.status === "fulfilled" ? recordValues(dmarc.value) : [];
  const spf = txtVals.find((x) => /v=spf1/i.test(x)) || "Не найден";
  const dmarcRec = dmarcVals.find((x) => /v=DMARC1/i.test(x)) || "Не найден";
  setResults("#emailResults", `${resultBlock("Проверка домена email", `${kv("Домен", domain)}${kv("Синтаксис", "Похож на корректный")}${kv("MX записи", mxVals.join(" · ") || "Не найдены / запрос не прошёл")}${kv("SPF", spf)}${kv("DMARC", dmarcRec)}`)}${resultLinks([["DNS отчёт домена", `https://dns.google/query?name=${encodeURIComponent(domain)}`], ["RDAP домена", `https://rdap.org/domain/${encodeURIComponent(domain)}`]])}<p class="result-footnote">Проверяется домен почты, но не существование почтового ящика. Адрес и результат не сохраняются в историю.</p>`);
  await saveScan("email", "Email domain check", `Проверен домен ${domain}; MX: ${mxVals.length ? "найдены" : "не подтверждены"}`);
}
function urlSubmit(event) {
  event.preventDefault();
  const raw = $("#urlInput").value.trim();
  let url;
  try { url = new URL(/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(raw) ? raw : `https://${raw}`); }
  catch { return toast("Не удалось разобрать URL.", "error"); }
  if (!['http:', 'https:'].includes(url.protocol)) return toast("Поддерживаются только HTTP и HTTPS адреса.", "error");
  const ipHost = isValidIPv4(url.hostname);
  const checks = [
    ["Используется HTTPS", url.protocol === "https:", "HTTPS не означает, что сайт безопасен."],
    ["В URL есть логин/пароль", Boolean(url.username || url.password), "Наличие userinfo может быть признаком маскировки адреса."],
    ["Домен в Punycode", url.hostname.includes("xn--"), "Проверь, не имитирует ли домен другой бренд."],
    ["Хост задан IP-адресом", ipHost, "Сайт использует IP вместо доменного имени."],
    ["Нестандартный порт", Boolean(url.port && !["80", "443"].includes(url.port)), "Сервис работает на нестандартном порту."],
    ["Большое число параметров", [...url.searchParams].length > 8, "Проверь параметры на лишние токены или персональные данные."]
  ];
  const warnings = checks.filter((x) => x[1]);
  const body = [kv("Протокол", url.protocol), kv("Хост", url.hostname), kv("Punycode / IDN", url.hostname), kv("Путь", url.pathname), kv("Порт", url.port || "по умолчанию"), kv("Параметров", [...url.searchParams].length), kv("Фрагмент", url.hash || "нет")].join("");
  const checkHtml = checks.map(([label, hit, note]) => `<div class="check-row ${hit ? "warning" : "ok"}"><span>${hit ? "!" : "✓"}</span><div><b>${escapeHtml(label)}: ${hit ? "обнаружено" : "не обнаружено"}</b><small>${escapeHtml(note)}</small></div></div>`).join("");
  setResults("#urlResults", `${resultBlock("Разбор адреса", body)}${resultBlock(`Признаки для ручной проверки (${warnings.length})`, checkHtml)}${resultLinks([["VirusTotal search", `https://www.virustotal.com/gui/search/${encodeURIComponent(url.href)}`], ["urlscan.io", `https://urlscan.io/search/#${encodeURIComponent(url.hostname)}`], ["Google Safe Browsing", "https://transparencyreport.google.com/safe-browsing/search"]])}<p class="result-footnote">Это эвристический разбор строки URL, не вердикт о вредоносности. Адрес не открывается и не отправляется на сканирование автоматически.</p>`);
  saveScan("url", "URL analysis", `Разобран URL; отмечено признаков для проверки: ${warnings.length}`).catch((e) => console.warn(e));
}

async function macSubmit(event) {
  event.preventDefault();
  const mac = $("#macInput").value.trim();
  const hex = mac.replace(/[^0-9a-f]/gi, "");
  if (!/^[0-9a-f]{6}([0-9a-f]{6})?$/i.test(hex)) return toast("Введи 6 hex-символов OUI или полный 12-символьный MAC.", "error");
  const prefix = hex.slice(0, 6).toUpperCase();
  const api = `https://api.maclookup.app/v2/macs/${prefix}`;
  const btn = event.submitter || $("#macForm button[type=submit]"); setBusy(btn, true, "Ищем производителя…");
  try {
    const data = await fetchJson(api);
    const html = data.found ? `${kv("Производитель", data.company)}${kv("Страна", data.country)}${kv("Тип блока", data.blockType)}${kv("Префикс", data.macPrefix)}${kv("Диапазон", `${data.blockStart || "—"} – ${data.blockEnd || "—"}`)}${kv("Рандомизированный MAC", data.isRand ? "Возможен" : "Не отмечен")}` : "<p>Префикс не найден в публичном реестре или использован случайный локальный MAC.</p>";
    setResults("#macResults", `${resultBlock(`MAC vendor · ${prefix}`, html)}${resultLinks([["MACLookup", api], ["Официальная документация", "https://maclookup.app/api-v2/documentation"]])}<p class="result-footnote">Vendor определяется по OUI-префиксу; случайный MAC может не соответствовать производителю устройства.</p>`);
    await saveScan("mac", "MAC vendor lookup", data.company || "Префикс не найден");
  } catch (error) { showError("#macResults", error.message, api); toast(error.message, "error"); }
  finally { setBusy(btn, false); }
}
async function sha256Hex(value) {
  const buffer = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hashSubmit(event) {
  event.preventDefault();
  const input = $("#hashInput").value;
  if (!input) return toast("Введи текст для хеширования.", "error");
  const algorithm = $("#hashAlgorithm").value;
  try {
    const bytes = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest(algorithm, bytes);
    const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    setResults("#hashResults", `${resultBlock(algorithm, `<code class="hash-value">${hex}</code><button class="btn btn-ghost btn-small" type="button" id="copyHash">Копировать</button>`, "positive")}<p class="result-footnote">Хеш вычислен локально в браузере и не отправлен на сервер.</p>`);
    $("#copyHash").addEventListener("click", () => copyText(hex));
    await saveScan("hash", "Text hash", `${algorithm} вычислен локально`);
  } catch (error) { showError("#hashResults", error.message); }
}
async function fileHashSubmit(event) {
  event.preventDefault();
  const file = $("#hashFile").files[0]; if (!file) return toast("Выбери файл.", "error");
  const btn = event.submitter || $("#fileHashForm button[type=submit]"); setBusy(btn, true, "Читаем файл…");
  try {
    const hash = await sha256Hex(await file.arrayBuffer());
    setResults("#fileHashResults", `${resultBlock("SHA-256", `<code class="hash-value">${hash}</code><button class="btn btn-ghost btn-small" type="button" id="copyFileHash">Копировать</button>`, "positive")}${kv("Файл", file.name)}${kv("Размер", `${(file.size / 1024).toFixed(1)} KB`)}`);
    $("#copyFileHash").addEventListener("click", () => copyText(hash));
    await saveScan("file", "File hash", `SHA-256 файла рассчитан локально (${file.size} байт)`);
  } catch (error) { showError("#fileHashResults", error.message); }
  finally { setBusy(btn, false); }
}
function passwordStrength(password) {
  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (new Set(password).size >= Math.min(8, password.length)) score++;
  const common = ["password", "qwerty", "123456", "12345678", "admin", "letmein", "welcome"];
  const weak = common.some((x) => password.toLowerCase().includes(x));
  if (weak) score = Math.min(score, 1);
  return { score: Math.min(score, 6), weak };
}
function strengthSubmit(event) {
  event.preventDefault();
  const input = $("#strengthInput"); const password = input.value;
  if (!password) return;
  const result = passwordStrength(password);
  const labels = ["Очень слабый", "Слабый", "Ниже среднего", "Средний", "Хороший", "Сильный", "Очень сильный"];
  const label = result.weak ? "Похоже на распространённый пароль" : labels[result.score];
  const feedback = [password.length < 12 ? "Увеличь длину хотя бы до 12–16 символов." : "Длина пароля — хороший фактор.", !/[A-Z]/.test(password) || !/[a-z]/.test(password) ? "Добавь разные регистры либо используй длинную случайную фразу." : "Разный регистр присутствует.", !/\d/.test(password) ? "Добавь цифры, если это не ухудшает запоминаемость." : "Цифры присутствуют.", !/[^A-Za-z0-9]/.test(password) ? "Добавь специальный символ или используй менеджер паролей." : "Специальные символы присутствуют."];
  setResults("#strengthResults", `${resultBlock(`Оценка: ${label}`, `<div class="strength-meter">${Array.from({ length: 6 }, (_, i) => `<i class="${i < result.score ? "filled" : ""}"></i>`).join("")}</div><ul class="feedback-list">${feedback.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>`)}<p class="result-footnote">Оценка эвристическая и выполняется только локально. Она не проверяет базы утечек. Сам пароль и результат не сохраняются.</p>`);
  input.value = "";
}
async function fileInfoSubmit(event) {
  event.preventDefault();
  const file = $("#infoFile").files[0]; if (!file) return toast("Выбери файл.", "error");
  try {
    const hash = await sha256Hex(await file.arrayBuffer());
    setResults("#fileInfoResults", resultBlock("Базовые метаданные файла", `${kv("Имя", file.name)}${kv("Тип MIME", file.type || "Не определён")}${kv("Размер", `${file.size.toLocaleString("ru-RU")} байт`)}${kv("Изменён", file.lastModified ? new Date(file.lastModified).toLocaleString("ru-RU") : "—")}${kv("SHA-256", hash)}`));
    await saveScan("file", "File metadata", "Локально прочитаны базовые свойства файла");
  } catch (error) { showError("#fileInfoResults", error.message); }
}
function cveSubmit(event) {
  event.preventDefault();
  const term = $("#cveInput").value.trim(); if (!term) return;
  const nvd = `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(term)}&form_type=Basic&results_type=overview`;
  const cisa = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(term)}`;
  setResults("#cveResults", `${resultBlock("Поиск уязвимостей", `<p>Открой результаты в актуальных каталогах и проверь CVE, затронутые версии и статус исправления.</p>${resultLinks([["NVD", nvd], ["CISA KEV Catalog", cisa], ["MITRE CVE", `https://www.cve.org/CVERecord?id=${encodeURIComponent(term)}`]])}`)}<p class="result-footnote">PrivacyGuard не запускает exploit и не проверяет уязвимость удалённого хоста.</p>`);
  saveScan("cve", "CVE search", "Созданы ссылки на публичные каталоги уязвимостей").catch((e) => console.warn(e));
}
function hashIdentifySubmit(event) {
  event.preventDefault();
  const value = $("#hashIdentifyInput").value.trim();
  if (!value) return toast("Введи строку или хеш для анализа.", "error");
  const candidates = [];
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(value)) candidates.push("bcrypt");
  if (/^\$argon2(id|i|d)\$/.test(value)) candidates.push("Argon2");
  if (/^\$6\$/.test(value)) candidates.push("sha512crypt");
  if (/^\$5\$/.test(value)) candidates.push("sha256crypt");
  if (/^\$1\$/.test(value)) candidates.push("md5crypt");
  if (/^[0-9a-f]+$/i.test(value)) {
    const length = value.length;
    const guesses = ({ 32: ["MD5", "NTLM"], 40: ["SHA-1", "RIPEMD-160"], 56: ["SHA-224"], 64: ["SHA-256", "SHA3-256", "BLAKE2s-256"], 96: ["SHA-384"], 128: ["SHA-512", "SHA3-512", "BLAKE2b-512"] })[length];
    if (guesses) candidates.push(...guesses);
  }
  if (!candidates.length) candidates.push("Формат не распознан по распространённым шаблонам");
  const body = [kv("Длина", `${value.length} символов`), kv("Hex-строка", /^[0-9a-f]+$/i.test(value) ? "Да" : "Нет"), kv("Возможные форматы", candidates.join(" · "))].join("");
  setResults("#hashIdentifyResults", `${resultBlock("Предположительный формат", body, "positive")}<p class="result-footnote">Это только эвристика по длине и префиксу. Несколько алгоритмов дают одинаковую длину; точный алгоритм нельзя надёжно определить только по строке. Подбор или расшифровка пароля не выполняются.</p>`);
  saveScan("hashid", "Hash identifier", `Кандидаты: ${candidates.join(", ")}`).catch((error) => console.warn(error));
}
function uuidSubmit(event) {
  event.preventDefault();
  const count = Number($("#uuidCount").value);
  if (!Number.isInteger(count) || count < 1 || count > 25) return toast("Можно создать от 1 до 25 UUID за раз.", "error");
  if (!crypto.randomUUID) return toast("Этот браузер не поддерживает crypto.randomUUID. Открой сайт по HTTPS или на localhost.", "error");
  const values = Array.from({ length: count }, () => crypto.randomUUID());
  const output = values.join("\n");
  setResults("#uuidResults", `${resultBlock(`UUID v4 · ${count}`, `<pre class="query-code">${escapeHtml(output)}</pre>`)}<button type="button" class="btn btn-ghost btn-small" id="copyUuids">Копировать UUID</button><p class="result-footnote">UUID сгенерированы с использованием криптографического генератора браузера.</p>`);
  $("#copyUuids").addEventListener("click", () => copyText(output));
  saveScan("uuid", "UUID generator", `Сгенерировано UUID: ${count}`).catch((error) => console.warn(error));
}

function mailHeaderSubmit(event) {
  event.preventDefault();
  const raw = $("#mailHeaderInput").value.trim();
  if (!raw) return toast("Вставь заголовки письма.", "error");
  const headerOnly = raw.split(/\r?\n\r?\n/, 1)[0];
  const unfolded = headerOnly.replace(/\r?\n[ \t]+/g, " ");
  const headers = new Map();
  for (const line of unfolded.split(/\r?\n/)) {
    const splitAt = line.indexOf(":");
    if (splitAt <= 0) continue;
    const name = line.slice(0, splitAt).trim().toLowerCase();
    const value = line.slice(splitAt + 1).trim();
    if (!headers.has(name)) headers.set(name, []);
    headers.get(name).push(value);
  }
  const first = (name) => headers.get(name)?.[0] || "Не найден";
  const all = (name) => headers.get(name) || [];
  const extractEmail = (value) => (value.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i) || [""])[0].toLowerCase();
  const from = extractEmail(first("from"));
  const replyTo = extractEmail(first("reply-to"));
  const returnPath = extractEmail(first("return-path"));
  const fromDomain = from.split("@")[1] || "";
  const replyDomain = replyTo.split("@")[1] || "";
  const authResults = [...all("authentication-results"), ...all("received-spf")].join(" | ");
  const findAuth = (name) => {
    const match = authResults.match(new RegExp(`\\b${name}\\s*=\\s*([a-z0-9_-]+)`, "i"));
    if (match?.[1]) return match[1].toLowerCase();
    if (name === "spf") {
      const receivedSpf = first("received-spf").match(/^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b/i);
      if (receivedSpf?.[1]) return receivedSpf[1].toLowerCase();
    }
    return "Не указан в заголовках";
  };
  const received = all("received");
  const dkimSignature = first("dkim-signature");
  const dkimDomain = (dkimSignature.match(/(?:^|;)\s*d=([^;\s]+)/i) || [])[1] || "Не указан";
  const dkimSelector = (dkimSignature.match(/(?:^|;)\s*s=([^;\s]+)/i) || [])[1] || "Не указан";
  const messageId = first("message-id");
  const rows = [
    kv("From", from || first("from")), kv("From domain", fromDomain || "Не определён"),
    kv("Reply-To", replyTo || first("reply-to")), kv("Reply-To domain", replyDomain || "Не определён"),
    kv("Return-Path", returnPath || first("return-path")), kv("Date", first("date")),
    kv("Message-ID", messageId), kv("Received hops", received.length),
    kv("SPF result", findAuth("spf")), kv("DKIM result", findAuth("dkim")),
    kv("DMARC result", findAuth("dmarc")), kv("DKIM signing domain", dkimDomain),
    kv("DKIM selector", dkimSelector)
  ].join("");
  const warnings = [];
  if (fromDomain && replyDomain && fromDomain !== replyDomain) warnings.push("Домен Reply-To отличается от домена From. Это может быть ожидаемо, но стоит проверить отправителя.");
  if (!all("authentication-results").length) warnings.push("Authentication-Results не найден. Нельзя определить SPF/DKIM/DMARC только по отсутствию этого заголовка.");
  if (!received.length) warnings.push("Заголовки Received не найдены: маршрут письма определить нельзя.");
  if (findAuth("spf") === "fail" || findAuth("dkim") === "fail" || findAuth("dmarc") === "fail") warnings.push("В Authentication-Results найден один или несколько результатов fail.");
  const receivedList = received.slice(0, 12).map((value, index) => `<div class="mini-data-row"><b>Hop ${index + 1}</b><small>${escapeHtml(value)}</small></div>`).join("") || "<p>Received не найден.</p>";
  const warningHtml = warnings.length ? `<ul class="feedback-list">${warnings.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : "<p>Простых несоответствий в извлечённых полях не найдено. Это не доказывает подлинность письма.</p>";
  const report = `From: ${from || first("from")}\nReply-To: ${replyTo || first("reply-to")}\nReturn-Path: ${returnPath || first("return-path")}\nReceived hops: ${received.length}\nSPF: ${findAuth("spf")}\nDKIM: ${findAuth("dkim")}\nDMARC: ${findAuth("dmarc")}\nDKIM domain: ${dkimDomain}\nDKIM selector: ${dkimSelector}`;
  setResults("#mailHeaderResults", `${resultBlock("Основные заголовки", rows)}${resultBlock("Маршрут Received", receivedList)}${resultBlock("Замечания", warningHtml)}<button type="button" class="btn btn-ghost btn-small" id="copyMailHeaderReport">Копировать краткий отчёт</button><p class="result-footnote">Заголовки могут быть подделаны до доверенной границы почтового провайдера. Для расследования сверяй результаты с исходным почтовым сервером и DKIM-подписью.</p>`);
  $("#copyMailHeaderReport").addEventListener("click", () => copyText(report));
  saveScan("mailheader", "Email header analysis", `Разобрано Received hops: ${received.length}; проверены поля SPF/DKIM/DMARC`).catch((error) => console.warn(error));
}

function generateSecurePassword(length, pools) {
  const all = pools.join("");
  if (!all || pools.length === 0) throw new Error("Выбери хотя бы один набор символов.");
  if (length < pools.length) throw new Error("Длина должна быть не меньше количества выбранных наборов.");
  const randomIndex = (max) => {
    const limit = Math.floor(256 / max) * max;
    const byte = new Uint8Array(1);
    let value;
    do { crypto.getRandomValues(byte); value = byte[0]; } while (value >= limit);
    return value % max;
  };
  const chars = pools.map((pool) => pool[randomIndex(pool.length)]);
  while (chars.length < length) chars.push(all[randomIndex(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
function passwordGeneratorSubmit(event) {
  event.preventDefault();
  const pools = [];
  if ($("#pgLower").checked) pools.push("abcdefghijkmnopqrstuvwxyz");
  if ($("#pgUpper").checked) pools.push("ABCDEFGHJKLMNPQRSTUVWXYZ");
  if ($("#pgNumbers").checked) pools.push("23456789");
  if ($("#pgSymbols").checked) pools.push("!@#$%^&*()-_=+[]{}:,.?");
  const length = Number($("#passwordLength").value);
  try {
    const password = generateSecurePassword(length, pools);
    setResults("#passwordGeneratorResults", `${resultBlock("Сгенерированный пароль", `<code class="hash-value">${escapeHtml(password)}</code>`)}<button type="button" class="btn btn-ghost btn-small" id="copyGeneratedPassword">Копировать пароль</button><p class="result-footnote">Использован криптографический генератор браузера. Сохрани пароль в менеджере паролей; PrivacyGuard не хранит его.</p>`);
    $("#copyGeneratedPassword").addEventListener("click", () => copyText(password));
    saveScan("passwordgen", "Password generator", `Локально создан пароль длиной ${length} символов; содержимое не сохранялось`).catch((error) => console.warn(error));
  } catch (error) { toast(error.message, "error"); }
}

function ipv4ToBigInt(ip) {
  return ip.split(".").reduce((value, part) => (value << 8n) + BigInt(Number(part)), 0n);
}
function bigIntToIpv4(value) {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 255n)).join(".");
}
function ipv6ToBigInt(address) {
  const value = address.toLowerCase();
  if (!/^[0-9a-f:]+$/.test(value) || (value.match(/::/g) || []).length > 1) throw new Error("Некорректный IPv6-адрес.");
  const compressed = value.includes("::");
  const [leftText, rightText = ""] = compressed ? value.split("::") : [value, ""];
  const left = leftText ? leftText.split(":") : [];
  const right = rightText ? rightText.split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((compressed && missing < 1) || (!compressed && missing !== 0)) throw new Error("IPv6 должен содержать 8 групп либо корректное сокращение ::.");
  const groups = [...left, ...Array(compressed ? missing : 0).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) throw new Error("Некорректная группа IPv6.");
  return BigInt(`0x${groups.map((group) => group.padStart(4, "0")).join("")}`);
}
function bigIntToIpv6(value) {
  const groups = Array.from({ length: 8 }, (_, index) => Number((value >> BigInt((7 - index) * 16)) & 0xffffn).toString(16));
  let bestStart = -1, bestLength = 1;
  for (let i = 0; i < 8;) {
    if (groups[i] !== "0") { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === "0") j++;
    if (j - i > bestLength) { bestStart = i; bestLength = j - i; }
    i = j;
  }
  if (bestStart < 0) return groups.join(":");
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
}
function cidrSubmit(event) {
  event.preventDefault();
  const input = $("#cidrInput").value.trim();
  const match = input.match(/^(.+?)\/(\d{1,3})$/);
  if (!match) return toast("Укажи сеть в формате 192.168.1.10/24 или 2001:db8::1/64.", "error");
  const address = match[1].trim();
  const prefix = Number(match[2]);
  let title, body, report, historySummary;
  if (isValidIPv4(address)) {
    if (prefix < 0 || prefix > 32) return toast("Для IPv4 префикс должен быть от 0 до 32.", "error");
    const ipNum = ipv4ToBigInt(address);
    const hostBits = 32n - BigInt(prefix);
    const hostMask = hostBits === 0n ? 0n : (1n << hostBits) - 1n;
    const fullMask = 0xffffffffn;
    const mask = fullMask ^ hostMask;
    const network = ipNum & mask;
    const broadcast = network | hostMask;
    const total = 1n << hostBits;
    const usable = prefix >= 31 ? total : (total > 2n ? total - 2n : 0n);
    const firstHost = prefix >= 31 ? network : network + 1n;
    const lastHost = prefix >= 31 ? broadcast : broadcast - 1n;
    const maskText = bigIntToIpv4(mask);
    const wildcardText = bigIntToIpv4(hostMask);
    title = `IPv4 subnet · /${prefix}`;
    body = [kv("Исходный IP", address), kv("Префикс", `/${prefix}`), kv("Маска", maskText), kv("Wildcard", wildcardText), kv("Адрес сети", bigIntToIpv4(network)), kv("Broadcast", bigIntToIpv4(broadcast)), kv("Первый адрес", bigIntToIpv4(firstHost)), kv("Последний адрес", bigIntToIpv4(lastHost)), kv("Всего адресов", total.toString()), kv("Доступно хостов", usable.toString())].join("");
    report = `IPv4: ${address}/${prefix}\nMask: ${maskText}\nWildcard: ${wildcardText}\nNetwork: ${bigIntToIpv4(network)}\nBroadcast: ${bigIntToIpv4(broadcast)}\nFirst host: ${bigIntToIpv4(firstHost)}\nLast host: ${bigIntToIpv4(lastHost)}\nTotal addresses: ${total}\nUsable hosts: ${usable}`;
    historySummary = `Рассчитана IPv4-сеть ${bigIntToIpv4(network)}/${prefix}`;
  } else if (address.includes(":")) {
    if (prefix < 0 || prefix > 128) return toast("Для IPv6 префикс должен быть от 0 до 128.", "error");
    try {
      const ipNum = ipv6ToBigInt(address);
      const hostBits = 128n - BigInt(prefix);
      const hostMask = hostBits === 0n ? 0n : (1n << hostBits) - 1n;
      const fullMask = (1n << 128n) - 1n;
      const network = ipNum & (fullMask ^ hostMask);
      const last = network | hostMask;
      const total = 1n << hostBits;
      const maskText = bigIntToIpv6(fullMask ^ hostMask);
      const networkText = bigIntToIpv6(network);
      const lastText = bigIntToIpv6(last);
      title = `IPv6 subnet · /${prefix}`;
      body = [kv("Исходный IPv6", address), kv("Префикс", `/${prefix}`), kv("Маска", maskText), kv("Адрес сети", networkText), kv("Последний адрес диапазона", lastText), kv("Всего адресов", total.toString()), kv("Адресное пространство", "128 бит")].join("");
      report = `IPv6: ${address}/${prefix}\nMask: ${maskText}\nNetwork: ${networkText}\nLast address: ${lastText}\nTotal addresses: ${total}`;
      historySummary = `Рассчитана IPv6-сеть ${networkText}/${prefix}`;
    } catch (error) { return toast(error.message, "error"); }
  } else return toast("Введи корректный IPv4 или IPv6 адрес.", "error");
  setResults("#cidrResults", `${resultBlock(title, body, "positive")}<button type="button" class="btn btn-ghost btn-small" id="copyCidrReport">Копировать отчёт</button><p class="result-footnote">Расчёт выполнен локально. IPv4 учитывает broadcast и диапазон хостов; IPv6 показывает весь диапазон префикса.</p>`);
  $("#copyCidrReport").addEventListener("click", () => copyText(report));
  saveScan("cidr", "IP subnet", historySummary).catch((error) => console.warn(error));
}
function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
function jwtSubmit(event) {
  event.preventDefault();
  const token = $("#jwtInput").value.trim();
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) return toast("JWT должен содержать три части, разделённые точками.", "error");
  let header, payload;
  try {
    header = JSON.parse(decodeBase64Url(parts[0]));
    payload = JSON.parse(decodeBase64Url(parts[1]));
  } catch (error) { return showError("#jwtResults", `Не удалось декодировать JWT: ${error.message}`); }
  const claimRows = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"].filter((key) => payload[key] !== undefined).map((key) => {
    const value = ["exp", "nbf", "iat"].includes(key) && Number.isFinite(Number(payload[key])) ? `${payload[key]} · ${new Date(Number(payload[key]) * 1000).toLocaleString("ru-RU")}` : typeof payload[key] === "object" ? JSON.stringify(payload[key]) : String(payload[key]);
    return kv(key, value);
  }).join("") || "<p>Стандартные claims не найдены.</p>";
  const headerJson = JSON.stringify(header, null, 2);
  const payloadJson = JSON.stringify(payload, null, 2);
  setResults("#jwtResults", `${resultBlock("JWT Header", `<pre class="query-code">${escapeHtml(headerJson)}</pre>`)}${resultBlock("JWT Payload", `<pre class="query-code">${escapeHtml(payloadJson)}</pre>`)}${resultBlock("Стандартные claims", claimRows)}<button type="button" class="btn btn-ghost btn-small" id="copyJwtPayload">Копировать payload</button><p class="result-footnote">Подпись JWT не проверялась. Декодированные claims нельзя считать достоверными без отдельной проверки подписи на стороне доверенного сервера. Не вставляй действующие секретные токены в чужие сайты.</p>`);
  $("#copyJwtPayload").addEventListener("click", () => copyText(payloadJson));
  saveScan("jwt", "JWT decode", "JWT локально декодирован без проверки подписи").catch((error) => console.warn(error));
}
function utf8ToBase64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
function base64ToUtf8(value) {
  const binary = atob(value.replace(/\s/g, ""));
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
function convertSubmit(event) {
  event.preventDefault();
  const mode = $("#convertMode").value;
  const input = $("#convertInput").value;
  let output = "";
  try {
    if (mode === "base64-encode") output = utf8ToBase64(input);
    else if (mode === "base64-decode") output = base64ToUtf8(input);
    else if (mode === "url-encode") output = encodeURIComponent(input);
    else if (mode === "url-decode") output = decodeURIComponent(input.replace(/\+/g, "%20"));
    else if (mode === "hex-encode") output = [...new TextEncoder().encode(input)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    else if (mode === "hex-decode") {
      const clean = input.replace(/\s+/g, "");
      if (!/^(?:[0-9a-f]{2})*$/i.test(clean)) throw new Error("HEX должен содержать пары шестнадцатеричных символов.");
      output = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(clean.match(/.{2}/g) || [], (part) => parseInt(part, 16)));
    }
  } catch (error) { return showError("#convertResults", `Преобразование не выполнено: ${error.message}`); }
  setResults("#convertResults", `${resultBlock("Результат преобразования", `<pre class="query-code" id="convertOutput">${escapeHtml(output)}</pre>`)}<button type="button" class="btn btn-ghost btn-small" id="copyConverted">Копировать результат</button><p class="result-footnote">Обработка выполняется локально в браузере. Данные не отправляются на внешний сервис.</p>`);
  $("#copyConverted").addEventListener("click", () => copyText(output));
  saveScan("convert", "Text conversion", `Выполнена операция ${mode}`).catch((error) => console.warn(error));
}
function timestampSubmit(event) {
  event.preventDefault();
  const raw = $("#timestampInput").value.trim();
  let date;
  if (/^-?\d+(?:\.\d+)?$/.test(raw)) {
    const numeric = Number(raw);
    if (!Number.isFinite(numeric) || Math.abs(numeric) > 8640000000000000) return toast("Timestamp выходит за допустимый диапазон.", "error");
    date = new Date(Math.abs(numeric) < 1e11 ? numeric * 1000 : numeric);
  } else date = new Date(raw);
  if (Number.isNaN(date.getTime())) return toast("Не удалось распознать timestamp или дату ISO.", "error");
  const seconds = Math.floor(date.getTime() / 1000);
  setResults("#timestampResults", `${resultBlock("Результат", [kv("Локальная дата", date.toLocaleString("ru-RU")), kv("UTC / ISO", date.toISOString()), kv("Unix seconds", seconds), kv("Unix milliseconds", date.getTime()), kv("Часовой пояс браузера", Intl.DateTimeFormat().resolvedOptions().timeZone || "не определён")].join(""), "positive")}<button type="button" class="btn btn-ghost btn-small" id="copyTimestamp">Копировать ISO</button>`);
  $("#copyTimestamp").addEventListener("click", () => copyText(date.toISOString()));
  saveScan("timestamp", "Unix timestamp", `Преобразована дата ${date.toISOString()}`).catch((error) => console.warn(error));
}
function jsonSubmit(event) {
  event.preventDefault();
  const input = $("#jsonInput").value;
  const mode = event.submitter?.value || "pretty";
  let parsed;
  try { parsed = JSON.parse(input); }
  catch (error) { return showError("#jsonResults", `Неверный JSON: ${error.message}`); }
  const output = mode === "minify" ? JSON.stringify(parsed) : JSON.stringify(parsed, null, 2);
  setResults("#jsonResults", `${resultBlock(mode === "minify" ? "Минифицированный JSON" : "Форматированный JSON", `<pre class="query-code" id="jsonOutput">${escapeHtml(output)}</pre>`)}<div class="result-footnote">JSON корректен. Размер результата: ${new TextEncoder().encode(output).length} байт.</div><button type="button" class="btn btn-ghost btn-small" id="copyJson">Копировать JSON</button>`);
  $("#copyJson").addEventListener("click", () => copyText(output));
  saveScan("json", "JSON formatter", mode === "minify" ? "JSON минифицирован" : "JSON отформатирован").catch((error) => console.warn(error));
}
function exportHistoryCsv() {
  if (!state.history.length) return toast("История пока пуста — экспортировать нечего.", "error");
  const headers = ["Тип", "Цель", "Описание", "Дата"];
  const rows = state.history.map((item) => [item.kind || "tool", item.target || "", item.summary || "", formatDate(item.createdAt)]);
  const safeCell = (value) => {
    let text = String(value ?? "");
    if (/^[\s\u0000-\u001f]*[=+@\-]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  const csv = [headers, ...rows].map((row) => row.map(safeCell).join(";")).join("\r\n");
  const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a"); link.href = url; link.download = `privacyguard-history-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link); link.click(); link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast("История экспортирована в CSV.");
}

async function copyText(value) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
    } else {
      const area = document.createElement("textarea");
      area.value = value; area.style.position = "fixed"; area.style.opacity = "0";
      document.body.append(area); area.select();
      const copied = document.execCommand("copy"); area.remove();
      if (!copied) throw new Error("copy failed");
    }
    toast("Скопировано в буфер обмена.");
  } catch { toast("Браузер запретил доступ к буферу обмена.", "error"); }
}

function attachEvents() {
  $("#loginForm").addEventListener("submit", loginWithEmail);
  $("#registerForm").addEventListener("submit", registerWithEmail);
  $("#forgotPassword").addEventListener("click", resetPassword);
  $("#googleSignIn").addEventListener("click", loginWithGoogle);
  $("#logoutButton").addEventListener("click", logout);
  $("#profileForm").addEventListener("submit", saveProfile);
  $("#ipForm").addEventListener("submit", ipSubmit);
  $("#myIpButton").addEventListener("click", () => ipSubmit(null, true));
  $("#domainForm").addEventListener("submit", domainSubmit);
  $("#domainList").addEventListener("click", handleDomainAction);
  $("#binForm").addEventListener("submit", binSubmit);
  $("#vinForm").addEventListener("submit", vinSubmit);
  $("#ibanForm").addEventListener("submit", ibanSubmit);
  $("#usernameForm").addEventListener("submit", usernameSubmit);
  $("#dorkForm").addEventListener("submit", dorkSubmit);
  $("#phoneForm").addEventListener("submit", phoneSubmit);
  $("#emailForm").addEventListener("submit", emailSubmit);
  $("#urlForm").addEventListener("submit", urlSubmit);
  $("#macForm").addEventListener("submit", macSubmit);
  $("#hashForm").addEventListener("submit", hashSubmit);
  $("#fileHashForm").addEventListener("submit", fileHashSubmit);
  $("#strengthForm").addEventListener("submit", strengthSubmit);
  $("#fileInfoForm").addEventListener("submit", fileInfoSubmit);
  $("#cveForm").addEventListener("submit", cveSubmit);
  $("#cidrForm").addEventListener("submit", cidrSubmit);
  $("#hashIdentifyForm").addEventListener("submit", hashIdentifySubmit);
  $("#uuidForm").addEventListener("submit", uuidSubmit);
  $("#mailHeaderForm").addEventListener("submit", mailHeaderSubmit);
  $("#jwtForm").addEventListener("submit", jwtSubmit);
  $("#convertForm").addEventListener("submit", convertSubmit);
  $("#timestampForm").addEventListener("submit", timestampSubmit);
  $("#jsonForm").addEventListener("submit", jsonSubmit);
  $("#passwordGeneratorForm").addEventListener("submit", passwordGeneratorSubmit);
  $("#passwordLength").addEventListener("input", (event) => { $("#passwordLengthLabel").textContent = event.target.value; });
  $("#historyFilter").addEventListener("input", (event) => { state.historyFilter = event.target.value; renderHistory(); });
  $("#exportHistory").addEventListener("click", exportHistoryCsv);
  $("#refreshHistory").addEventListener("click", async () => {
    try { await loadHistory(); renderHistory(); renderOverview(); toast("История обновлена."); }
    catch (error) { toast(`Не удалось обновить историю: ${error.message}`, "error"); }
  });
  $("#mobileMenu").addEventListener("click", openMobileSidebar);
  $("#sidebarScrim").addEventListener("click", closeMobileSidebar);
  $("#recommendChecklist").addEventListener("change", (event) => {
    const input = event.target.closest("input[data-task]");
    if (input) updateTask(input.dataset.task, input.checked);
  });
  document.addEventListener("click", (event) => {
    const brand = event.target.closest(".sidebar-brand");
    if (brand) { event.preventDefault(); goToPage("overview"); }
    const authTab = event.target.closest("[data-auth-tab]"); if (authTab) setAuthTab(authTab.dataset.authTab);
    const pageButton = event.target.closest("[data-page]"); if (pageButton) { event.preventDefault(); goToPage(pageButton.dataset.page); }
    const toggle = event.target.closest("[data-toggle-password]");
    if (toggle) {
      const input = document.getElementById(toggle.dataset.togglePassword);
      if (input) {
        input.type = input.type === "password" ? "text" : "password";
        toggle.setAttribute("aria-label", input.type === "password" ? "Показать пароль" : "Скрыть пароль");
      }
    }
  });
  window.addEventListener("hashchange", () => {
    const page = window.location.hash.replace(/^#/, "");
    if (PAGE_TITLES[page] && state.activePage !== page) goToPage(page);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeMobileSidebar();
  });
}
async function initialize() {
  attachEvents(); setAuthTab("login");
  try { await getRedirectResult(auth); }
  catch (error) { console.warn("Google redirect result:", error); toast(friendlyAuthError(error), "error"); }
  onAuthStateChanged(auth, async (user) => {
    const version = ++state.accountLoadVersion;
    state.user = user || null; state.profile = null; state.historyFilter = "";
    $("#historyFilter").value = "";
    if (!user) {
      state.history = []; state.domains = []; state.completedTasks = [];
      showAuth(); return;
    }
    state.history = []; state.domains = []; state.completedTasks = [];
    await loadAccountData(user, version);
  });
}
initialize().catch((error) => {
  console.error("PrivacyGuard init failed:", error);
  $("#bootScreen").hidden = true; showAuth();
  toast("Не удалось запустить приложение. Проверь консоль браузера и настройки Firebase.", "error");
});
