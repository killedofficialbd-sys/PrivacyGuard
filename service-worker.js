/* PrivacyGuard 3.1 service worker
 * Cache only the app shell and same-origin static files. Never cache Firebase/API responses or private user data.
 */
const CACHE_NAME = 'privacyguard-shell-v3-1-1-ui-fix';
const SHELL = [
  './', './index.html', './offline.html', './404.html', './403.html', './500.html',
  './css/styles.css', './css/pg31.css',
  './js/app.js', './js/firebase.js', './js/v3.js', './js/legal.js', './js/offline.js',
  './manifest.json', './README_RU.txt', './CHANGELOG.md',
  './docs/USER_GUIDE_RU.md', './docs/USER_AGREEMENT_RU.md', './docs/PRIVACY_POLICY_RU.md', './docs/ACCEPTABLE_USE_RU.md',
  './assets/icons/icon.svg', './assets/icons/icon-192.png', './assets/icons/icon-512.png'
];
const STATIC_EXTENSIONS = /\.(?:html|css|js|svg|png|webp|woff2|json|md|txt)$/i;

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key.startsWith('privacyguard-shell-') && key !== CACHE_NAME).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);

  // Connection probes must go to the network and must never be served from cache.
  if (url.searchParams.has('pg_probe')) {
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }

  // Do not cache cross-origin calls: Firebase, IP intelligence, DNS, CVE, HIBP and other APIs.
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const response = await fetch(request);
        if (response && response.ok) {
          const copy = response.clone();
          const cache = await caches.open(CACHE_NAME);
          const path = new URL(request.url).pathname;
          if (path.endsWith('/') || path.endsWith('/index.html')) await cache.put('./index.html', copy);
        }
        return response;
      } catch {
        const path = url.pathname;
        const isAppRoot = path.endsWith('/') || path.endsWith('/index.html') || path.endsWith('/offline.html');
        if (!isAppRoot) {
          const missing = await caches.match('./404.html');
          if (missing) return new Response(missing.body, { status: 404, statusText: 'Not Found', headers: missing.headers });
        }
        const offline = await caches.match('./offline.html');
        if (offline) return offline;
        return new Response('PG-NET-001 · PrivacyGuard is offline. Reconnect and retry.', {
          status: 503, statusText: 'Service Unavailable',
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }
    })());
    return;
  }

  const allowedStatic = url.pathname.endsWith('/manifest.json') ||
    /\/(?:css|js|assets|docs)\//.test(url.pathname) ||
    /\/(?:index|offline|404|403|500)\.html$/.test(url.pathname) ||
    url.pathname.endsWith('/README_RU.txt') || url.pathname.endsWith('/CHANGELOG.md');
  if (allowedStatic && STATIC_EXTENSIONS.test(url.pathname)) {
    event.respondWith((async () => {
      const cached = await caches.match(request);
      if (cached) return cached;
      try {
        const response = await fetch(request);
        if (response.ok) {
          const copy = response.clone();
          const cache = await caches.open(CACHE_NAME);
          await cache.put(request, copy);
        }
        return response;
      } catch {
        return new Response('PG-NET-001 · Resource is unavailable offline.', {
          status: 503, statusText: 'Service Unavailable',
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }
    })());
  }
});
