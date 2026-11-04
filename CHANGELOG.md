# PrivacyGuard OSINT Suite — Changelog

## 3.1.1 — UI refinements
- Replaced the settings gear with a balanced, symmetrical SVG icon.
- Reworked the diagnostics legend into readable code/description rows that wrap on narrow screens.
- Updated the Service Worker cache version so installed clients fetch the corrected interface styles.

## 3.1.0 — Legal Center, Knowledge Hub & Offline Lab
- Added a premium legal document center: Terms, Privacy Policy and Acceptable Use Policy.
- Added three independent unchecked confirmation controls; the confirmed versions and server timestamp are stored per Firebase UID in `users/{uid}/legalAcceptances/...`.
- Added create-only acceptance Firestore rules (updates are denied; a user may delete their own record as part of data/account deletion) and re-confirmation on document-version changes.
- Added a step-by-step Academy / Knowledge Hub with official links to CISA Alerts and KEV, NIST NVD and NVD News, ENISA, EDPB, OWASP, MDN, Firebase and Have I Been Pwned.
- Added live NVD CVE keyword search with response escaping, timeout handling and a local rolling-window limit.
- Expanded Offline Lab into a standalone page with JSON formatter/minifier, Base64 UTF-8, SHA-256, secure random password generator, UUID and Unix timestamp converter.
- Reworked Service Worker: app shell offline fallback, dedicated Offline Lab, offline 404 response, versioned cache, same-origin static allowlist, and no cache for Firebase or third-party API responses.
- Added branded 404, 403 and 500 pages plus Firebase Hosting, Nginx and Apache deployment examples.
- Added network diagnostics, PWA installation prompt, storage estimate/persistence request and safe clearing of PrivacyGuard shell caches.
- Added Russian user guide and deployment/legal-document setup instructions.
- Kept the IPinfo Lite lookup token and request flow restored in 3.0.1.


## Major upgrade
- Сохранена исходная система Email/Google Authentication и существующие страницы инструментов 2.3.
- Добавлены разделы Projects, Assets, Monitoring, Reports, Notifications, Favorites и Settings.
- Добавлен Global Search с Ctrl+K / Cmd+K по разделам и загруженным пользовательским данным.
- Добавлены пользовательские Firestore subcollections с UID-scoped Rules.
- Добавлена ручная проверка доменов и публичных IP с сопоставлением снимков.
- Добавлено уведомление при обнаружении различий между снимками.
- Добавлено создание отчётов из снимков, экспорт JSON и печатная версия.
- Добавлен экспорт данных пользователя и удаление истории.
- Добавлены светлая/тёмная/system темы и настройка reduced motion.
- Добавлена PWA-оболочка, service worker и offline fallback без кеширования внешних API или приватных ответов.
- Удалено использование IPinfo browser token из клиентского кода; IP-обогащение переведено на ipwho.is.
- Добавлены README на русском и инструкции Firebase/Hosting.

## Known limitations
- Monitoring работает по ручному запуску; расписание через Cloud Functions/Scheduler не настроено.
- Для нового аккаунта необходима настройка Firebase Authentication, Firestore и публикация firestore.rules.
- PWA требует HTTPS или localhost; без интернета Firebase и публичные источники недоступны.
- Unified Security Score не показывается, пока нет корректной общей методики оценки.

- Добавлено окно деталей актива с DNS/SPF/DMARC/RDAP/CT или IP/ASN, историей изменений и экспортом снимка JSON.
- Исправлены подписи источника IP-геолокации (ipwho.is), проверка DNS-кодов ответов, защита CSV от formula injection и очистка только кэшей PrivacyGuard.
- В IP-активах добавлены пассивные сведения Shodan InternetDB; добавлен счётчик замечаний на Dashboard.
- Расширена проверка публичных IP: фильтрация специальных и тестовых диапазонов IPv4/IPv6, пассивное обогащение Shodan InternetDB.


## 3.0.1 — notification control and IP lookup restoration
- Increased the notification button and bell glyph size, including mobile sizing.
- Kept the unread red indicator within the button boundary and added an accessible unread-count label.
- Restored the IPinfo Lite lookup flow and the project token from the user's original 2.3 archive.
- Note: browser-side IPinfo tokens are visible to site visitors; restrict usage in the provider dashboard.
