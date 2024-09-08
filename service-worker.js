const CACHE_NAME = "digital-attendance-v1";
const urlsToCache = [
  "/",
  "/index.html",
  "/hub.html",
  "/find-password.html",
  "/signup.html",
  "/change-password.html",
  "/dashboard.html",
  "/qr.html",
  "/reader.html",
  "/statistics-dashboard.html",
  "/favicon/site.webmanifest",
  "/favicon/favicon-32x32.png",
  "/favicon/favicon-16x16.png",
  "/favicon/apple-touch-icon.png",
  "/favicon/android-chrome-192x192.png",
  "/favicon/android-chrome-512x512.png",
  "https://cdn.tailwindcss.com",
  "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap",
  "https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css",
];

// 설치 이벤트
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(urlsToCache))
  );
});

// 페치 이벤트
self.addEventListener("fetch", (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      if (response) {
        return response;
      }
      return fetch(event.request);
    })
  );
});

// 활성화 이벤트
self.addEventListener("activate", (event) => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});
