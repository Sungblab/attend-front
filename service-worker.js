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
      return fetch(event.request).then((response) => {
        // 중요: 유효한 응답인지 확인
        if (!response || response.status !== 200 || response.type !== "basic") {
          return response;
        }

        // 응답을 복제하여 캐시에 저장
        const responseToCache = response.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });

        return response;
      });
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

// 푸시 알림 이벤트 (옵션)
self.addEventListener("push", function (event) {
  if (event.data) {
    const notificationData = event.data.json();
    const options = {
      body: notificationData.body,
      icon: "/favicon/android-chrome-192x192.png",
      badge: "/favicon/favicon-32x32.png",
    };
    event.waitUntil(
      self.registration.showNotification(notificationData.title, options)
    );
  }
});

// 오프라인 페이지 추가
const OFFLINE_PAGE = "/offline.html";

self.addEventListener("fetch", (event) => {
  event.respondWith(
    fetch(event.request).catch(() => {
      return caches.match(OFFLINE_PAGE);
    })
  );
});
