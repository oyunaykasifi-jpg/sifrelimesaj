// sifrelimesaj.com - Service Worker (Offline Cache)
// HTML: network-first (güncellemeler hızlı gelsin)
// Diğer dosyalar: cache-first (offline stabil)

const CACHE_NAME = "sifrelimesaj-v4";

const ASSETS = [
  "./",
  "./index.html",
  "./rehber.html",
  "./privacy.html",
  "./app.js",
  "./manifest.json",
  "./icon-192.png",
  "./icon-512.png"
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((c) => c.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.map((k) => (k === CACHE_NAME ? null : caches.delete(k)))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  const accept = req.headers.get("accept") || "";

  // HTML sayfalar: önce network, olmazsa cache (update sorunu çözülür)
  if (req.method === "GET" && accept.includes("text/html")) {
    e.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(req, copy));
          return res;
        })
        .catch(() =>
          caches.match(req).then((r) => r || caches.match("./index.html"))
        )
    );
    return;
  }

  // Diğer her şey: cache-first
  e.respondWith(
    caches.match(req).then((cached) => cached || fetch(req))
  );
});
