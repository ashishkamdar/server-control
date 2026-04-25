const CACHE_NAME = "mmam-v2";
const API_CACHE = "mmam-api-v1";
const SYNC_QUEUE = "mmam-sync-queue";

// App shell — pages and static assets to cache
const SHELL_URLS = [
  "/",
  "/coach",
  "/personality",
  "/event-prep",
  "/gymkhana",
  "/projects",
  "/approach",
  "/online-work",
  "/journal",
  "/revenue",
  "/whatsapp",
  "/weekly-review",
  "/portfolio",
  "/suggestions",
  "/chat",
  "/settings",
];

// API endpoints to cache responses for offline reading
const CACHEABLE_APIS = [
  "/api/projects",
  "/api/gymkhana",
  "/api/coaching",
  "/api/journal",
  "/api/revenue",
  "/api/weekly-review",
  "/api/whatsapp-templates",
];

// Install — cache app shell
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(SHELL_URLS).catch(() => {
        // Some pages may fail — that's ok, cache what we can
        return Promise.allSettled(
          SHELL_URLS.map((url) => cache.add(url).catch(() => {}))
        );
      });
    })
  );
  self.skipWaiting();
});

// Activate — clean old caches
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME && key !== API_CACHE)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// Fetch — network first for APIs, cache first for pages
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Skip non-GET requests (POST/PUT/DELETE go to sync queue if offline)
  if (event.request.method !== "GET") {
    event.respondWith(handleMutationRequest(event.request));
    return;
  }

  // API requests — network first, fall back to cache
  if (CACHEABLE_APIS.some((api) => url.pathname === api)) {
    event.respondWith(networkFirstThenCache(event.request, API_CACHE));
    return;
  }

  // Page/asset requests — cache first, fall back to network
  if (url.origin === self.location.origin) {
    event.respondWith(cacheFirstThenNetwork(event.request));
    return;
  }

  // External requests — just fetch
  event.respondWith(fetch(event.request));
});

// Network first strategy (for APIs)
async function networkFirstThenCache(request, cacheName) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match(request);
    if (cached) return cached;
    return new Response(JSON.stringify([]), {
      headers: { "Content-Type": "application/json" },
    });
  }
}

// Cache first strategy (for pages/assets)
async function cacheFirstThenNetwork(request) {
  const cached = await caches.match(request);
  if (cached) {
    // Refresh cache in background
    fetch(request)
      .then((response) => {
        if (response.ok) {
          caches.open(CACHE_NAME).then((cache) => cache.put(request, response));
        }
      })
      .catch(() => {});
    return cached;
  }
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    // Return offline page for navigation requests
    if (request.mode === "navigate") {
      return caches.match("/") || new Response("Offline", { status: 503 });
    }
    return new Response("Offline", { status: 503 });
  }
}

// Handle mutation requests (POST/PUT/DELETE) — queue if offline
async function handleMutationRequest(request) {
  try {
    const response = await fetch(request.clone());
    return response;
  } catch {
    // Offline — queue for later sync
    const body = await request.text();
    const queueItem = {
      url: request.url,
      method: request.method,
      headers: Object.fromEntries(request.headers.entries()),
      body: body,
      timestamp: Date.now(),
    };

    // Store in IndexedDB
    await storeInSyncQueue(queueItem);

    // Return a fake success response
    return new Response(JSON.stringify({ queued: true, offline: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }
}

// IndexedDB for sync queue
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("mmam-offline", 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("sync-queue")) {
        db.createObjectStore("sync-queue", { keyPath: "timestamp" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function storeInSyncQueue(item) {
  const db = await openDB();
  const tx = db.transaction("sync-queue", "readwrite");
  tx.objectStore("sync-queue").add(item);
}

async function getAndClearSyncQueue() {
  const db = await openDB();
  const tx = db.transaction("sync-queue", "readwrite");
  const store = tx.objectStore("sync-queue");

  return new Promise((resolve) => {
    const req = store.getAll();
    req.onsuccess = () => {
      const items = req.result;
      store.clear();
      resolve(items);
    };
    req.onerror = () => resolve([]);
  });
}

// Sync when back online
self.addEventListener("message", async (event) => {
  if (event.data === "sync") {
    const queue = await getAndClearSyncQueue();
    let synced = 0;

    for (const item of queue) {
      try {
        await fetch(item.url, {
          method: item.method,
          headers: item.headers,
          body: item.body,
        });
        synced++;
      } catch {
        // Still offline — re-queue
        await storeInSyncQueue(item);
      }
    }

    // Notify all clients
    const clients = await self.clients.matchAll();
    clients.forEach((client) =>
      client.postMessage({ type: "sync-complete", synced, remaining: queue.length - synced })
    );
  }
});
