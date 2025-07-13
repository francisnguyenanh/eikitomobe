const CACHE_NAME = 'eikitomobe-cache-v1.0.0';
const STATIC_CACHE = 'eikitomobe-static-v1.0.0';
const DYNAMIC_CACHE = 'eikitomobe-dynamic-v1.0.0';

// Files to cache immediately when service worker installs
const STATIC_FILES = [
  '/',
  '/home',
  '/login',
  '/mindmap',
  '/task',
  '/ever_note',
  '/password_manager',
  '/static/manifest.json',
  '/static/css/common.css',
  '/static/js/master_password_auth.js',
  '/static/favicon.ico',
  // Add more critical static files
];

// Files that should be cached when accessed
const CACHE_PATTERNS = [
  /^\/static\//,
  /^\/templates\//,
  /\.css$/,
  /\.js$/,
  /\.png$/,
  /\.jpg$/,
  /\.jpeg$/,
  /\.gif$/,
  /\.webp$/,
  /\.svg$/,
  /\.ico$/,
  /\.woff$/,
  /\.woff2$/,
  /\.ttf$/
];

// API endpoints that should work offline (with cached data)
const OFFLINE_API_PATTERNS = [
  /^\/api\/card_info$/,
  /^\/api\/ui_settings$/,
  /^\/api\/links_tree$/,
  /^\/get_card_info$/,
  /^\/notes$/,
  /^\/manage_categories$/
];

// Install event - cache static files
self.addEventListener('install', event => {
  console.log('[SW] Installing service worker...');
  
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        console.log('[SW] Caching static files');
        return cache.addAll(STATIC_FILES);
      })
      .then(() => {
        console.log('[SW] Static files cached successfully');
        return self.skipWaiting(); // Force activation
      })
      .catch(error => {
        console.error('[SW] Failed to cache static files:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  console.log('[SW] Activating service worker...');
  
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
              console.log('[SW] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => {
        console.log('[SW] Service worker activated');
        return self.clients.claim(); // Take control immediately
      })
  );
});

// Fetch event - handle all network requests
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip non-GET requests for caching
  if (request.method !== 'GET') {
    // For POST/PUT/DELETE requests, try network first, fallback to offline page
    if (isOfflineApiRequest(request)) {
      event.respondWith(handleOfflineApiRequest(request));
    }
    return;
  }
  
  // Handle different types of requests
  if (isStaticFile(request)) {
    event.respondWith(cacheFirst(request, STATIC_CACHE));
  } else if (isApiRequest(request)) {
    event.respondWith(networkFirst(request, DYNAMIC_CACHE));
  } else if (isPageRequest(request)) {
    event.respondWith(networkFirst(request, DYNAMIC_CACHE));
  } else {
    event.respondWith(networkFirst(request, DYNAMIC_CACHE));
  }
});

// Cache strategies
async function cacheFirst(request, cacheName) {
  try {
    const cache = await caches.open(cacheName);
    const cachedResponse = await cache.match(request);
    
    if (cachedResponse) {
      console.log('[SW] Serving from cache:', request.url);
      return cachedResponse;
    }
    
    console.log('[SW] Cache miss, fetching from network:', request.url);
    const networkResponse = await fetch(request);
    
    if (networkResponse.ok) {
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.error('[SW] Cache first failed:', error);
    return new Response('Offline - Resource not available', { 
      status: 503,
      statusText: 'Service Unavailable'
    });
  }
}

async function networkFirst(request, cacheName) {
  try {
    console.log('[SW] Trying network first:', request.url);
    const networkResponse = await fetch(request);
    
    if (networkResponse.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.log('[SW] Network failed, trying cache:', request.url);
    
    const cache = await caches.open(cacheName);
    const cachedResponse = await cache.match(request);
    
    if (cachedResponse) {
      console.log('[SW] Serving from cache (network failed):', request.url);
      return cachedResponse;
    }
    
    // Return offline page for HTML requests
    if (request.headers.get('accept')?.includes('text/html')) {
      return caches.match('/offline.html') || createOfflinePage();
    }
    
    // Return offline JSON for API requests
    if (isApiRequest(request)) {
      return new Response(JSON.stringify({
        status: 'offline',
        message: 'This feature is not available offline',
        cached: false
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    return new Response('Offline - Resource not available', { 
      status: 503,
      statusText: 'Service Unavailable'
    });
  }
}

// Handle offline API requests (POST/PUT/DELETE)
async function handleOfflineApiRequest(request) {
  try {
    return await fetch(request);
  } catch (error) {
    console.log('[SW] API request failed, storing for sync:', request.url);
    
    // Store the request for background sync when online
    if ('sync' in self.registration) {
      await storeRequestForSync(request);
    }
    
    return new Response(JSON.stringify({
      status: 'offline',
      message: 'Request stored for sync when online',
      offline: true
    }), {
      status: 202, // Accepted
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Helper functions
function isStaticFile(request) {
  return CACHE_PATTERNS.some(pattern => pattern.test(request.url));
}

function isApiRequest(request) {
  return request.url.includes('/api/') || 
         request.url.includes('/notes') ||
         request.url.includes('/get_card_info') ||
         OFFLINE_API_PATTERNS.some(pattern => pattern.test(request.url));
}

function isOfflineApiRequest(request) {
  return OFFLINE_API_PATTERNS.some(pattern => pattern.test(request.url));
}

function isPageRequest(request) {
  return request.headers.get('accept')?.includes('text/html');
}

function createOfflinePage() {
  const offlineHTML = `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Offline - EikiTomobe</title>
      <style>
        body { 
          font-family: Arial, sans-serif; 
          text-align: center; 
          padding: 50px; 
          background: #f5f5f5; 
        }
        .offline-container {
          max-width: 400px;
          margin: 0 auto;
          background: white;
          padding: 30px;
          border-radius: 10px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .offline-icon { font-size: 64px; margin-bottom: 20px; }
        h1 { color: #333; margin-bottom: 20px; }
        p { color: #666; margin-bottom: 30px; }
        .retry-btn {
          background: #3498db;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 5px;
          cursor: pointer;
          font-size: 16px;
        }
        .retry-btn:hover { background: #2980b9; }
      </style>
    </head>
    <body>
      <div class="offline-container">
        <div class="offline-icon">📱</div>
        <h1>Bạn đang offline</h1>
        <p>Không có kết nối internet. Một số tính năng có thể không khả dụng.</p>
        <button class="retry-btn" onclick="window.location.reload()">Thử lại</button>
      </div>
    </body>
    </html>
  `;
  
  return new Response(offlineHTML, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// Background sync for storing offline requests
async function storeRequestForSync(request) {
  const requestData = {
    url: request.url,
    method: request.method,
    headers: Object.fromEntries(request.headers.entries()),
    body: await request.text(),
    timestamp: Date.now()
  };
  
  // Store in IndexedDB for background sync
  const db = await openDB();
  const transaction = db.transaction(['offline_requests'], 'readwrite');
  const store = transaction.objectStore('offline_requests');
  await store.add(requestData);
}

// IndexedDB helper
function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('EikiTomobeOfflineDB', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains('offline_requests')) {
        const store = db.createObjectStore('offline_requests', { 
          keyPath: 'id', 
          autoIncrement: true 
        });
        store.createIndex('timestamp', 'timestamp');
      }
    };
  });
}

// Background sync event
self.addEventListener('sync', event => {
  console.log('[SW] Background sync triggered:', event.tag);
  
  if (event.tag === 'offline-requests') {
    event.waitUntil(syncOfflineRequests());
  }
});

async function syncOfflineRequests() {
  try {
    const db = await openDB();
    const transaction = db.transaction(['offline_requests'], 'readonly');
    const store = transaction.objectStore('offline_requests');
    const requests = await store.getAll();
    
    for (const requestData of requests) {
      try {
        const response = await fetch(requestData.url, {
          method: requestData.method,
          headers: requestData.headers,
          body: requestData.body
        });
        
        if (response.ok) {
          // Delete synced request
          const deleteTransaction = db.transaction(['offline_requests'], 'readwrite');
          const deleteStore = deleteTransaction.objectStore('offline_requests');
          await deleteStore.delete(requestData.id);
          
          console.log('[SW] Synced offline request:', requestData.url);
        }
      } catch (error) {
        console.error('[SW] Failed to sync request:', requestData.url, error);
      }
    }
  } catch (error) {
    console.error('[SW] Background sync failed:', error);
  }
}

// Message handling for manual cache updates
self.addEventListener('message', event => {
  console.log('[SW] Received message:', event.data);
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'CACHE_UPDATE') {
    event.waitUntil(updateCache());
  }
});

async function updateCache() {
  console.log('[SW] Updating cache...');
  const cache = await caches.open(STATIC_CACHE);
  await cache.addAll(STATIC_FILES);
  console.log('[SW] Cache updated');
}
