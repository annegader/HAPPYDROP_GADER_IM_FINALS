const CACHE_NAME = 'happydrop-static-v3';
const STATIC_ASSETS = [
    'assets/style.css',
    'assets/HappyDropLogo.png',
    'manifest.json'
];

self.addEventListener('install', function (event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function (cache) { return cache.addAll(STATIC_ASSETS); })
            .then(function () { return self.skipWaiting(); })
    );
});

self.addEventListener('activate', function (event) {
    event.waitUntil(
        caches.keys()
            .then(function (keys) {
                return Promise.all(keys.filter(function (key) {
                    return key !== CACHE_NAME;
                }).map(function (key) { return caches.delete(key); }));
            })
            .then(function () { return self.clients.claim(); })
    );
});

self.addEventListener('fetch', function (event) {
    const request = event.request;
    const url = new URL(request.url);
    const isStaticAsset = url.origin === self.location.origin
        && (url.pathname.includes('/assets/') || url.pathname.endsWith('/manifest.json'));

    if (request.method !== 'GET' || !isStaticAsset) return;

    event.respondWith(
        caches.match(request).then(function (cachedResponse) {
            if (cachedResponse) return cachedResponse;
            return fetch(request).then(function (response) {
                if (response.ok) {
                    const responseCopy = response.clone();
                    caches.open(CACHE_NAME).then(function (cache) {
                        return cache.put(request, responseCopy);
                    });
                }
                return response;
            });
        })
    );
});
