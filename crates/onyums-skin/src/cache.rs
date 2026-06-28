//! Local response cache — the caching half of Phase 5's "edge-rules & caching".
//!
//! Like [edge rules](crate::edge), a response cache is **pure request logic** that ports to
//! Tor untouched: the cache key is the request method, host, and path+query — never an IP —
//! so a single in-process [`ResponseCache`] serves repeat requests for a hot path without
//! re-running the gate or the inner router. It is deliberately small and operator-driven: a
//! bounded map of `(method, host, path+query) → (status, headers, body)` with a per-entry
//! TTL, evicting the entry nearest to expiry when full.
//!
//! Caching over an onion service is a latency win, not a bandwidth one — there is no global
//! edge to fan out to (Skin's [honest non-goals](../index.html) exclude the CDN half) — but a
//! rendezvous round-trip is expensive, so caching a hot static path locally is worthwhile.
//!
//! Expiry is driven by the crate's injectable [`Clock`], so TTL behaviour is deterministically
//! testable without sleeping (as the circuit accounting already is). Only **safe, idempotent**
//! methods (`GET`/`HEAD`) are cacheable; [`cache_control_ttl`] reads a response's
//! `Cache-Control` so a `no-store` / `no-cache` origin response is never cached and an explicit
//! `max-age` is honoured.

use std::{
	collections::HashMap,
	sync::Mutex,
	time::{Duration, Instant},
};

use axum::{
	body::Body,
	http::{header, request::Parts, HeaderMap, Method, StatusCode},
	response::Response,
};

use crate::circuit::{Clock, SystemClock};

/// The cache key for one request: method, host, and path+query. Host is lowercased so the
/// onion address matches regardless of how the client cased it; the path+query is kept raw.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
	/// The request method (only `GET`/`HEAD` are stored — see [`is_cacheable_method`]).
	pub method: Method,
	/// The request host (URI authority, else the `Host` header), lowercased; empty if absent.
	pub host: String,
	/// The request path plus `?query` when present.
	pub path_and_query: String,
}

impl CacheKey {
	/// Derive the cache key from a parsed request's [`Parts`].
	#[must_use]
	pub fn from_parts(parts: &Parts) -> Self {
		let host = parts
			.uri
			.authority()
			.map(|a| a.as_str().to_owned())
			.or_else(|| parts.headers.get(header::HOST).and_then(|v| v.to_str().ok()).map(str::to_owned))
			.unwrap_or_default()
			.to_ascii_lowercase();
		let path_and_query = parts.uri.path_and_query().map_or_else(|| parts.uri.path().to_owned(), |pq| pq.as_str().to_owned());
		Self { method: parts.method.clone(), host, path_and_query }
	}
}

/// A cached response: status line, headers, and the full body bytes. Cloned out on a hit and
/// rebuilt into a [`Response`] by [`into_response`](Self::into_response).
#[derive(Clone, Debug)]
pub struct CachedResponse {
	/// The stored status code.
	pub status: StatusCode,
	/// The stored response headers.
	pub headers: HeaderMap,
	/// The full, already-collected response body.
	pub body: Vec<u8>,
}

impl CachedResponse {
	/// Construct from parts.
	#[must_use]
	pub fn new(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Self {
		Self { status, headers, body }
	}

	/// Rebuild an axum [`Response`] from the cached entry, restoring status and headers.
	#[must_use]
	pub fn into_response(self) -> Response {
		let mut response = Response::builder().status(self.status).body(Body::from(self.body)).expect("a cached status is always a valid response");
		*response.headers_mut() = self.headers;
		response
	}
}

/// One stored entry plus the instant it expires.
struct Entry {
	response: CachedResponse,
	expires: Instant,
}

/// A bounded, TTL-expiring in-process response cache. Shared behind `&self` (interior
/// `Mutex`), generic over an injectable [`Clock`] for deterministic expiry tests.
pub struct ResponseCache<C: Clock = SystemClock> {
	entries: Mutex<HashMap<CacheKey, Entry>>,
	capacity: usize,
	clock: C,
}

impl ResponseCache<SystemClock> {
	/// A cache holding at most `capacity` entries, on the real [`SystemClock`]. A `capacity`
	/// of `0` disables storage (every [`store`](Self::store) is a no-op).
	#[must_use]
	pub fn new(capacity: usize) -> Self {
		Self::with_clock(capacity, SystemClock)
	}
}

impl<C: Clock> ResponseCache<C> {
	/// A cache holding at most `capacity` entries, on a caller-supplied [`Clock`].
	#[must_use]
	pub fn with_clock(capacity: usize, clock: C) -> Self {
		Self { entries: Mutex::new(HashMap::new()), capacity, clock }
	}

	/// Look up a fresh entry. Returns a clone of the [`CachedResponse`] on a hit; on a miss —
	/// including an entry that has expired — returns `None` and drops the stale entry.
	#[must_use]
	pub fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
		let now = self.clock.now();
		let mut entries = self.lock();
		match entries.get(key) {
			Some(entry) if entry.expires > now => Some(entry.response.clone()),
			Some(_) => {
				entries.remove(key);
				None
			}
			None => None,
		}
	}

	/// Store `response` under `key` with a freshness lifetime of `ttl`. Returns whether it was
	/// stored: a zero `capacity`, a zero `ttl`, or a non-cacheable method (the key's method is
	/// not `GET`/`HEAD`) all decline. When the cache is full, expired entries are purged first,
	/// then the entry nearest to expiry is evicted to make room.
	pub fn store(&self, key: CacheKey, response: CachedResponse, ttl: Duration) -> bool {
		if self.capacity == 0 || ttl.is_zero() || !is_cacheable_method(&key.method) {
			return false;
		}
		let now = self.clock.now();
		let mut entries = self.lock();
		// Refreshing an existing key never needs eviction; only a genuinely new key can grow
		// the map past capacity.
		if !entries.contains_key(&key) && entries.len() >= self.capacity {
			purge_expired(&mut entries, now);
			if entries.len() >= self.capacity {
				evict_nearest_expiry(&mut entries);
			}
		}
		entries.insert(key, Entry { response, expires: now + ttl });
		true
	}

	/// Drop every expired entry, returning how many were removed.
	pub fn purge_expired(&self) -> usize {
		let now = self.clock.now();
		let mut entries = self.lock();
		let before = entries.len();
		purge_expired(&mut entries, now);
		before - entries.len()
	}

	/// The number of entries currently held (including any not-yet-purged expired ones).
	#[must_use]
	pub fn len(&self) -> usize {
		self.lock().len()
	}

	/// Whether the cache holds no entries.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.lock().is_empty()
	}

	/// Remove all entries.
	pub fn clear(&self) {
		self.lock().clear();
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Entry>> {
		self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}
}

/// Whether a method is safe to cache: only the read-only, idempotent `GET` and `HEAD`.
#[must_use]
pub fn is_cacheable_method(method: &Method) -> bool {
	matches!(*method, Method::GET | Method::HEAD)
}

/// Read a freshness lifetime from a response's `Cache-Control`. Returns `None` — meaning "do
/// not cache" — when `no-store` or `no-cache` is present or there is no positive `max-age`;
/// otherwise the `max-age=N` value as a [`Duration`]. A `max-age` of `0` yields `None`.
#[must_use]
pub fn cache_control_ttl(headers: &HeaderMap) -> Option<Duration> {
	let value = headers.get(header::CACHE_CONTROL)?.to_str().ok()?;
	let mut max_age = None;
	for directive in value.split(',') {
		let directive = directive.trim();
		let lower = directive.to_ascii_lowercase();
		if lower == "no-store" || lower == "no-cache" || lower == "private" {
			return None;
		}
		if let Some(seconds) = lower.strip_prefix("max-age=") {
			max_age = seconds.trim().parse::<u64>().ok();
		}
	}
	match max_age {
		Some(0) | None => None,
		Some(seconds) => Some(Duration::from_secs(seconds)),
	}
}

/// Remove every entry whose expiry is at or before `now`.
fn purge_expired(entries: &mut HashMap<CacheKey, Entry>, now: Instant) {
	entries.retain(|_, entry| entry.expires > now);
}

/// Evict the single entry nearest to expiring (the smallest `expires`). No-op when empty.
fn evict_nearest_expiry(entries: &mut HashMap<CacheKey, Entry>) {
	if let Some(key) = entries.iter().min_by_key(|(_, entry)| entry.expires).map(|(key, _)| key.clone()) {
		entries.remove(&key);
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use axum::http::Request;

	use super::*;
	use crate::circuit::ManualClock;

	/// Shares one [`ManualClock`] between the test driver and the cache (the cache takes the
	/// clock by value, so an `Arc` newtype hands both ends the same underlying clock — the
	/// same pattern `circuit`'s tests use).
	#[derive(Clone)]
	struct SharedClock(Arc<ManualClock>);

	impl Clock for SharedClock {
		fn now(&self) -> Instant {
			self.0.now()
		}
	}

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	fn body(text: &str) -> CachedResponse {
		CachedResponse::new(StatusCode::OK, HeaderMap::new(), text.as_bytes().to_vec())
	}

	#[test]
	fn cache_key_lowercases_host_and_keeps_path_and_query() {
		let key = CacheKey::from_parts(&parts(Request::builder().method("GET").uri("/page?x=1").header("host", "ABC.onion")));
		assert_eq!(key.method, Method::GET);
		assert_eq!(key.host, "abc.onion");
		assert_eq!(key.path_and_query, "/page?x=1");
	}

	#[test]
	fn store_then_get_round_trips_a_hit() {
		let cache = ResponseCache::new(8);
		let key = CacheKey::from_parts(&parts(Request::builder().uri("/")));
		assert!(cache.store(key.clone(), body("hello"), Duration::from_secs(60)));
		let hit = cache.get(&key).expect("fresh entry hits");
		assert_eq!(hit.body, b"hello");
		assert_eq!(hit.status, StatusCode::OK);
	}

	#[test]
	fn miss_on_absent_key() {
		let cache = ResponseCache::new(8);
		assert!(cache.get(&CacheKey::from_parts(&parts(Request::builder().uri("/nope")))).is_none());
	}

	#[test]
	fn entry_expires_after_ttl_and_is_dropped_on_get() {
		let clock = Arc::new(ManualClock::new());
		let cache = ResponseCache::with_clock(8, SharedClock(clock.clone()));
		let key = CacheKey::from_parts(&parts(Request::builder().uri("/")));
		cache.store(key.clone(), body("v"), Duration::from_secs(10));
		clock.advance(Duration::from_secs(5));
		assert!(cache.get(&key).is_some(), "still fresh at t+5");
		clock.advance(Duration::from_secs(6));
		assert!(cache.get(&key).is_none(), "expired at t+11");
		assert_eq!(cache.len(), 0, "expired entry is dropped on the missing get");
	}

	#[test]
	fn store_declines_zero_capacity_zero_ttl_and_uncacheable_methods() {
		let key = CacheKey::from_parts(&parts(Request::builder().uri("/")));
		assert!(!ResponseCache::new(0).store(key.clone(), body("x"), Duration::from_secs(1)), "zero capacity");
		assert!(!ResponseCache::new(8).store(key.clone(), body("x"), Duration::ZERO), "zero ttl");
		let post = CacheKey::from_parts(&parts(Request::builder().method("POST").uri("/")));
		assert!(!ResponseCache::new(8).store(post, body("x"), Duration::from_secs(1)), "POST is uncacheable");
	}

	#[test]
	fn refreshing_an_existing_key_does_not_count_against_capacity() {
		let cache = ResponseCache::new(1);
		let key = CacheKey::from_parts(&parts(Request::builder().uri("/")));
		assert!(cache.store(key.clone(), body("one"), Duration::from_secs(60)));
		assert!(cache.store(key.clone(), body("two"), Duration::from_secs(60)));
		assert_eq!(cache.len(), 1);
		assert_eq!(cache.get(&key).unwrap().body, b"two");
	}

	#[test]
	fn full_cache_purges_expired_before_evicting() {
		let clock = Arc::new(ManualClock::new());
		let cache = ResponseCache::with_clock(2, SharedClock(clock.clone()));
		let a = CacheKey::from_parts(&parts(Request::builder().uri("/a")));
		let b = CacheKey::from_parts(&parts(Request::builder().uri("/b")));
		let c = CacheKey::from_parts(&parts(Request::builder().uri("/c")));
		cache.store(a.clone(), body("a"), Duration::from_secs(1)); // expires soon
		cache.store(b.clone(), body("b"), Duration::from_secs(100));
		clock.advance(Duration::from_secs(2)); // `a` is now expired
		// Inserting `c` should reclaim `a` (purged as expired), keeping `b`.
		cache.store(c.clone(), body("c"), Duration::from_secs(100));
		assert!(cache.get(&a).is_none());
		assert!(cache.get(&b).is_some());
		assert!(cache.get(&c).is_some());
	}

	#[test]
	fn full_cache_with_no_expired_evicts_nearest_expiry() {
		let cache = ResponseCache::new(2);
		let a = CacheKey::from_parts(&parts(Request::builder().uri("/a")));
		let b = CacheKey::from_parts(&parts(Request::builder().uri("/b")));
		let c = CacheKey::from_parts(&parts(Request::builder().uri("/c")));
		cache.store(a.clone(), body("a"), Duration::from_secs(10)); // nearest expiry
		cache.store(b.clone(), body("b"), Duration::from_secs(100));
		cache.store(c.clone(), body("c"), Duration::from_secs(100));
		assert!(cache.get(&a).is_none(), "the nearest-expiry entry is evicted");
		assert!(cache.get(&b).is_some());
		assert!(cache.get(&c).is_some());
		assert_eq!(cache.len(), 2);
	}

	#[test]
	fn purge_expired_counts_and_clears() {
		let clock = Arc::new(ManualClock::new());
		let cache = ResponseCache::with_clock(8, SharedClock(clock.clone()));
		cache.store(CacheKey::from_parts(&parts(Request::builder().uri("/a"))), body("a"), Duration::from_secs(1));
		cache.store(CacheKey::from_parts(&parts(Request::builder().uri("/b"))), body("b"), Duration::from_secs(1));
		clock.advance(Duration::from_secs(2));
		assert_eq!(cache.purge_expired(), 2);
		assert!(cache.is_empty());
	}

	#[test]
	fn cache_control_ttl_parses_max_age_and_honours_no_store() {
		let mut headers = HeaderMap::new();
		headers.insert(header::CACHE_CONTROL, "public, max-age=300".parse().unwrap());
		assert_eq!(cache_control_ttl(&headers), Some(Duration::from_secs(300)));
		headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
		assert_eq!(cache_control_ttl(&headers), None);
		headers.insert(header::CACHE_CONTROL, "max-age=0".parse().unwrap());
		assert_eq!(cache_control_ttl(&headers), None);
		headers.insert(header::CACHE_CONTROL, "private, max-age=60".parse().unwrap());
		assert_eq!(cache_control_ttl(&headers), None, "private is treated as uncacheable by a shared cache");
		assert_eq!(cache_control_ttl(&HeaderMap::new()), None, "no header → no caching");
	}

	#[test]
	fn cached_response_round_trips_into_a_response() {
		let mut headers = HeaderMap::new();
		headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
		let response = CachedResponse::new(StatusCode::NOT_FOUND, headers, b"missing".to_vec()).into_response();
		assert_eq!(response.status(), StatusCode::NOT_FOUND);
		assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/plain");
	}
}
