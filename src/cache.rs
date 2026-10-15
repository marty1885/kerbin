//! Byte-budgeted LRU storage plus one shared fetch per key.
use crate::proxy::Response;
use lru::LruCache;
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

pub type Wire = Arc<[u8]>;
type Pending = watch::Receiver<Option<Wire>>;
// Charge an allowance for each entry's bookkeeping, in addition to key/body bytes.
const ENTRY_OVERHEAD: usize = 128;

struct Entry {
    wire: Wire,
    expires: Instant,
    weight: usize,
}
struct State {
    entries: LruCache<String, Entry>,
    bytes: usize,
    pending: HashMap<String, Pending>,
}
impl State {
    fn purge(&mut self, now: Instant) {
        let bytes = &mut self.bytes;
        self.entries.retain(|_, entry| {
            if entry.expires <= now {
                *bytes -= entry.weight;
                false
            } else {
                true
            }
        });
    }
}
#[derive(Default)]
pub struct Stats {
    pub hits: AtomicU64,
    pub shared: AtomicU64,
    pub misses: AtomicU64,
}
struct Inner {
    state: Mutex<State>,
    max_bytes: usize,
    ttl: Duration,
    stats: Arc<Stats>,
}
#[derive(Clone)]
pub struct Cache(Arc<Inner>);
impl Cache {
    pub fn new(max_bytes: usize, ttl: Duration) -> Self {
        let inner = Arc::new(Inner {
            state: Mutex::new(State {
                entries: LruCache::unbounded(),
                bytes: 0,
                pending: HashMap::new(),
            }),
            max_bytes,
            ttl,
            stats: Arc::new(Stats::default()),
        });
        // Reclaim expired entries even when nobody requests them again.
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(inner) = weak.upgrade() else { break };
                inner.state.lock().unwrap().purge(Instant::now());
            }
        });
        Self(inner)
    }

    pub fn stats(&self) -> Arc<Stats> {
        self.0.stats.clone()
    }
    pub async fn get_or_fetch<F, Fut>(&self, key: String, fetch: F) -> Wire
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        let mut receiver = {
            let mut state = self.0.state.lock().unwrap();
            let now = Instant::now();
            if let Some(entry) = state.entries.get(&key)
                && entry.expires > now
            {
                self.0.stats.hits.fetch_add(1, Ordering::Relaxed);
                return entry.wire.clone();
            }
            if let Some(entry) = state.entries.pop(&key) {
                state.bytes -= entry.weight;
            }
            if let Some(receiver) = state.pending.get(&key) {
                self.0.stats.shared.fetch_add(1, Ordering::Relaxed);
                receiver.clone()
            } else {
                if state.pending.len() >= 128 {
                    return Response::error(44, "Pending request capacity exhausted")
                        .wire()
                        .into();
                }
                self.0.stats.misses.fetch_add(1, Ordering::Relaxed);
                let (sender, receiver) = watch::channel(None);
                state.pending.insert(key.clone(), receiver.clone());
                let inner = self.0.clone();
                // Fetch lifetime is independent of any one client disconnecting.
                tokio::spawn(async move {
                    // Supervise the worker so a parser panic cannot strand waiters.
                    let response = tokio::spawn(async move { fetch().await })
                        .await
                        .unwrap_or_else(|_| Response::error(43, "Upstream processing failed"));
                    let ttl = if response.status == 20 {
                        inner.ttl
                    } else {
                        inner.ttl.min(Duration::from_secs(10))
                    };
                    let wire: Wire = response.wire().into();
                    let weight = wire
                        .len()
                        .saturating_add(key.len())
                        .saturating_add(ENTRY_OVERHEAD);
                    let mut state = inner.state.lock().unwrap();
                    state.purge(Instant::now());
                    if response.status != 44
                        && response.cacheable
                        && !ttl.is_zero()
                        && weight <= inner.max_bytes
                    {
                        while state.bytes > inner.max_bytes - weight {
                            let (_, entry) = state.entries.pop_lru().unwrap();
                            state.bytes -= entry.weight;
                        }
                        state.bytes += weight;
                        state.entries.put(
                            key.clone(),
                            Entry {
                                wire: wire.clone(),
                                expires: Instant::now() + ttl,
                                weight,
                            },
                        );
                    }
                    // Publish under the lock before allowing a new fetch for this key.
                    sender.send_replace(Some(wire));
                    state.pending.remove(&key);
                });
                receiver
            }
        };
        loop {
            if let Some(wire) = receiver.borrow_and_update().clone() {
                return wire;
            }
            if receiver.changed().await.is_err() {
                return Response::error(43, "Upstream processing interrupted")
                    .wire()
                    .into();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn page(text: &str) -> Response {
        Response {
            status: 20,
            meta: "text/gemini".into(),
            body: text.as_bytes().to_vec(),
            cacheable: true,
        }
    }
    async fn get(cache: &Cache, key: &str, count: &Arc<AtomicUsize>) -> Wire {
        let count = count.clone();
        cache
            .get_or_fetch(key.into(), move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                page("page")
            })
            .await
    }
    #[tokio::test(start_paused = true)]
    async fn fixed_ttl_and_idle_reclamation() {
        let cache = Cache::new(4096, Duration::from_secs(5));
        let count = Arc::new(AtomicUsize::new(0));
        let first = get(&cache, "a", &count).await;
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(Arc::ptr_eq(&first, &get(&cache, "a", &count).await));
        tokio::time::advance(Duration::from_secs(1)).await;
        get(&cache, "a", &count).await;
        assert_eq!(count.load(Ordering::SeqCst), 2); // Hits don't extend TTL.
        tokio::time::advance(Duration::from_secs(6)).await;
        tokio::task::yield_now().await;
        assert_eq!(cache.0.state.lock().unwrap().bytes, 0);
    }
    #[tokio::test]
    async fn byte_budget_evicts_lru_and_bypasses_oversized_entries() {
        let weight = page("page").wire().len() + 1 + ENTRY_OVERHEAD;
        let cache = Cache::new(2 * weight, Duration::from_secs(60));
        let count = Arc::new(AtomicUsize::new(0));
        get(&cache, "a", &count).await;
        get(&cache, "b", &count).await;
        get(&cache, "a", &count).await;
        get(&cache, "c", &count).await;
        {
            let state = cache.0.state.lock().unwrap();
            assert!(state.entries.contains("a"));
            assert!(!state.entries.contains("b"));
            assert!(state.bytes <= 2 * weight);
        }
        cache
            .get_or_fetch("huge".into(), || async { page(&"x".repeat(4096)) })
            .await;
        let state = cache.0.state.lock().unwrap();
        assert!(!state.entries.contains("huge"));
        assert_eq!(state.bytes, 2 * weight);
    }
    #[tokio::test]
    async fn concurrent_requests_share_fetch_even_if_initiator_is_cancelled() {
        let cache = Cache::new(4096, Duration::from_secs(60));
        let count = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let other = cache.clone();
        let counter = count.clone();
        let initiator = tokio::spawn(async move {
            other
                .get_or_fetch("a".into(), move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    started_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    page("page")
                })
                .await
        });
        started_rx.await.unwrap();
        initiator.abort();
        let mut waiters = Vec::new();
        for _ in 0..20 {
            let cache = cache.clone();
            let count = count.clone();
            waiters.push(tokio::spawn(async move { get(&cache, "a", &count).await }));
        }
        tokio::task::yield_now().await;
        release_tx.send(()).unwrap();
        for waiter in waiters {
            assert!(waiter.await.unwrap().starts_with(b"20 "));
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(cache.0.state.lock().unwrap().pending.is_empty());
    }
    #[tokio::test(start_paused = true)]
    async fn errors_expire_early_and_uncacheable_and_disabled_responses_are_not_retained() {
        let cache = Cache::new(4096, Duration::from_secs(60));
        let error = cache
            .get_or_fetch("error".into(), || async { Response::error(43, "failed") })
            .await;
        assert!(Arc::ptr_eq(
            &error,
            &cache
                .get_or_fetch("error".into(), || async { page("retry") })
                .await
        ));
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(
            cache
                .get_or_fetch("error".into(), || async { page("retry") })
                .await
                .starts_with(b"20 ")
        );
        cache
            .get_or_fetch("private".into(), || async {
                let mut r = page("private");
                r.cacheable = false;
                r
            })
            .await;
        assert!(!cache.0.state.lock().unwrap().entries.contains("private"));
        for cache in [
            Cache::new(0, Duration::from_secs(60)),
            Cache::new(4096, Duration::ZERO),
        ] {
            let count = Arc::new(AtomicUsize::new(0));
            get(&cache, "a", &count).await;
            get(&cache, "a", &count).await;
            assert_eq!(count.load(Ordering::SeqCst), 2);
            assert_eq!(cache.0.state.lock().unwrap().bytes, 0);
        }
    }
    #[tokio::test]
    async fn panicked_fetch_does_not_strand_pending_requests() {
        let cache = Cache::new(4096, Duration::from_secs(60));
        let wire = cache
            .get_or_fetch("panic".into(), || async { panic!("worker failure") })
            .await;
        assert!(wire.starts_with(b"43 "));
        assert!(cache.0.state.lock().unwrap().pending.is_empty());
    }
    #[tokio::test]
    async fn pending_work_has_a_hard_cap() {
        let cache = Cache::new(4096, Duration::from_secs(60));
        let started = Arc::new(tokio::sync::Barrier::new(129));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let mut jobs = Vec::new();
        for n in 0..128 {
            let cache = cache.clone();
            let started = started.clone();
            let release = release.clone();
            jobs.push(tokio::spawn(async move {
                cache
                    .get_or_fetch(format!("key-{n}"), move || async move {
                        started.wait().await;
                        release.acquire().await.unwrap().forget();
                        page("page")
                    })
                    .await
            }));
        }
        started.wait().await;
        assert!(
            cache
                .get_or_fetch("overflow".into(), || async {
                    panic!("Overflow fetch must not start")
                })
                .await
                .starts_with(b"44 ")
        );
        assert_eq!(cache.0.state.lock().unwrap().pending.len(), 128);
        release.add_permits(128);
        for job in jobs {
            assert!(job.await.unwrap().starts_with(b"20 "));
        }
        assert!(cache.0.state.lock().unwrap().pending.is_empty());
    }
}
