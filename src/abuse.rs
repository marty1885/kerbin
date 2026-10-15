//! Admission limits use bounded, fail-closed tables; buckets cannot be reset by eviction.
use crate::proxy::Response;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

#[derive(Clone)]
pub struct Limits {
    pub connections: usize,
    pub fetches: usize,
    pub per_destination: usize,
    pub parsers: usize,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub redirects: usize,
    pub timeout: Duration,
    pub client_rate: u32,
    pub client_burst: u32,
    pub global_rate: u32,
    pub global_burst: u32,
    pub destination_rate: u32,
    pub destination_burst: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 64,
            fetches: 8,
            per_destination: 2,
            parsers: 2,
            input_bytes: 2 * 1024 * 1024,
            output_bytes: 1024 * 1024,
            redirects: 5,
            timeout: Duration::from_secs(30),
            client_rate: 30,
            client_burst: 10,
            global_rate: 60,
            global_burst: 10,
            destination_rate: 12,
            destination_burst: 6,
        }
    }
}
#[derive(Default)]
pub struct Stats {
    pub denied: AtomicU64,
    pub throttled: AtomicU64,
    pub busy: AtomicU64,
    pub oversized: AtomicU64,
    pub timed_out: AtomicU64,
    pub upstream: AtomicU64,
    pub transport: AtomicU64,
}
impl Stats {
    pub fn reject(counter: &AtomicU64, status: u8, message: &str) -> Response {
        counter.fetch_add(1, Ordering::Relaxed);
        let mut response = Response::error(status, message);
        if status == 44 {
            response.cacheable = false;
        }
        response
    }
}
struct Bucket {
    tokens: f64,
    updated: Instant,
}
impl Bucket {
    fn new(burst: u32) -> Self {
        Self {
            tokens: burst.into(),
            updated: Instant::now(),
        }
    }
    fn refill(&mut self, rate: u32, burst: u32, now: Instant) {
        self.tokens = (self.tokens
            + now.duration_since(self.updated).as_secs_f64() * f64::from(rate) / 60.0)
            .min(burst.into());
        self.updated = now;
    }
    fn take(&mut self, rate: u32, burst: u32, now: Instant) -> bool {
        self.refill(rate, burst, now);
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}
struct Account {
    bucket: Bucket,
    active: usize,
    seen: Instant,
}
struct Table<K> {
    entries: HashMap<K, Account>,
    next_sweep: Instant,
}
impl<K> Table<K> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_sweep: Instant::now(),
        }
    }
}
struct State {
    handshakes: Table<IpAddr>,
    clients: Table<IpAddr>,
    destinations: Table<String>,
    global: Bucket,
    handshake_global: Bucket,
}
const TABLE_CAPACITY: usize = 4096;
// Never discard debt: remove only fully replenished, idle accounts.
fn purge(
    table: &mut HashMap<impl std::hash::Hash + Eq, Account>,
    rate: u32,
    burst: u32,
    now: Instant,
) {
    table.retain(|_, account| {
        account.bucket.refill(rate, burst, now);
        account.active != 0
            || account.bucket.tokens < f64::from(burst)
            || now.duration_since(account.seen) < Duration::from_secs(120)
    });
}
fn account<K: std::hash::Hash + Eq>(
    table: &mut Table<K>,
    key: K,
    rate: u32,
    burst: u32,
    now: Instant,
) -> Option<&mut Account> {
    if !table.entries.contains_key(&key) && table.entries.len() >= TABLE_CAPACITY {
        if now < table.next_sweep {
            return None;
        }
        table.next_sweep = now + Duration::from_secs(1);
        purge(&mut table.entries, rate, burst, now);
        if table.entries.len() >= TABLE_CAPACITY {
            return None;
        }
    }
    let value = table.entries.entry(key).or_insert_with(|| Account {
        bucket: Bucket::new(burst),
        active: 0,
        seen: now,
    });
    value.seen = now;
    Some(value)
}
#[derive(Clone)]
pub struct Guard {
    pub limits: Limits,
    pub stats: Arc<Stats>,
    pub connections: Arc<Semaphore>,
    pub parsers: Arc<Semaphore>,
    fetches: Arc<Semaphore>,
    state: Arc<Mutex<State>>,
}
impl Guard {
    pub fn new(limits: Limits) -> Self {
        Self {
            connections: Arc::new(Semaphore::new(limits.connections)),
            fetches: Arc::new(Semaphore::new(limits.fetches)),
            parsers: Arc::new(Semaphore::new(limits.parsers)),
            state: Arc::new(Mutex::new(State {
                handshakes: Table::new(),
                clients: Table::new(),
                destinations: Table::new(),
                global: Bucket::new(limits.global_burst),
                handshake_global: Bucket::new(limits.connections as u32),
            })),
            stats: Arc::new(Stats::default()),
            limits,
        }
    }
    pub fn handshake(&self, ip: IpAddr) -> bool {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let rate = self.limits.client_rate.saturating_mul(2);
        let burst = self.limits.client_burst.saturating_mul(2);
        let allowed = account(&mut state.handshakes, client_key(ip), rate, burst, now)
            .is_some_and(|account| account.bucket.take(rate, burst, now));
        let allowed = allowed
            && state.handshake_global.take(
                self.limits.global_rate.saturating_mul(2),
                self.limits.connections as u32,
                now,
            );
        if !allowed {
            self.stats.throttled.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }
    pub fn client(&self, ip: IpAddr) -> Result<(), Response> {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let allowed = account(
            &mut state.clients,
            client_key(ip),
            self.limits.client_rate,
            self.limits.client_burst,
            now,
        )
        .is_some_and(|account| {
            account
                .bucket
                .take(self.limits.client_rate, self.limits.client_burst, now)
        });
        if allowed {
            Ok(())
        } else {
            Err(Stats::reject(
                &self.stats.throttled,
                44,
                "Client request limit exceeded",
            ))
        }
    }
    pub fn fetch(&self) -> Result<OwnedSemaphorePermit, Response> {
        let permit = self
            .fetches
            .clone()
            .try_acquire_owned()
            .map_err(|_| Stats::reject(&self.stats.busy, 44, "Upstream capacity exhausted"))?;
        self.global()?;
        Ok(permit)
    }
    pub fn global(&self) -> Result<(), Response> {
        if self.state.lock().unwrap().global.take(
            self.limits.global_rate,
            self.limits.global_burst,
            Instant::now(),
        ) {
            Ok(())
        } else {
            Err(Stats::reject(
                &self.stats.throttled,
                44,
                "Global upstream request limit exceeded",
            ))
        }
    }
    // One account for the hostname and each resolved address prevents hostname
    // aliases and changing client identities from resetting destination limits.
    pub fn destination(&self, host: &str, ips: &[IpAddr]) -> Result<DestinationLease, Response> {
        let mut keys = vec![format!("host:{host}")];
        keys.extend(ips.iter().map(|ip| format!("ip:{ip}")));
        keys.sort();
        keys.dedup();
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        for key in &keys {
            let entry = account(
                &mut state.destinations,
                key.clone(),
                self.limits.destination_rate,
                self.limits.destination_burst,
                now,
            )
            .ok_or_else(|| {
                Stats::reject(
                    &self.stats.busy,
                    44,
                    "Destination accounting capacity exhausted",
                )
            })?;
            entry.bucket.refill(
                self.limits.destination_rate,
                self.limits.destination_burst,
                now,
            );
            if entry.active >= self.limits.per_destination {
                return Err(Stats::reject(
                    &self.stats.busy,
                    44,
                    "Destination concurrency limit exceeded",
                ));
            }
            if entry.bucket.tokens < 1.0 {
                return Err(Stats::reject(
                    &self.stats.throttled,
                    44,
                    "Destination request limit exceeded",
                ));
            }
        }
        for key in &keys {
            let entry = state.destinations.entries.get_mut(key).unwrap();
            entry.bucket.tokens -= 1.0;
            entry.active += 1;
        }
        Ok(DestinationLease {
            guard: self.clone(),
            keys,
        })
    }
}
pub struct DestinationLease {
    guard: Guard,
    keys: Vec<String>,
}
impl Drop for DestinationLease {
    fn drop(&mut self) {
        let mut state = self.guard.state.lock().unwrap();
        for key in &self.keys {
            state.destinations.entries.get_mut(key).unwrap().active -= 1;
        }
    }
}
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                ip.into()
            } else {
                let n = u128::from(ip) & (!0u128 << 64);
                IpAddr::V6(Ipv6Addr::from(n))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn buckets_refill_and_ipv6_clients_share_a_prefix() {
        let guard = Guard::new(Limits {
            client_rate: 60,
            client_burst: 2,
            ..Limits::default()
        });
        let a = "2001:4860:1:2::1".parse().unwrap();
        let b = "2001:4860:1:2::2".parse().unwrap();
        assert!(guard.client(a).is_ok());
        assert!(guard.client(b).is_ok());
        assert!(guard.client(a).is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(guard.client(b).is_ok());
    }
    #[tokio::test]
    async fn destination_leases_and_global_capacity_are_released() {
        let guard = Guard::new(Limits {
            fetches: 1,
            per_destination: 1,
            ..Limits::default()
        });
        let fetch = guard.fetch().unwrap();
        assert!(guard.fetch().is_err());
        drop(fetch);
        assert!(guard.fetch().is_ok());
        let ips = ["8.8.8.8".parse().unwrap()];
        let lease = guard.destination("one.example", &ips).unwrap();
        assert!(guard.destination("alias.example", &ips).is_err());
        drop(lease);
        assert!(guard.destination("alias.example", &ips).is_ok());
    }
    #[tokio::test(start_paused = true)]
    async fn destination_buckets_apply_across_clients_and_redirects() {
        let guard = Guard::new(Limits {
            global_burst: 1,
            destination_burst: 1,
            destination_rate: 60,
            ..Limits::default()
        });
        assert!(guard.global().is_ok());
        assert!(guard.global().is_err());
        let ips = ["8.8.8.8".parse().unwrap()];
        drop(guard.destination("one.example", &ips).unwrap());
        assert!(guard.destination("alias.example", &ips).is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(guard.destination("alias.example", &ips).is_ok());
    }
    #[tokio::test(start_paused = true)]
    async fn full_tables_fail_closed_without_forgetting_debt() {
        let guard = Guard::new(Limits {
            client_burst: 1,
            ..Limits::default()
        });
        for n in 0..TABLE_CAPACITY {
            assert!(
                guard
                    .client(IpAddr::V4(std::net::Ipv4Addr::from(n as u32)))
                    .is_ok()
            );
        }
        assert_eq!(
            guard.state.lock().unwrap().clients.entries.len(),
            TABLE_CAPACITY
        );
        assert!(guard.client("8.8.8.8".parse().unwrap()).is_err());
        assert!(
            guard
                .client(IpAddr::V4(std::net::Ipv4Addr::from(0)))
                .is_err()
        );
        tokio::time::advance(Duration::from_secs(121)).await;
        assert!(guard.client("8.8.8.8".parse().unwrap()).is_ok());
        assert!(guard.state.lock().unwrap().clients.entries.len() <= TABLE_CAPACITY);
    }
    #[tokio::test(start_paused = true)]
    async fn handshake_budgets_cover_many_identities_and_mapped_clients_share_tokens() {
        let guard = Guard::new(Limits {
            connections: 1,
            client_burst: 1,
            ..Default::default()
        });
        assert!(guard.handshake("1.2.3.4".parse().unwrap()));
        assert!(!guard.handshake("5.6.7.8".parse().unwrap()));
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(guard.handshake("5.6.7.8".parse().unwrap()));
        assert!(guard.client("1.2.3.4".parse().unwrap()).is_ok());
        assert!(guard.client("::ffff:1.2.3.4".parse().unwrap()).is_err());
    }
}

#[derive(clap::Args)]
pub struct Options {
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=1024))]
    max_connections: u32,
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u32).range(1..=1024))]
    max_fetches: u32,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=1024))]
    max_fetches_per_destination: u32,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=16))]
    max_parsers: u32,
    #[arg(long, default_value_t = 2_097_152, value_parser = positive_bytes)]
    max_input_bytes: usize,
    #[arg(long, default_value_t = 1_048_576, value_parser = positive_bytes)]
    max_output_bytes: usize,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(0..=10))]
    max_redirects: u32,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..=300))]
    fetch_timeout_secs: u32,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    client_requests_per_minute: u32,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    client_burst: u32,
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    global_fetches_per_minute: u32,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    global_burst: u32,
    #[arg(long, default_value_t = 12, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    destination_fetches_per_minute: u32,
    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    destination_burst: u32,
}
fn positive_bytes(value: &str) -> Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| "Expected a positive byte count".to_string())?;
    if value == 0 || value > 64 * 1024 * 1024 {
        Err("Byte limits must be between 1 and 67108864".into())
    } else {
        Ok(value)
    }
}
impl Options {
    pub fn limits(&self) -> Limits {
        Limits {
            connections: self.max_connections as usize,
            fetches: self.max_fetches as usize,
            per_destination: self.max_fetches_per_destination as usize,
            parsers: self.max_parsers as usize,
            input_bytes: self.max_input_bytes,
            output_bytes: self.max_output_bytes,
            redirects: self.max_redirects as usize,
            timeout: Duration::from_secs(self.fetch_timeout_secs.into()),
            client_rate: self.client_requests_per_minute,
            client_burst: self.client_burst,
            global_rate: self.global_fetches_per_minute,
            global_burst: self.global_burst,
            destination_rate: self.destination_fetches_per_minute,
            destination_burst: self.destination_burst,
        }
    }
}
