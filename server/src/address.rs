//! DRA-0055 (`docs/DELIVERY_FAILURE_FINDINGS.md`) — per-source-address
//! connection limits.
//!
//! Every other limiter in this server (`crate::abuse`) is keyed by a
//! connection id or an authenticated identity, and both are free to
//! mint: authentication is self-certifying (`ws.rs`'s module doc), so one
//! client can open a connection, authenticate as a brand-new keypair, and
//! repeat without limit. That is the residual scope DRA-0031 (a global
//! connection cap one source can fill), DRA-0044 (throwaway identities
//! between pruning sweeps) and DRA-0050 (per-identity limiters, but
//! identities are free) each recorded. Keying on the network address is
//! the one thing a client can't regenerate for free.
//!
//! [`AddressLimiter`] enforces two things per address:
//! - at most [`MAX_CONNECTIONS_PER_ADDRESS`] concurrent connections, and
//! - a token bucket on *opening* connections
//!   ([`NEW_CONNECTIONS_PER_ADDRESS_CAPACITY`], refilling at
//!   [`NEW_CONNECTIONS_PER_ADDRESS_REFILL_PER_SEC`]). A connection can
//!   authenticate at most once, so this also bounds how fast one address
//!   can bring new identities online.
//!
//! **Which address.** By default, the TCP peer address, which a client
//! can't spoof. Behind a reverse proxy (the chart's optional Ingress),
//! every connection's peer is the proxy, so the operator lists the
//! proxy's address ranges as trusted ([`TrustedProxies`]). Only for a
//! connection *from* a trusted proxy is `X-Forwarded-For` read, walking
//! it right to left past any further trusted hops. `X-Forwarded-For` from
//! anyone else is ignored, since a client can write anything there.
//!
//! **IPv6.** A single host is normally given a whole /64, so IPv6
//! addresses are grouped by /64 — otherwise one host could rotate through
//! 2^64 source addresses and never hit a limit.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

/// Concurrent connections allowed from one address. Generous on purpose:
/// several devices behind one household or office NAT share an address.
pub const MAX_CONNECTIONS_PER_ADDRESS: usize = 32;
/// Burst of new connections one address may open back to back — enough
/// for every device behind a NAT reconnecting at once after an outage.
pub const NEW_CONNECTIONS_PER_ADDRESS_CAPACITY: f64 = 60.0;
/// Sustained new-connection rate per address once the burst is spent.
/// A real client reconnects with a 2s-to-60s backoff (`ui/src-tauri`'s
/// `poll_loop`), far below this.
pub const NEW_CONNECTIONS_PER_ADDRESS_REFILL_PER_SEC: f64 = 1.0;

/// An IP network in CIDR form (`10.0.0.0/8`, `fd00::/8`); a bare address
/// is a single-host network. Used only to describe trusted proxies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                mask_v4(net, self.prefix) == mask_v4(ip, self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                mask_v6(net, self.prefix) == mask_v6(ip, self.prefix)
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for IpNet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("{s:?} is not an IP address or CIDR range"))?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("{s:?} has an invalid prefix length"))?,
            None => max,
        };
        Ok(IpNet { addr, prefix })
    }
}

fn mask_v4(ip: Ipv4Addr, prefix: u8) -> u32 {
    let bits = u32::from(ip);
    if prefix == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - u32::from(prefix)))
    }
}

fn mask_v6(ip: Ipv6Addr, prefix: u8) -> u128 {
    let bits = u128::from(ip);
    if prefix == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - u32::from(prefix)))
    }
}

/// The operator-configured reverse proxies whose `X-Forwarded-For` is
/// believed. Empty (the default) means the header is never read.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<IpNet>);

impl TrustedProxies {
    pub fn new(nets: Vec<IpNet>) -> Self {
        TrustedProxies(nets)
    }

    /// Parse a comma-separated list, e.g. `"10.42.0.0/16, 10.43.0.0/16"`.
    /// An empty string yields no trusted proxies.
    pub fn parse_list(list: &str) -> Result<Self, String> {
        list.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::parse)
            .collect::<Result<Vec<_>, _>>()
            .map(TrustedProxies)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|net| net.contains(ip))
    }

    /// The address to attribute a connection to: `peer` itself unless
    /// `peer` is a trusted proxy, in which case the right-most
    /// `X-Forwarded-For` entry that isn't also a trusted proxy. Falls back
    /// to `peer` if the header is missing or unusable.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        if !self.trusts(peer) {
            return peer;
        }
        let hops: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect();
        for hop in hops.iter().rev() {
            let Ok(ip) = hop.parse::<IpAddr>().map(|ip| ip.to_canonical()) else {
                // A trusted proxy only ever appends real addresses, so an
                // unparseable entry means we've walked into client-supplied
                // text without finding the client. Don't guess.
                return peer;
            };
            if !self.trusts(ip) {
                return ip;
            }
        }
        peer
    }
}

/// What an address is counted under: the IPv4 address, or the IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKey {
    V4(Ipv4Addr),
    V6Prefix64(u64),
}

impl AddressKey {
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => AddressKey::V4(v4),
            IpAddr::V6(v6) => AddressKey::V6Prefix64((u128::from(v6) >> 64) as u64),
        }
    }
}

/// Why [`AddressLimiter::try_acquire`] refused a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressRefusal {
    TooManyConcurrent,
    OpeningTooFast,
}

impl AddressRefusal {
    /// The HTTP body sent with the 429, distinct per cause.
    pub fn message(self) -> &'static str {
        match self {
            AddressRefusal::TooManyConcurrent => {
                "too many concurrent connections from this address"
            }
            AddressRefusal::OpeningTooFast => "opening connections too fast from this address",
        }
    }
}

struct AddressEntry {
    active: usize,
    tokens: f64,
    last_refill: Instant,
}

/// Per-address concurrent-connection counts and new-connection buckets.
pub struct AddressLimiter {
    entries: HashMap<AddressKey, AddressEntry>,
    max_concurrent: usize,
    capacity: f64,
    refill_per_sec: f64,
}

impl Default for AddressLimiter {
    fn default() -> Self {
        AddressLimiter::new(
            MAX_CONNECTIONS_PER_ADDRESS,
            NEW_CONNECTIONS_PER_ADDRESS_CAPACITY,
            NEW_CONNECTIONS_PER_ADDRESS_REFILL_PER_SEC,
        )
    }
}

impl AddressLimiter {
    pub fn new(max_concurrent: usize, capacity: f64, refill_per_sec: f64) -> Self {
        AddressLimiter {
            entries: HashMap::new(),
            max_concurrent,
            capacity,
            refill_per_sec,
        }
    }

    /// Admit one new connection from `key`, or say why not. On success the
    /// caller owns one concurrent slot and must hand it back with
    /// [`release`](Self::release) when the connection ends.
    pub fn try_acquire(&mut self, key: AddressKey, now: Instant) -> Result<(), AddressRefusal> {
        let capacity = self.capacity;
        let entry = self.entries.entry(key).or_insert_with(|| AddressEntry {
            active: 0,
            tokens: capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        entry.last_refill = now;
        if entry.active >= self.max_concurrent {
            return Err(AddressRefusal::TooManyConcurrent);
        }
        if entry.tokens < 1.0 {
            return Err(AddressRefusal::OpeningTooFast);
        }
        entry.tokens -= 1.0;
        entry.active += 1;
        Ok(())
    }

    pub fn release(&mut self, key: AddressKey) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.active = entry.active.saturating_sub(1);
        }
    }

    /// Drop entries with no live connections that have been idle for
    /// `older_than` — long enough that their bucket is full again, so
    /// forgetting them changes nothing observable. Called by
    /// `crate::pruning::sweep_once`; returns how many were removed.
    pub fn sweep_stale(&mut self, older_than: Duration, now: Instant) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            entry.active > 0 || now.duration_since(entry.last_refill) < older_than
        });
        before - self.entries.len()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn cidr_parsing_and_matching() {
        let net: IpNet = "10.42.0.0/16".parse().unwrap();
        assert!(net.contains(ip("10.42.7.9")));
        assert!(!net.contains(ip("10.43.0.1")));
        assert!(
            net.contains(ip("::ffff:10.42.0.1")),
            "IPv4-mapped peers match"
        );
        let host: IpNet = "192.0.2.1".parse().unwrap();
        assert!(host.contains(ip("192.0.2.1")));
        assert!(!host.contains(ip("192.0.2.2")));
        let v6: IpNet = "fd00::/8".parse().unwrap();
        assert!(v6.contains(ip("fd12::1")));
        assert!(!v6.contains(ip("fe80::1")));
        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("not-an-ip".parse::<IpNet>().is_err());
    }

    /// Guard: with no trusted proxies configured (the default), a client
    /// can't pick its own rate-limit key by sending `X-Forwarded-For`.
    #[test]
    fn forwarded_for_is_ignored_unless_the_peer_is_a_trusted_proxy() {
        let none = TrustedProxies::default();
        assert_eq!(
            none.client_ip(ip("203.0.113.5"), &xff("198.51.100.1")),
            ip("203.0.113.5")
        );

        let trusted = TrustedProxies::parse_list("10.42.0.0/16").unwrap();
        assert_eq!(
            trusted.client_ip(ip("203.0.113.5"), &xff("198.51.100.1")),
            ip("203.0.113.5"),
            "an untrusted peer's header is ignored even when proxies are configured"
        );
    }

    #[test]
    fn a_trusted_proxys_forwarded_for_names_the_real_client() {
        let trusted = TrustedProxies::parse_list("10.42.0.0/16, 10.43.0.0/16").unwrap();
        // Client-supplied junk on the left, the real client, then two
        // trusted hops the proxies appended.
        let headers = xff("1.1.1.1, 198.51.100.7, 10.43.0.2");
        assert_eq!(
            trusted.client_ip(ip("10.42.0.9"), &headers),
            ip("198.51.100.7"),
            "walk right to left past trusted hops; never trust the client-written left side"
        );
        assert_eq!(
            trusted.client_ip(ip("10.42.0.9"), &HeaderMap::new()),
            ip("10.42.0.9"),
            "no header: fall back to the peer"
        );
        assert_eq!(
            trusted.client_ip(ip("10.42.0.9"), &xff("garbage, 10.43.0.2")),
            ip("10.42.0.9"),
            "unparseable entry: don't guess"
        );
    }

    #[test]
    fn ipv6_addresses_are_grouped_by_their_64() {
        assert_eq!(
            AddressKey::of(ip("2001:db8:1:2::1")),
            AddressKey::of(ip("2001:db8:1:2:ffff::9"))
        );
        assert_ne!(
            AddressKey::of(ip("2001:db8:1:2::1")),
            AddressKey::of(ip("2001:db8:1:3::1"))
        );
        assert_eq!(
            AddressKey::of(ip("::ffff:192.0.2.1")),
            AddressKey::of(ip("192.0.2.1"))
        );
    }

    #[test]
    fn concurrent_slots_and_opening_rate_are_enforced_per_address() {
        let now = Instant::now();
        let a = AddressKey::of(ip("192.0.2.1"));
        let b = AddressKey::of(ip("192.0.2.2"));

        let mut concurrent = AddressLimiter::new(2, 100.0, 0.0);
        assert!(concurrent.try_acquire(a, now).is_ok());
        assert!(concurrent.try_acquire(a, now).is_ok());
        assert_eq!(
            concurrent.try_acquire(a, now),
            Err(AddressRefusal::TooManyConcurrent)
        );
        assert!(
            concurrent.try_acquire(b, now).is_ok(),
            "another address is unaffected"
        );
        concurrent.release(a);
        assert!(
            concurrent.try_acquire(a, now).is_ok(),
            "a released slot is reusable"
        );

        let mut rate = AddressLimiter::new(100, 3.0, 1.0);
        for _ in 0..3 {
            rate.try_acquire(a, now).unwrap();
            rate.release(a);
        }
        assert_eq!(
            rate.try_acquire(a, now),
            Err(AddressRefusal::OpeningTooFast)
        );
        assert!(
            rate.try_acquire(a, now + Duration::from_secs(1)).is_ok(),
            "the bucket refills"
        );
    }

    #[test]
    fn idle_entries_are_swept_but_live_ones_are_kept() {
        let now = Instant::now();
        let mut limiter = AddressLimiter::new(10, 10.0, 1.0);
        let idle = AddressKey::of(ip("192.0.2.1"));
        let live = AddressKey::of(ip("192.0.2.2"));
        limiter.try_acquire(idle, now).unwrap();
        limiter.release(idle);
        limiter.try_acquire(live, now).unwrap();

        let later = now + Duration::from_secs(600);
        assert_eq!(limiter.sweep_stale(Duration::from_secs(300), later), 1);
        assert_eq!(limiter.len(), 1, "the entry with a live connection stays");
    }
}
