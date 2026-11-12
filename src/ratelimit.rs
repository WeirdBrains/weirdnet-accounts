//! Per-client rate limits. State is in memory, bounded, and not shared across processes.
//!
//! The limiter is generic over the application's request classes (`C`), so each service
//! names its own (TAUR: rpc, auth, git, …; Salty Gull: api, upload, mcp, …).

use crate::{Error, Result};
pub use ipnet::IpNet;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Default number of distinct clients tracked per class.
pub const DEFAULT_MAX_KEYS: usize = 8192;

/// The limit for one class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassLimit<C> {
    /// The class.
    pub class: C,
    /// Requests allowed per window; 0 disables the class.
    pub max: u32,
    /// Window length (at least 1 second is used).
    pub window: Duration,
}

/// A full policy. The default policy limits nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatePolicy<C> {
    /// Limits per class; classes not listed are unlimited.
    pub classes: Vec<ClassLimit<C>>,
    /// Proxies whose `X-Forwarded-For` is honoured.
    pub trusted_proxies: Vec<IpNet>,
    /// Distinct clients tracked per class before new clients are refused.
    pub max_keys: usize,
}

impl<C> Default for RatePolicy<C> {
    fn default() -> Self {
        Self { classes: Vec::new(), trusted_proxies: Vec::new(), max_keys: DEFAULT_MAX_KEYS }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Ip(IpAddr),
    /// In-process call with no TCP peer. One shared bucket.
    Peerless,
}

struct Bucket {
    max: u32,
    window: Duration,
    hits: HashMap<Key, Vec<Instant>>,
}

/// Fixed-window counters keyed by client address.
pub struct Limiter<C> {
    buckets: HashMap<C, Bucket>,
    trusted: Vec<IpNet>,
    max_keys: usize,
}

impl<C: Copy + Eq + Hash> Default for Limiter<C> {
    fn default() -> Self {
        Self::from_policy(&RatePolicy::default())
    }
}

impl<C: Copy + Eq + Hash> Limiter<C> {
    /// A limiter for `policy`.
    pub fn from_policy(policy: &RatePolicy<C>) -> Self {
        let mut buckets = HashMap::new();
        for c in &policy.classes {
            buckets.insert(c.class, Bucket { max: c.max, window: c.window.max(Duration::from_secs(1)), hits: HashMap::new() });
        }
        Self { buckets, trusted: policy.trusted_proxies.clone(), max_keys: policy.max_keys.max(1) }
    }

    /// Client address for `peer`, honouring `X-Forwarded-For` only from trusted proxies.
    pub fn client(&self, peer: Option<IpAddr>, forwarded: Option<&str>) -> Option<IpAddr> {
        peer.map(|ip| client_ip(ip, forwarded, &self.trusted))
    }

    /// Counts one request, or refuses it with [`Error::RateLimited`].
    pub fn enforce(&mut self, class: C, peer: Option<IpAddr>, forwarded: Option<&str>, now: Instant) -> Result<()> {
        let Some(bucket) = self.buckets.get_mut(&class) else {
            return Ok(());
        };
        if bucket.max == 0 {
            return Ok(());
        }
        let key = match peer {
            None => Key::Peerless,
            Some(ip) => Key::Ip(client_ip(ip, forwarded, &self.trusted)),
        };
        let window = bucket.window;
        let max = bucket.max;
        let cap = self.max_keys;
        if let Some(hits) = bucket.hits.get_mut(&key) {
            hits.retain(|t| now.saturating_duration_since(*t) < window);
            if hits.len() as u32 >= max {
                return Err(Error::RateLimited { retry_after: retry_after(hits, now, window) });
            }
            hits.push(now);
            return Ok(());
        }
        bucket.hits.retain(|_, hits| hits.iter().any(|t| now.saturating_duration_since(*t) < window));
        if bucket.hits.len() >= cap {
            return Err(Error::RateLimited { retry_after: window.as_secs().max(1) });
        }
        bucket.hits.insert(key, vec![now]);
        Ok(())
    }
}

fn retry_after(hits: &[Instant], now: Instant, window: Duration) -> u64 {
    let Some(oldest) = hits.iter().min() else {
        return 1;
    };
    let elapsed = now.saturating_duration_since(*oldest);
    window.saturating_sub(elapsed).as_secs().max(1)
}

/// Parses a comma-separated CIDR list of trusted proxies. `label` names the setting in errors
/// (e.g. `TAUR_TRUSTED_PROXIES/--trusted-proxies`). A prefix length of 0 is refused: it would
/// treat every peer as a proxy and honour a client-supplied `X-Forwarded-For`.
pub fn parse_trusted_proxies(raw: &str, label: &str) -> std::result::Result<Vec<IpNet>, String> {
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let net: IpNet = part.parse().map_err(|_| format!("{label}: \"{part}\" is not a CIDR"))?;
        if net.prefix_len() == 0 {
            return Err(format!("{label}: {part} matches every address, so a client could spoof X-Forwarded-For"));
        }
        out.push(net);
    }
    Ok(out)
}

/// Client address for a connection.
///
/// `X-Forwarded-For` is ignored unless `peer` is inside `trusted`. Walking the header from the
/// right, trusted hops are skipped and the first address outside `trusted` is the client, so a
/// spoofed value to the left of the proxy's own entry is never used. When every hop is trusted,
/// the left-most address is used so two clients are not collapsed into one bucket.
pub fn client_ip(peer: IpAddr, forwarded: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    if !trusted.iter().any(|n| n.contains(&peer)) {
        return peer;
    }
    let mut chain = Vec::new();
    if let Some(header) = forwarded {
        for part in header.split(',') {
            if let Ok(ip) = part.trim().parse::<IpAddr>() {
                chain.push(ip);
            }
        }
    }
    chain.push(peer);
    for ip in chain.iter().rev() {
        if !trusted.iter().any(|n| n.contains(ip)) {
            return *ip;
        }
    }
    chain[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum Class {
        Rpc,
        Auth,
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn policy(max: u32, window: Duration) -> RatePolicy<Class> {
        RatePolicy { classes: vec![ClassLimit { class: Class::Rpc, max, window }], trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()], max_keys: 2 }
    }

    #[test]
    fn burst_then_window_reset_and_distinct_clients() {
        let mut lim = Limiter::from_policy(&policy(2, Duration::from_secs(60)));
        let t = Instant::now();
        let a = Some(ip(1, 1, 1, 1));
        lim.enforce(Class::Rpc, a, Some("9.9.9.9"), t).unwrap();
        lim.enforce(Class::Rpc, a, Some("8.8.8.8"), t).unwrap();
        match lim.enforce(Class::Rpc, a, Some("1.2.3.4"), t).unwrap_err() {
            Error::RateLimited { retry_after } => assert!((1..=60).contains(&retry_after)),
            other => panic!("{other}"),
        }
        lim.enforce(Class::Rpc, Some(ip(2, 2, 2, 2)), Some("9.9.9.9"), t).unwrap();
        lim.enforce(Class::Rpc, a, None, t + Duration::from_secs(60)).unwrap();
    }

    #[test]
    fn trusted_proxy_uses_the_appended_client_and_ignores_a_spoof() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let proxy = ip(10, 1, 0, 1);
        assert_eq!(client_ip(proxy, Some("9.9.9.9, 203.0.113.5"), &trusted), ip(203, 0, 113, 5));
        assert_eq!(client_ip(ip(198, 51, 100, 8), Some("203.0.113.5"), &trusted), ip(198, 51, 100, 8));
        assert_eq!(client_ip(proxy, None, &trusted), proxy);
        assert_eq!(client_ip(proxy, Some("10.0.0.7"), &trusted), ip(10, 0, 0, 7));
        let lim = Limiter::from_policy(&policy(1, Duration::from_secs(1)));
        assert_eq!(lim.client(Some(proxy), Some("203.0.113.5")), Some(ip(203, 0, 113, 5)));
        assert_eq!(lim.client(None, Some("203.0.113.5")), None);
    }

    #[test]
    fn full_table_does_not_forget_active_keys() {
        let mut lim = Limiter::from_policy(&policy(10, Duration::from_secs(60)));
        let t = Instant::now();
        lim.enforce(Class::Rpc, Some(ip(1, 0, 0, 1)), None, t).unwrap();
        lim.enforce(Class::Rpc, Some(ip(1, 0, 0, 2)), None, t).unwrap();
        assert!(matches!(lim.enforce(Class::Rpc, Some(ip(1, 0, 0, 3)), None, t), Err(Error::RateLimited { .. })));
        lim.enforce(Class::Rpc, Some(ip(1, 0, 0, 1)), None, t).unwrap();
    }

    #[test]
    fn disabled_class_unknown_class_and_peerless_bucket() {
        let mut lim = Limiter::from_policy(&policy(0, Duration::from_secs(60)));
        let t = Instant::now();
        for _ in 0..5 {
            lim.enforce(Class::Rpc, Some(ip(1, 2, 3, 4)), None, t).unwrap();
        }
        lim.enforce(Class::Auth, Some(ip(1, 2, 3, 4)), None, t).unwrap();
        let mut lim = Limiter::from_policy(&policy(1, Duration::from_secs(60)));
        lim.enforce(Class::Rpc, None, None, t).unwrap();
        assert!(lim.enforce(Class::Rpc, None, Some("1.1.1.1"), t).is_err());
        let mut open: Limiter<Class> = Limiter::default();
        open.enforce(Class::Rpc, None, None, t).unwrap();
    }

    #[test]
    fn trusted_proxy_parsing() {
        let l = "X_PROXIES";
        assert_eq!(parse_trusted_proxies(" 10.0.0.0/8, ,::1/128", l).unwrap().len(), 2);
        assert_eq!(parse_trusted_proxies("nope", l).unwrap_err(), "X_PROXIES: \"nope\" is not a CIDR");
        assert!(parse_trusted_proxies("0.0.0.0/0", l).unwrap_err().contains("matches every address"));
    }
}
