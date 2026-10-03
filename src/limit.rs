//! A per-peer token-bucket rate limiter, and the same bucket used to slow down
//! token guessing (failed authentications).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// `burst` requests at once, refilled at `per_sec`.
#[derive(Debug, Clone, Copy)]
pub struct RateConfig {
    pub burst: f64,
    pub per_sec: f64,
}

impl RateConfig {
    /// 60 requests in a burst, 20 per second sustained: far above a human or an
    /// orchestrator, far below a flood.
    pub const DEFAULT: RateConfig = RateConfig {
        burst: 60.0,
        per_sec: 20.0,
    };
    /// Failed authentications: 5 in a burst, one more every 12 s.
    pub const FAILURES: RateConfig = RateConfig {
        burst: 5.0,
        per_sec: 1.0 / 12.0,
    };
}

pub struct RateLimiter {
    cfg: RateConfig,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

const MAX_KEYS: usize = 4096;

impl RateLimiter {
    pub fn new(cfg: RateConfig) -> RateLimiter {
        RateLimiter {
            cfg,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn refilled(&self, b: &mut (f64, Instant), now: Instant) {
        let dt = now.duration_since(b.1).as_secs_f64();
        b.0 = (b.0 + dt * self.cfg.per_sec).min(self.cfg.burst);
        b.1 = now;
    }

    /// Takes one token for `key`. `Err(secs)` = how long until one is back.
    pub fn take(&self, key: &str) -> Result<(), u64> {
        self.take_at(key, Instant::now())
    }

    fn take_at(&self, key: &str, now: Instant) -> Result<(), u64> {
        let Ok(mut map) = self.buckets.lock() else {
            return Ok(()); // a poisoned lock must not lock everyone out
        };
        if map.len() >= MAX_KEYS && !map.contains_key(key) {
            // forget the buckets that are full again: they carry no information
            map.retain(|_, b| b.0 < self.cfg.burst - 0.001);
            if map.len() >= MAX_KEYS {
                map.clear();
            }
        }
        let b = map.entry(key.to_string()).or_insert((self.cfg.burst, now));
        self.refilled(b, now);
        if b.0 >= 1.0 {
            b.0 -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - b.0) / self.cfg.per_sec).ceil().max(1.0) as u64)
        }
    }

    /// Whether `key` could take a token now, without taking it.
    pub fn would_allow(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let Ok(mut map) = self.buckets.lock() else {
            return Ok(());
        };
        match map.get_mut(key) {
            None => Ok(()),
            Some(b) => {
                self.refilled(b, now);
                if b.0 >= 1.0 {
                    Ok(())
                } else {
                    Err(((1.0 - b.0) / self.cfg.per_sec).ceil().max(1.0) as u64)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_burst_is_allowed_then_refused_then_refilled() {
        let l = RateLimiter::new(RateConfig {
            burst: 3.0,
            per_sec: 1.0,
        });
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(l.take_at("a", t0).is_ok());
        }
        let wait = l.take_at("a", t0).unwrap_err();
        assert_eq!(wait, 1, "one second until the next token");
        // another peer is unaffected
        assert!(l.take_at("b", t0).is_ok());
        // two seconds later two tokens are back, not more than burst
        let t2 = t0 + Duration::from_secs(2);
        assert!(l.take_at("a", t2).is_ok());
        assert!(l.take_at("a", t2).is_ok());
        assert!(l.take_at("a", t2).is_err());
        let t100 = t0 + Duration::from_secs(100);
        for _ in 0..3 {
            assert!(l.take_at("a", t100).is_ok());
        }
        assert!(
            l.take_at("a", t100).is_err(),
            "the bucket never exceeds its burst"
        );
    }

    #[test]
    fn the_table_is_bounded() {
        let l = RateLimiter::new(RateConfig {
            burst: 2.0,
            per_sec: 0.0,
        });
        let t = Instant::now();
        for i in 0..(MAX_KEYS + 50) {
            let _ = l.take_at(&format!("ip{i}"), t);
        }
        assert!(l.buckets.lock().unwrap().len() <= MAX_KEYS);
    }

    #[test]
    fn failures_config_blocks_after_five() {
        let l = RateLimiter::new(RateConfig::FAILURES);
        for _ in 0..5 {
            assert!(l.take("1.2.3.4").is_ok());
        }
        let wait = l.take("1.2.3.4").unwrap_err();
        assert!((10..=13).contains(&wait), "{wait}");
        assert!(l.would_allow("1.2.3.4").is_err());
        assert!(l.would_allow("9.9.9.9").is_ok());
    }
}
