//! Idempotent replays: the response to a mutating request by
//! `(method, path, Idempotency-Key)`, so a client that retries after a timeout
//! gets the answer to its first attempt instead of a second commit.

use std::collections::{HashMap, VecDeque};

use crate::http::{Request, Response, err};

const CAP: usize = 256;
pub const MAX_KEY: usize = 128;

#[derive(Default)]
pub struct IdemCache {
    order: VecDeque<String>,
    map: HashMap<String, Response>,
}

impl IdemCache {
    pub fn get(&self, k: &str) -> Option<Response> {
        self.map.get(k).cloned()
    }

    /// Bounded: the oldest entry goes first.
    pub fn put(&mut self, k: String, r: Response) {
        if self.map.insert(k.clone(), r).is_none() {
            self.order.push_back(k);
        }
        while self.order.len() > CAP {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

/// The cache key of a request, `None` without the header, an error response for
/// an unreasonable one.
pub fn key_of(req: &Request) -> Result<Option<String>, Response> {
    let Some(k) = req.headers.get("idempotency-key") else {
        return Ok(None);
    };
    let k = k.trim();
    if k.is_empty() || k.len() > MAX_KEY || k.chars().any(|c| c.is_control()) {
        return Err(err(
            400,
            "bad_request",
            format!("Idempotency-Key must be 1-{MAX_KEY} printable characters"),
        ));
    }
    Ok(Some(format!("{} {} {k}", req.method, req.path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_scoped_by_method_and_path_and_validated() {
        let a = Request::new("POST", "/v1/commit").header("Idempotency-Key", "k1");
        let b = Request::new("POST", "/v1/confirm").header("Idempotency-Key", "k1");
        assert_ne!(key_of(&a).unwrap(), key_of(&b).unwrap());
        assert_eq!(key_of(&Request::new("POST", "/v1/x")).unwrap(), None);
        let long = Request::new("POST", "/v1/x").header("Idempotency-Key", &"x".repeat(200));
        assert_eq!(key_of(&long).unwrap_err().status, 400);
        let empty = Request::new("POST", "/v1/x").header("Idempotency-Key", "  ");
        assert_eq!(key_of(&empty).unwrap_err().status, 400);
    }

    #[test]
    fn the_cache_is_bounded_oldest_first() {
        let mut c = IdemCache::default();
        let r = err(200, "x", "y");
        for i in 0..400 {
            c.put(format!("k{i}"), r.clone());
        }
        assert!(c.get("k0").is_none());
        assert!(c.get("k143").is_none());
        assert!(c.get("k399").is_some());
        // re-putting a key does not duplicate it in the order
        c.put("k399".into(), r);
        assert!(c.get("k399").is_some());
    }
}
