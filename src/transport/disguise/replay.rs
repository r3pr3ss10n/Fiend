use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct ReplayGuard {
    inner: Mutex<ReplayInner>,
}

struct ReplayInner {
    seen: HashMap<Vec<u8>, Instant>,
    ttl: Duration,
    last_gc: Instant,
}

impl ReplayGuard {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(ReplayInner {
                seen: HashMap::new(),
                ttl,
                last_gc: Instant::now(),
            }),
        }
    }

    pub fn check(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let ttl = inner.ttl;
        if now.duration_since(inner.last_gc) > ttl {
            inner.seen.retain(|_, t| now.duration_since(*t) <= ttl);
            inner.last_gc = now;
        }

        let key = data.to_vec();
        if inner.seen.contains_key(&key) {
            return false;
        }

        inner.seen.insert(key, now);
        true
    }
}
