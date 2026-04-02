use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct PdsRateBudget {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    global_bucket: Mutex<TokenBucket>,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn backoff(&mut self, duration: Duration) {
        self.tokens = 0.0;
        self.last_refill = Instant::now() + duration;
    }
}

impl PdsRateBudget {
    pub fn new(global_rate: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            global_bucket: Mutex::new(TokenBucket::new(30.0, global_rate)),
        }
    }

    /// Attempt to acquire a token for the given PDS host.
    ///
    /// Returns `true` if both the global budget and the per-host bucket have
    /// capacity; `false` if either is exhausted.  When the global bucket has
    /// capacity but the per-host bucket is empty, the consumed global token is
    /// returned so it is not wasted.
    pub fn try_acquire(&self, pds_host: &str) -> bool {
        {
            let mut global = self.global_bucket.lock().unwrap();
            if !global.try_consume() {
                return false;
            }
        }
        {
            let mut buckets = self.buckets.lock().unwrap();
            let bucket = buckets
                .entry(pds_host.to_string())
                .or_insert_with(|| TokenBucket::new(50.0, 10.0));
            if !bucket.try_consume() {
                // Return the global token we already consumed.
                let mut global = self.global_bucket.lock().unwrap();
                global.tokens = (global.tokens + 1.0).min(global.max_tokens);
                return false;
            }
        }
        true
    }

    /// Apply a back-off to the per-host bucket (e.g. after a 429 response).
    /// The bucket tokens are zeroed and the refill clock is shifted forward by
    /// `duration`, effectively preventing any requests to that host until the
    /// duration has elapsed.
    pub fn backoff_host(&self, pds_host: &str, duration: Duration) {
        let mut buckets = self.buckets.lock().unwrap();
        if let Some(bucket) = buckets.get_mut(pds_host) {
            bucket.backoff(duration);
        }
    }
}
