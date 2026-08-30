use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Minimum backoff duration for a PDS host after 429 (60 seconds).
pub const MIN_RETRY_AFTER_SECS: u64 = 60;

/// Maximum allowed backoff duration for a PDS host (1 hour / 3600 seconds) to prevent worker paralysis.
pub const MAX_RETRY_AFTER_SECS: u64 = 3600;

/// Default backoff duration when Retry-After is absent or unparseable.
pub const DEFAULT_RETRY_AFTER_SECS: u64 = 60;

/// Parse and clamp a Retry-After header or string payload to [MIN_RETRY_AFTER_SECS, MAX_RETRY_AFTER_SECS].
/// Never panics on overflow or negative values.
pub fn parse_and_clamp_retry_after(raw: Option<&str>) -> u64 {
    let Some(raw_str) = raw else {
        return DEFAULT_RETRY_AFTER_SECS;
    };
    let trimmed = raw_str.trim();
    if trimmed.is_empty() {
        return DEFAULT_RETRY_AFTER_SECS;
    }
    if let Ok(secs) = trimmed.parse::<u64>() {
        return secs.clamp(MIN_RETRY_AFTER_SECS, MAX_RETRY_AFTER_SECS);
    }
    if let Ok(signed) = trimmed.parse::<i64>() {
        if signed <= 0 {
            return MIN_RETRY_AFTER_SECS;
        }
        return (signed as u64).clamp(MIN_RETRY_AFTER_SECS, MAX_RETRY_AFTER_SECS);
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return MAX_RETRY_AFTER_SECS;
    }
    DEFAULT_RETRY_AFTER_SECS
}

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
        let max_duration = Duration::from_secs(MAX_RETRY_AFTER_SECS);
        let safe_duration = duration.min(max_duration);
        self.tokens = 0.0;
        let now = Instant::now();
        self.last_refill = now
            .checked_add(safe_duration)
            .unwrap_or_else(|| now + max_duration);
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
        let max_duration = Duration::from_secs(MAX_RETRY_AFTER_SECS);
        let safe_duration = duration.min(max_duration);
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry(pds_host.to_string())
            .or_insert_with(|| TokenBucket::new(50.0, 10.0));
        bucket.backoff(safe_duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_clamp_retry_after_boundaries() {
        assert_eq!(parse_and_clamp_retry_after(None), 60);
        assert_eq!(parse_and_clamp_retry_after(Some("")), 60);
        assert_eq!(parse_and_clamp_retry_after(Some("invalid")), 60);
        assert_eq!(parse_and_clamp_retry_after(Some("-5")), 60);
        assert_eq!(parse_and_clamp_retry_after(Some("0")), 60);
        // Boundary below 60
        assert_eq!(parse_and_clamp_retry_after(Some("59")), 60);
        // Exactly at min limit
        assert_eq!(parse_and_clamp_retry_after(Some("60")), 60);
        // Middle valid values
        assert_eq!(parse_and_clamp_retry_after(Some("120")), 120);
        assert_eq!(parse_and_clamp_retry_after(Some("3599")), 3599);
        // Exactly at max limit
        assert_eq!(parse_and_clamp_retry_after(Some("3600")), 3600);
        // Boundary above 3600
        assert_eq!(parse_and_clamp_retry_after(Some("3601")), 3600);
        // Extreme values near i64::MAX and u64::MAX
        assert_eq!(
            parse_and_clamp_retry_after(Some(&i64::MAX.to_string())),
            3600
        );
        assert_eq!(
            parse_and_clamp_retry_after(Some(&u64::MAX.to_string())),
            3600
        );
        assert_eq!(
            parse_and_clamp_retry_after(Some("999999999999999999999999999999")),
            3600
        );
    }

    #[test]
    fn test_backoff_never_panics_on_extreme_duration() {
        let mut bucket = TokenBucket::new(10.0, 1.0);
        // Must not panic on Duration::MAX
        bucket.backoff(Duration::MAX);
        assert_eq!(bucket.tokens, 0.0);
        assert!(!bucket.try_consume());

        let pds_budget = PdsRateBudget::new(20.0);
        pds_budget.backoff_host("test.pds", Duration::MAX);
        assert!(!pds_budget.try_acquire("test.pds"));
    }
}
