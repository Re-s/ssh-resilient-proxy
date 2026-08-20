//! 重连退避策略。
//!
//! 断网自愈的第一要素是"以正确的节奏重试"。太激进会在服务器故障时
//! 形成自我 DDoS，太保守则恢复缓慢。这里用带抖动的截断指数退避：
//!
//! * 首次失败立刻快速重试（网络抖动通常是瞬时的）；
//! * 持续失败则指数增长到上限；
//! * 每次延迟加入随机抖动，避免多个客户端同步重连造成惊群。

use std::time::Duration;

use rand::Rng;

#[derive(Debug, Clone)]
pub struct BackoffPolicy {
    /// 第一次重试前的等待时间。
    pub initial: Duration,
    /// 退避上限。
    pub max: Duration,
    /// 每次失败后的乘数。
    pub multiplier: f64,
    /// 抖动比例（0.0..=1.0）。实际延迟在 `[d*(1-j), d*(1+j)]` 内均匀取值。
    pub jitter: f64,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(250),
            max: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: 0.2,
        }
    }
}

#[derive(Debug)]
pub struct Backoff {
    policy: BackoffPolicy,
    /// 连续失败次数。
    attempts: u32,
}

impl Backoff {
    pub fn new(policy: BackoffPolicy) -> Self {
        Self {
            policy,
            attempts: 0,
        }
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// 连接成功，清空退避状态。
    pub fn reset(&mut self) {
        self.attempts = 0;
    }

    /// 计算下一次重试前应等待的时长，并推进内部计数。
    pub fn next_delay(&mut self) -> Duration {
        let base =
            self.policy.initial.as_secs_f64() * self.policy.multiplier.powi(self.attempts as i32);
        let capped = base.min(self.policy.max.as_secs_f64());
        self.attempts = self.attempts.saturating_add(1);

        if self.policy.jitter <= 0.0 {
            return Duration::from_secs_f64(capped);
        }
        let j = self.policy.jitter.clamp(0.0, 1.0);
        let low = capped * (1.0 - j);
        let high = capped * (1.0 + j);
        // 抖动后仍不允许超过 max 的 1.5 倍，防止配置极端值导致长时间停滞。
        let hard_cap = self.policy.max.as_secs_f64() * 1.5;
        let picked = rand::rng().random_range(low..=high).min(hard_cap);
        Duration::from_secs_f64(picked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_jitter() -> BackoffPolicy {
        BackoffPolicy {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: 0.0,
        }
    }

    #[test]
    fn grows_exponentially_then_saturates() {
        let mut b = Backoff::new(no_jitter());
        assert_eq!(b.next_delay(), Duration::from_millis(100));
        assert_eq!(b.next_delay(), Duration::from_millis(200));
        assert_eq!(b.next_delay(), Duration::from_millis(400));
        assert_eq!(b.next_delay(), Duration::from_millis(800));
        for _ in 0..20 {
            b.next_delay();
        }
        assert_eq!(b.next_delay(), Duration::from_secs(10), "must clamp at max");
    }

    #[test]
    fn reset_returns_to_initial() {
        let mut b = Backoff::new(no_jitter());
        b.next_delay();
        b.next_delay();
        assert_eq!(b.attempts(), 2);
        b.reset();
        assert_eq!(b.attempts(), 0);
        assert_eq!(b.next_delay(), Duration::from_millis(100));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let policy = BackoffPolicy {
            initial: Duration::from_millis(1000),
            max: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: 0.25,
        };
        for _ in 0..200 {
            let mut b = Backoff::new(policy.clone());
            let d = b.next_delay().as_secs_f64();
            assert!(
                (0.75..=1.25).contains(&d),
                "delay {d} outside jitter window"
            );
        }
    }

    /// 大量重试后不能因为 powi 溢出成 inf 而产生非法 Duration。
    #[test]
    fn survives_many_attempts_without_overflow() {
        let mut b = Backoff::new(BackoffPolicy::default());
        for _ in 0..500 {
            let d = b.next_delay();
            assert!(d.as_secs_f64().is_finite());
            assert!(d <= Duration::from_secs(45), "hard cap violated: {d:?}");
        }
    }
}
