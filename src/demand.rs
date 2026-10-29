//! Statistics a pool decides by: how long its clients hold a server connection, how long a new
//! one takes to open, and how many it needed at once lately.

use std::time::Duration;

const BUCKETS: usize = 48;
/// Upper bound of the first bucket; each next one is √2 times wider, up to ~5 minutes.
const BASE: f64 = 25e-6;
/// Below this weight a pool's own holds say too little and the process-wide ones are used.
pub const MIN_WEIGHT: f64 = 20.0;
/// Fraction of the recorded weight kept per second, a half-life of ~23 s.
pub const DECAY_PER_SECOND: f64 = 0.97;

fn bound(i: usize) -> f64 {
    BASE * 2f64.powf(i as f64 / 2.0)
}

fn bucket(seconds: f64) -> usize {
    if seconds <= BASE {
        return 0;
    }
    ((2.0 * (seconds / BASE).log2()).ceil() as usize).min(BUCKETS - 1)
}

/// A decaying histogram of how long leases lasted.
#[derive(Debug, Clone)]
pub struct Holds {
    counts: [f64; BUCKETS],
    sum: f64,
    weight: f64,
}

impl Default for Holds {
    fn default() -> Self {
        Self {
            counts: [0.0; BUCKETS],
            sum: 0.0,
            weight: 0.0,
        }
    }
}

impl Holds {
    pub fn record(&mut self, hold: Duration) {
        let seconds = hold.as_secs_f64();
        self.counts[bucket(seconds)] += 1.0;
        self.sum += seconds;
        self.weight += 1.0;
    }

    pub fn decay(&mut self, factor: f64) {
        self.counts.iter_mut().for_each(|count| *count *= factor);
        self.sum *= factor;
        self.weight *= factor;
    }

    pub fn weight(&self) -> f64 {
        self.weight
    }

    /// Mean hold in seconds.
    pub fn mean(&self) -> f64 {
        if self.weight > 0.0 {
            self.sum / self.weight
        } else {
            0.0
        }
    }

    /// Share of holds not longer than `seconds`, interpolated within a bucket.
    fn cdf(&self, seconds: f64) -> f64 {
        if self.weight <= 0.0 {
            return 0.0;
        }
        let i = bucket(seconds);
        let below: f64 = self.counts[..i].iter().sum();
        let low = if i == 0 { 0.0 } else { bound(i - 1) };
        let within = ((seconds - low) / (bound(i) - low)).clamp(0.0, 1.0);
        ((below + self.counts[i] * within) / self.weight).min(1.0)
    }

    /// Probability that a lease that has lasted `elapsed` ends within the next `within`. A lease
    /// already longer than every recorded hold is not expected to end.
    pub fn ends_within(&self, elapsed: Duration, within: Duration) -> f64 {
        let elapsed = elapsed.as_secs_f64();
        let running = 1.0 - self.cdf(elapsed);
        if running <= 1e-9 {
            return 0.0;
        }
        ((self.cdf(elapsed + within.as_secs_f64()) - self.cdf(elapsed)) / running).clamp(0.0, 1.0)
    }
}

/// Moving average of how long a new server connection takes to open.
#[derive(Debug, Clone, Default)]
pub struct ConnectTime {
    seconds: Option<f64>,
}

impl ConnectTime {
    /// Assumed until the first connection opened.
    const INITIAL: Duration = Duration::from_millis(50);
    /// A floor, so a near-instant open still leaves waiters a moment to be served.
    const MIN: Duration = Duration::from_millis(1);

    pub fn record(&mut self, took: Duration) {
        let took = took.as_secs_f64();
        self.seconds = Some(match self.seconds {
            Some(average) => average + 0.2 * (took - average),
            None => took,
        });
    }

    pub fn estimate(&self) -> Duration {
        self.seconds
            .map_or(Self::INITIAL, Duration::from_secs_f64)
            .max(Self::MIN)
    }
}

/// The most connections a pool had leased at once in each of the last few windows.
#[derive(Debug, Clone, Default)]
pub struct Peaks {
    windows: [(u64, usize); Peaks::WINDOWS],
}

impl Peaks {
    const WINDOWS: usize = 6;
    pub const WINDOW: Duration = Duration::from_secs(5);

    /// `window` numbers [`Peaks::WINDOW`]-long periods since any fixed instant.
    pub fn record(&mut self, window: u64, leased: usize) {
        let slot = &mut self.windows[(window % Self::WINDOWS as u64) as usize];
        if slot.0 != window {
            *slot = (window, 0);
        }
        slot.1 = slot.1.max(leased);
    }

    /// The peak over the current and the previous windows, ~30 s.
    pub fn recent(&self, window: u64) -> usize {
        self.windows
            .iter()
            .filter(|(id, _)| *id + Self::WINDOWS as u64 > window && *id <= window)
            .map(|(_, peak)| *peak)
            .max()
            .unwrap_or(0)
    }
}

/// How many new connections to open for `waiting` clients now.
///
/// A connection that frees up serves one waiter after another, so with short holds a few
/// connections serve many waiters before a new one would even be ready. Waiters should get a
/// connection within `patience` (see [`patience`]); `ending` is the expected number of leases
/// to end within it and `opening` the connections already being opened, assumed half-way.
pub fn opens_needed(
    waiting: usize,
    opening: usize,
    ending: f64,
    hold: Duration,
    connect: Duration,
    patience: Duration,
) -> usize {
    if waiting <= opening {
        return 0;
    }
    let hold = hold.as_secs_f64().max(1e-6);
    let connect = connect.as_secs_f64();
    let patience = patience.as_secs_f64();
    // A lease ends half-way through the patience on average and serves for the rest of it.
    let per_ending = 1.0 + patience / (2.0 * hold);
    let per_opening = 1.0 + (patience - connect / 2.0).max(0.0) / hold;
    // A new connection is ready after a connect time and then serves for the patience.
    let per_new = 1.0 + patience / hold;
    let served = ending * per_ending + opening as f64 * per_opening;
    let needed = ((waiting as f64 - served) / per_new).ceil().max(0.0) as usize;
    // Nothing expected to free up soon: open one rather than wait for a lease that may not end.
    let needed = if needed == 0 && opening == 0 && ending < 0.5 {
        1
    } else {
        needed
    };
    needed.min(waiting - opening - (ending.floor() as usize).min(waiting - opening - 1))
}

/// How long a waiter should wait for a released connection, at most, before one is opened:
/// half a connect time kept the waits shortest for the fewest new connections in simulation.
pub fn patience(connect: Duration) -> Duration {
    connect / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(millis: f64) -> Duration {
        Duration::from_secs_f64(millis / 1000.0)
    }

    fn holds(millis: &[f64]) -> Holds {
        let mut holds = Holds::default();
        for &m in millis {
            holds.record(ms(m));
        }
        holds
    }

    #[test]
    fn short_holds_end_soon_and_outliers_do_not() {
        let holds = holds(&[1.0; 100]);
        assert!(holds.ends_within(ms(0.0), ms(50.0)) > 0.99);
        assert_eq!(holds.ends_within(ms(500.0), ms(50.0)), 0.0);
    }

    #[test]
    fn a_long_running_lease_is_less_likely_to_end_soon() {
        let mut millis = vec![1.0; 90];
        millis.extend([1000.0; 10]);
        let holds = holds(&millis);
        let fresh = holds.ends_within(ms(0.0), ms(50.0));
        let running = holds.ends_within(ms(100.0), ms(50.0));
        assert!((0.85..0.95).contains(&fresh), "{fresh}");
        assert!(running < 0.1, "{running}");
    }

    #[test]
    fn decay_keeps_the_shape_and_shrinks_the_weight() {
        let mut holds = holds(&[2.0; 50]);
        let mean = holds.mean();
        holds.decay(0.5);
        assert!((holds.mean() - mean).abs() < 1e-12);
        assert_eq!(holds.weight(), 25.0);
    }

    fn opens(waiting: usize, opening: usize, ending: f64, hold: f64) -> usize {
        let connect = ms(50.0);
        opens_needed(
            waiting,
            opening,
            ending,
            ms(hold),
            connect,
            patience(connect),
        )
    }

    #[test]
    fn a_burst_of_short_queries_waits_for_one_free_connection() {
        // 2 ms queries, 50 ms to connect, one lease about to end: it serves ~7 within 25 ms.
        assert_eq!(opens(5, 0, 1.0, 2.0), 0);
        // Nothing leased: a new connection serves ~13 waiters within 25 ms of opening.
        assert_eq!(opens(20, 0, 0.0, 2.0), 2);
        assert_eq!(opens(40, 0, 0.0, 2.0), 3);
        assert_eq!(opens(2, 2, 0.0, 2.0), 0);
    }

    #[test]
    fn long_holds_open_a_connection_per_waiter() {
        assert_eq!(opens(5, 0, 0.2, 500.0), 5);
        assert_eq!(opens(5, 2, 0.2, 500.0), 3);
    }

    #[test]
    fn leases_expected_to_end_cover_their_share_of_waiters() {
        // 20 ms queries: a freed connection serves ~1.6 waiters within the patience.
        assert_eq!(opens(4, 0, 3.0, 20.0), 0);
        assert_eq!(opens(10, 0, 1.0, 20.0), 4);
        // Never more than the waiters a release will not reach.
        assert_eq!(opens(3, 0, 2.0, 1000.0), 1);
    }

    #[test]
    fn peaks_cover_the_last_six_windows() {
        let mut peaks = Peaks::default();
        peaks.record(10, 7);
        peaks.record(12, 3);
        assert_eq!(peaks.recent(12), 7);
        assert_eq!(peaks.recent(15), 7);
        assert_eq!(peaks.recent(16), 3);
        assert_eq!(peaks.recent(18), 0);
    }
}
