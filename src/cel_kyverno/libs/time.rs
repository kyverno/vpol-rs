use cel::common::types::{CelDuration, CelString, CelTimestamp};
use cel::{DeclarationError, Env, ExecutionError, Library};
use chrono::{Datelike as _, Local, TimeDelta, Timelike as _};
use kube_cel::cel;

/// Seconds from Go's zero time (0001-01-01T00:00:00Z) to the Unix epoch.
/// `time.truncate` rounds relative to Go's zero time, as `time.Time.Truncate` does.
const GO_ZERO_TO_UNIX_SECS: i128 = 62_135_596_800;

const NANOS_PER_SEC: i128 = 1_000_000_000;

/// Kyverno's `time` CEL library: `time.now()`, `time.truncate(timestamp, duration)`
/// and `time.toCron(timestamp)`.
pub struct TimeLib;

impl TimeLib {
    pub fn new() -> Self {
        TimeLib
    }
}

impl Library for TimeLib {
    fn name(&self) -> Option<&str> {
        Some("kyverno.time")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        cel::add_overload!(env, fn now: () -> CelTimestamp,
            name = "time.now", id = "time_now")?;
        cel::add_overload!(env, fn truncate: (CelTimestamp, CelDuration) -> Result<CelTimestamp>,
            name = "time.truncate", id = "time_truncate")?;
        cel::add_overload!(env, fn to_cron: (CelTimestamp) -> CelString,
            name = "time.toCron", id = "time_to_cron")?;
        Ok(())
    }
}

/// The current time, in the host's local offset, as Go's `time.Now()`.
fn now() -> CelTimestamp {
    CelTimestamp::from(Local::now().fixed_offset())
}

/// Rounds `ts` down to a multiple of `dur` since Go's zero time, keeping its
/// offset. A duration that isn't positive returns `ts` unchanged, as in Go.
fn truncate(ts: &CelTimestamp, dur: &CelDuration) -> Result<CelTimestamp, ExecutionError> {
    let ts = *ts.inner();
    if *dur.inner() <= TimeDelta::zero() {
        return Ok(CelTimestamp::from(ts));
    }
    let step = dur
        .inner()
        .num_nanoseconds()
        .ok_or_else(|| ExecutionError::function_error("time.truncate", "duration out of range"))?;

    let since_zero = (i128::from(ts.timestamp()) + GO_ZERO_TO_UNIX_SECS) * NANOS_PER_SEC
        + i128::from(ts.timestamp_subsec_nanos());
    // The remainder is below `step`, an `i64`, so it fits back into one.
    let excess = i64::try_from(since_zero.rem_euclid(i128::from(step)))
        .expect("remainder is smaller than an i64 step");

    ts.checked_sub_signed(TimeDelta::nanoseconds(excess))
        .map(CelTimestamp::from)
        .ok_or_else(|| ExecutionError::function_error("time.truncate", "timestamp out of range"))
}

/// A cron expression, `minute hour day-of-month month day-of-week`, firing at
/// `ts`, read in its own offset. Sunday is day 0.
fn to_cron(ts: &CelTimestamp) -> CelString<'static> {
    let ts = ts.inner();
    format!(
        "{} {} {} {} {}",
        ts.minute(),
        ts.hour(),
        ts.day(),
        ts.month(),
        ts.weekday().num_days_from_sunday()
    )
    .into()
}

#[cfg(test)]
mod tests {
    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    #[test]
    fn to_cron() {
        // 2024-03-05 is a Tuesday.
        assert_eq!(
            eval("time.toCron(timestamp('2024-03-05T14:30:00Z'))"),
            Ok(Value::String("30 14 5 3 2".to_owned().into()))
        );
    }

    #[test]
    fn truncates_from_go_zero_time() {
        for expr in [
            "time.truncate(timestamp('2024-03-05T14:30:45Z'), duration('1h')) == timestamp('2024-03-05T14:00:00Z')",
            // Go's zero time is a Monday, so weeks start on Mondays (2024-03-04).
            "time.truncate(timestamp('2024-03-05T14:30:45Z'), duration('168h')) == timestamp('2024-03-04T00:00:00Z')",
            "time.truncate(timestamp('2024-03-05T14:30:45Z'), duration('0s')) == timestamp('2024-03-05T14:30:45Z')",
        ] {
            assert_eq!(eval(expr), Ok(Value::Bool(true)), "{expr}");
        }
    }
}
