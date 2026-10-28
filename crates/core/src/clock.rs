//! Display both clocks from the same system-clock sample; receipt times remain UTC.
use chrono::{DateTime, FixedOffset, Local, Utc};

pub fn labels(now_ms: u64) -> (String, String) {
    let utc = i64::try_from(now_ms)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis);
    match utc {
        Some(utc) => format_labels(utc, utc.with_timezone(&Local).fixed_offset()),
        None => ("UTC unavailable".into(), "LOCAL unavailable".into()),
    }
}

fn format_labels(utc: DateTime<Utc>, local: DateTime<FixedOffset>) -> (String, String) {
    (
        utc.format("%H:%M:%S UTC").to_string(),
        local.format("%H:%M:%S LOCAL %:z").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_offsets_preserve_the_same_instant_across_midnight() {
        let utc = DateTime::parse_from_rfc3339("2026-10-28T23:45:12Z")
            .unwrap()
            .to_utc();
        for (seconds, expected) in [
            (3600, "00:45:12 LOCAL +01:00"),
            (7200, "01:45:12 LOCAL +02:00"),
            (19800, "05:15:12 LOCAL +05:30"),
            (-12600, "20:15:12 LOCAL -03:30"),
            (0, "23:45:12 LOCAL +00:00"),
        ] {
            let local = utc.with_timezone(&FixedOffset::east_opt(seconds).unwrap());
            assert_eq!(local.timestamp_millis(), utc.timestamp_millis());
            let (u, l) = format_labels(utc, local);
            assert_eq!(u, "23:45:12 UTC");
            assert_eq!(l, expected);
        }
    }
    #[test]
    fn unsupported_timestamp_has_explicit_fallback() {
        assert_eq!(
            labels(u64::MAX),
            ("UTC unavailable".into(), "LOCAL unavailable".into())
        );
    }
    #[test]
    fn system_timezone_is_used() {
        let now = Utc::now();
        let expected = now
            .with_timezone(&Local)
            .format("%H:%M:%S LOCAL %:z")
            .to_string();
        assert_eq!(labels(now.timestamp_millis() as u64).1, expected);
    }
}
