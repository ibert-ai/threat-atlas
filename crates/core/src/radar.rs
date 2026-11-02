//! Cloudflare Radar layer 3 top-attack aggregates for the standalone SOC view.
//! Values are the provider's shares of all layer 3 attacks. Rows are origin -> target locations
//! exactly as supplied: nothing here invents targets, routes, individual events or summed totals.
use serde::Deserialize;

pub const MAX_BYTES: usize = 2_000_000;
pub const MAX_ROWS: usize = 100;
/// Two request intervals of the 15-minute floor; older snapshots are labelled stale.
pub const STALE_AFTER_MS: u64 = 30 * 60 * 1000;

#[derive(Deserialize)]
struct Envelope {
    success: bool,
    result: Option<Body>,
}
#[derive(Deserialize)]
struct Body {
    meta: Meta,
    top_0: Vec<Row>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    last_updated: String,
    normalization: String,
    date_range: Vec<Window>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Window {
    pub start_time: String,
    pub end_time: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub origin_country_alpha2: String,
    pub origin_country_name: String,
    pub value: String,
    // Documented schema lists only origin fields; targets are shown only when the provider sends them.
    #[serde(default)]
    pub target_country_alpha2: Option<String>,
    #[serde(default)]
    pub target_country_name: Option<String>,
}
#[derive(Debug, Clone)]
pub struct Aggregate {
    pub rows: Vec<Row>,
    pub values: Vec<f64>,
    pub normalization: String,
    pub last_updated: String,
    pub windows: Vec<Window>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Invalid;

/// Same acceptance rules as the Swift beta parser: bounded size and rows, a date window,
/// and finite non-negative values. Anything else is rejected without partial data.
pub fn parse(data: &[u8]) -> Result<Aggregate, Invalid> {
    if data.len() > MAX_BYTES {
        return Err(Invalid);
    }
    let envelope: Envelope = serde_json::from_slice(data).map_err(|_| Invalid)?;
    let body = match (envelope.success, envelope.result) {
        (true, Some(body)) => body,
        _ => return Err(Invalid),
    };
    if body.top_0.len() > MAX_ROWS || body.meta.date_range.is_empty() {
        return Err(Invalid);
    }
    let values = body
        .top_0
        .iter()
        .map(|row| {
            row.value
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|v| v.is_finite() && *v >= 0.)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(Invalid)?;
    Ok(Aggregate {
        rows: body.top_0,
        values,
        normalization: body.meta.normalization,
        last_updated: body.meta.last_updated,
        windows: body.meta.date_range,
    })
}

/// One entry per origin location in provider order: its largest single row (never a sum)
/// and how many ranked rows share that origin.
#[derive(Debug, PartialEq)]
pub struct Origin {
    pub code: String,
    pub largest: f64,
    pub rows: usize,
}
impl Aggregate {
    pub fn largest(&self) -> f64 {
        self.values.iter().copied().fold(0., f64::max)
    }
    pub fn origins(&self) -> Vec<Origin> {
        let mut origins: Vec<Origin> = Vec::new();
        for (row, &value) in self.rows.iter().zip(&self.values) {
            let code = row.origin_country_alpha2.trim().to_uppercase();
            match origins.iter_mut().find(|o| o.code == code) {
                Some(origin) => {
                    origin.largest = origin.largest.max(value);
                    origin.rows += 1;
                }
                None => origins.push(Origin {
                    code,
                    largest: value,
                    rows: 1,
                }),
            }
        }
        origins
    }
    /// Provider value string unchanged; only PERCENTAGE gets a unit suffix.
    pub fn value_label(&self, index: usize) -> String {
        let raw = self.rows[index].value.trim();
        if self.normalization.eq_ignore_ascii_case("PERCENTAGE") {
            format!("{raw}%")
        } else {
            format!("{raw} ({})", self.normalization)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    NoData,
    Empty,
    Current,
    Stale,
}
pub fn freshness(data: Option<&Aggregate>, received_ms: u64, now_ms: u64) -> Freshness {
    match data {
        None => Freshness::NoData,
        Some(data) if data.rows.is_empty() => Freshness::Empty,
        Some(_) if now_ms.saturating_sub(received_ms) > STALE_AFTER_MS => Freshness::Stale,
        Some(_) => Freshness::Current,
    }
}

/// Approximate positions for places too small for the bundled 1:110m country polygons.
/// Reference geometry for a marker only, not telemetry.
pub fn small_place(code: &str) -> Option<(f64, f64)> {
    Some(match code {
        "HK" => (114.2, 22.3),
        "SG" => (103.8, 1.35),
        "MO" => (113.5, 22.2),
        "BH" => (50.6, 26.0),
        "MT" => (14.4, 35.9),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic fixtures only: never presented as telemetry.
    fn fixture(rows: &str) -> String {
        format!(
            r#"{{"success":true,"result":{{"meta":{{"lastUpdated":"2026-01-01T00:00:00Z","normalization":"PERCENTAGE","dateRange":[{{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}}]}},"top_0":[{rows}]}}}}"#
        )
    }
    const BR_US: &str = r#"{"originCountryAlpha2":"BR","originCountryName":"Brazil","targetCountryAlpha2":"US","targetCountryName":"United States","value":"7.5"}"#;
    const BR_NO_TARGET: &str =
        r#"{"originCountryAlpha2":"br","originCountryName":"Brazil","value":"4.4"}"#;
    const HK: &str =
        r#"{"originCountryAlpha2":"HK","originCountryName":"Hong Kong","value":"2.1"}"#;

    #[test]
    fn parses_rows_with_and_without_provider_targets() {
        let data = parse(fixture(&format!("{BR_US},{BR_NO_TARGET},{HK}")).as_bytes()).unwrap();
        assert_eq!(data.values, vec![7.5, 4.4, 2.1]);
        assert_eq!(data.rows[0].target_country_alpha2.as_deref(), Some("US"));
        assert_eq!(data.rows[1].target_country_alpha2, None);
        assert_eq!(data.value_label(0), "7.5%");
        assert_eq!(data.windows.len(), 1);
    }
    #[test]
    fn origins_keep_largest_row_and_never_sum() {
        let data = parse(fixture(&format!("{BR_US},{BR_NO_TARGET},{HK}")).as_bytes()).unwrap();
        assert_eq!(
            data.origins(),
            vec![
                Origin {
                    code: "BR".into(),
                    largest: 7.5,
                    rows: 2
                },
                Origin {
                    code: "HK".into(),
                    largest: 2.1,
                    rows: 1
                },
            ]
        );
        assert_eq!(data.largest(), 7.5);
    }
    #[test]
    fn rejects_invalid_payloads_whole() {
        let bad_value = |v: &str| fixture(&BR_US.replace("7.5", v));
        let too_many = fixture(&vec![HK; MAX_ROWS + 1].join(","));
        let no_window = fixture(HK).replace(
            r#"[{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}]"#,
            "[]",
        );
        for payload in [
            r#"{"success":false}"#.to_string(),
            "{}".into(),
            "not json".into(),
            bad_value("NaN"),
            bad_value("inf"),
            bad_value("-1"),
            bad_value("x"),
            too_many,
            no_window,
        ] {
            assert_eq!(
                parse(payload.as_bytes()).err(),
                Some(Invalid),
                "{payload:.60}"
            );
        }
        assert_eq!(parse(&vec![b' '; MAX_BYTES + 1]).err(), Some(Invalid));
    }
    #[test]
    fn freshness_states_and_units() {
        let data = parse(fixture(HK).as_bytes()).unwrap();
        let empty = parse(fixture("").as_bytes()).unwrap();
        assert_eq!(freshness(None, 0, 0), Freshness::NoData);
        assert_eq!(freshness(Some(&empty), 0, 0), Freshness::Empty);
        assert_eq!(
            freshness(Some(&data), 1000, 1000 + STALE_AFTER_MS),
            Freshness::Current
        );
        assert_eq!(
            freshness(Some(&data), 1000, 1001 + STALE_AFTER_MS),
            Freshness::Stale
        );
        assert_eq!(freshness(Some(&data), 5000, 1000), Freshness::Current);
        let mut other = data.clone();
        other.normalization = "MIN0_MAX".into();
        assert_eq!(other.value_label(0), "2.1 (MIN0_MAX)");
        assert_eq!(small_place("HK"), Some((114.2, 22.3)));
        assert_eq!(small_place("XX"), None);
    }
}
