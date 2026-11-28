//! Conversions between lexicon `datetime` values and `chrono` instants.

use chrono::{DateTime, Utc};
use petrel_core::Datetime;

/// The instant a lexicon datetime names, or `None` when it is outside chrono's range.
pub fn to_utc(value: &Datetime) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::try_from(value.clone()).ok()
}

/// A lexicon datetime for an instant, or `None` when it cannot be written as one
/// (a year outside 0000..=9999).
pub fn from_utc(value: DateTime<Utc>) -> Option<Datetime> {
    Datetime::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_chrono() {
        let parsed = Datetime::parse("2026-08-24T12:00:00.123Z").unwrap();
        let instant = to_utc(&parsed).unwrap();
        assert_eq!(instant.timestamp_millis(), 1_787_572_800_123);
        let back = from_utc(instant).unwrap();
        assert_eq!(to_utc(&back), Some(instant));
    }

    #[test]
    fn offset_datetimes_convert_to_the_same_instant() {
        let offset = Datetime::parse("2026-08-24T14:00:00+02:00").unwrap();
        let utc = Datetime::parse("2026-08-24T12:00:00Z").unwrap();
        assert_eq!(to_utc(&offset), to_utc(&utc));
    }
}
