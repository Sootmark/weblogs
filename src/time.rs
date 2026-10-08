//! The times access logs write.

use common::time::{days_from_civil, Precision, Ts};

const TICKS_PER_SECOND: i64 = 10_000_000;
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Ticks of a wall-clock time, checked.
fn ticks(date: (i64, u32, u32), hour: i64, minute: i64, second: i64) -> Option<i64> {
    let (year, month, day) = date;
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(seconds * TICKS_PER_SECOND)
}

/// `13/Jan/2016:19:31:16 +0000` (Apache's `%t` inside its brackets) as
/// UTC.
pub(crate) fn clf(text: &str) -> Option<Ts> {
    let (stamp, zone) = text.trim().split_once(' ')?;
    let mut parts = stamp.splitn(4, [':', '/']);
    let day: u32 = parts.next()?.parse().ok()?;
    let name = parts.next()?;
    let month = MONTHS.iter().position(|m| *m == name)? as u32 + 1;
    let year: i64 = parts.next()?.parse().ok()?;
    let mut clock = parts.next()?.splitn(3, ':');
    let number = |t: Option<&str>| t?.parse::<i64>().ok();
    let ticks = ticks(
        (year, month, day),
        number(clock.next())?,
        number(clock.next())?,
        number(clock.next())?,
    )?;
    let offset = offset_minutes(zone.trim())?;
    Some(Ts::from_local_ticks(ticks, Precision::Second).assume_offset(offset))
}

/// `+0200`, `-0500` in minutes.
fn offset_minutes(zone: &str) -> Option<i32> {
    let (sign, digits) = match zone.as_bytes().first()? {
        b'+' => (1, &zone[1..]),
        b'-' => (-1, &zone[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i32 = digits[..2].parse().ok()?;
    let minutes: i32 = digits[2..].parse().ok()?;
    Some(sign * (hours * 60 + minutes))
}

/// `2012-10-29 00:06:26,838` (Log4j's default) as local time.
pub(crate) fn log4j(text: &str) -> Option<Ts> {
    let (date, clock) = text.trim().split_once(' ')?;
    let mut date = date.splitn(3, '-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: u32 = date.next()?.parse().ok()?;
    let day: u32 = date.next()?.parse().ok()?;
    let (clock, millis) = clock.split_once([',', '.']).unwrap_or((clock, "0"));
    let mut clock = clock.splitn(3, ':');
    let number = |t: Option<&str>| t?.parse::<i64>().ok();
    let ticks = ticks(
        (year, month, day),
        number(clock.next())?,
        number(clock.next())?,
        number(clock.next())?,
    )?;
    let millis: i64 = millis.parse().ok().filter(|m| (0..1000).contains(m))?;
    Some(Ts::from_local_ticks(
        ticks + millis * 10_000,
        Precision::Millisecond,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let iso = |t: Option<Ts>| t.and_then(|t| t.to_iso8601());
        assert_eq!(
            iso(clf("13/Jan/2016:19:31:20 +0200")).as_deref(),
            Some("2016-01-13T17:31:20.0000000Z")
        );
        assert_eq!(clf("13/Foo/2016:19:31:20 +0200"), None);
        assert_eq!(clf("13/Jan/2016:19:31:20 0200"), None);
        assert_eq!(
            iso(log4j("2012-10-29 00:06:26,838")).as_deref(),
            Some("2012-10-29T00:06:26.8380000")
        );
        assert_eq!(log4j("2012-13-29 00:06:26,838"), None);
    }
}
