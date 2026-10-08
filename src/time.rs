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

/// ISO 8601 (`2020-01-11T16:55:20.356586Z`, `2021-10-14T22:17:11+00:00`):
/// UTC with `Z` or an offset, local without (`2022-04-01T08:51:42`).
pub(crate) fn iso8601(text: &str) -> Option<Ts> {
    let (date, clock) = text.trim().split_once('T')?;
    let mut date = date.splitn(3, '-');
    let number = |t: Option<&str>| t?.parse::<i64>().ok();
    let year = number(date.next())?;
    let month = u32::try_from(number(date.next())?).ok()?;
    let day = u32::try_from(number(date.next())?).ok()?;
    let (clock, zone) = match clock.find(['Z', '+', '-']) {
        Some(at) => (&clock[..at], Some(&clock[at..])),
        None => (clock, None),
    };
    let (clock, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    let mut clock = clock.splitn(3, ':');
    let ticks = ticks(
        (year, month, day),
        number(clock.next())?,
        number(clock.next())?,
        number(clock.next())?,
    )?;
    let (sub, precision) = fraction_ticks(fraction)?;
    let local = Ts::from_local_ticks(ticks + sub, precision);
    match zone {
        None => Some(local),
        Some("Z") => Some(local.assume_offset(0)),
        Some(offset) => Some(local.assume_offset(offset_minutes(&offset.replace(':', ""))?)),
    }
}

/// A second's fraction in ticks, and its precision.
fn fraction_ticks(fraction: &str) -> Option<(i64, Precision)> {
    const TICK_DIGITS: usize = 7;
    if fraction.is_empty() {
        return Some((0, Precision::Second));
    }
    if fraction.len() > TICK_DIGITS || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let precision = match fraction.len() {
        1..=3 => Precision::Millisecond,
        4..=6 => Precision::Microsecond,
        _ => Precision::Tick,
    };
    Some((
        format!("{fraction:0<TICK_DIGITS$}").parse().ok()?,
        precision,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_times() {
        let iso = |t: &str| iso8601(t).and_then(|t| t.to_iso8601());
        assert_eq!(
            iso("2020-01-11T16:55:20.356586Z").as_deref(),
            Some("2020-01-11T16:55:20.3565860Z")
        );
        assert_eq!(
            iso("2021-10-14T22:17:11+02:00").as_deref(),
            Some("2021-10-14T20:17:11.0000000Z")
        );
        assert_eq!(
            iso("2022-04-01T08:51:42").as_deref(),
            Some("2022-04-01T08:51:42.0000000")
        );
        assert_eq!(iso("2022-04-01T08:51:42.x"), None);
        assert_eq!(iso("2022-04-01 08:51:42"), None);
    }

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
