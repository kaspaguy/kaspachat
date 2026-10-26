//! WIRE_FORMAT §7 kind 0x06: conversation settings.

use crate::Error;

pub const TIMER_SECONDS: u32 = 108_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefs {
    /// 1 = the original 1:1-only form; 2 = with a context byte (§7.1).
    pub version: u8,
    pub epoch: u32,
    /// None = the 1:1 session (version 1, or version 2 context 0x00); Some = that group (context 0x01).
    pub group_id: Option<[u8; 16]>,
    pub timer_off: bool,
    pub screenshot_protection: bool,
}

/// v1: `0x01 ‖ epoch u32 ‖ flags u8`; v2: `0x02 ‖ epoch u32 ‖ context u8 ‖ contextData (0 or 16) ‖ flags u8` (§7.1).
pub fn encode(p: &Prefs) -> Result<Vec<u8>, Error> {
    let flags = p.timer_off as u8 | ((p.screenshot_protection as u8) << 1);
    let mut v = vec![p.version];
    v.extend_from_slice(&p.epoch.to_be_bytes());
    match (p.version, &p.group_id) {
        (1, None) => {}
        (2, None) => v.push(0),
        (2, Some(g)) => {
            v.push(1);
            v.extend_from_slice(g);
        }
        _ => return Err(Error::Malformed),
    }
    v.push(flags);
    Ok(v)
}

pub fn decode(b: &[u8]) -> Result<Prefs, Error> {
    let (group_id, flags) = match (b.first(), b.get(5), b.len()) {
        (Some(1), _, 6) => (None, b[5]),
        (Some(2), Some(0), 7) => (None, b[6]),
        (Some(2), Some(1), 23) => (Some(b[6..22].try_into().unwrap()), b[22]),
        _ => return Err(Error::Malformed),
    };
    if flags & !0b11 != 0 {
        return Err(Error::Malformed);
    }
    Ok(Prefs { version: b[0], epoch: u32::from_be_bytes(b[1..5].try_into().unwrap()), group_id, timer_off: flags & 1 != 0, screenshot_protection: flags & 2 != 0 })
}

/// Per member and per context (whichever version carried them): only the preferences with the highest epoch are kept; the first received are
/// kept whatever their epoch; equal or lower epochs are ignored. Returns whether it replaced.
pub fn update(slot: &mut Option<Prefs>, incoming: Prefs) -> bool {
    match slot {
        Some(cur) if incoming.epoch <= cur.epoch => false,
        _ => {
            *slot = Some(incoming);
            true
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effective {
    /// 0 = timer off.
    pub timer_seconds: u32,
    pub screenshot_protection: bool,
}

/// `members`: (is Plus, per the registry; latest preferences or None = "timer on, no protection").
pub fn effective(members: &[(bool, Option<Prefs>)]) -> Effective {
    let timer_off = members.iter().all(|(plus, p)| *plus && p.is_some_and(|p| p.timer_off));
    // Honoured from any member, whatever their tier (SC-0022).
    let ss = members.iter().any(|(_, p)| p.is_some_and(|p| p.screenshot_protection));
    Effective { timer_seconds: if timer_off { 0 } else { TIMER_SECONDS }, screenshot_protection: ss }
}
