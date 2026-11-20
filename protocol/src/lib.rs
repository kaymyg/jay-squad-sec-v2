//! Versioned, validated event schema for the Jay Squad Sec engine boundary.
//!
//! Front ends (the Android app via the JNI bridge, or any sensor adapter)
//! submit [`WireEvent`]s. Nothing reaches the engine until it clears
//! [`validate`]. This is the "narrow, versioned interface" from the
//! architecture: the engine never trusts raw front-end input, so a buggy or
//! hostile front end cannot smuggle malformed, oversized or control-laden data
//! into the detection path.
//!
//! Layering: `protocol` sits above `core` (it maps to the engine's event
//! types) and below the front ends and the JNI bridge. `core` never depends on
//! `protocol`, which keeps the engine self-contained.

use jay_squad_sec::event::{Event, EventKind};
use jay_squad_sec::rtid::Rtid;
use std::fmt;

/// Wire schema version. Bump on any breaking change to [`WireEvent`] so an
/// older front end paired with a newer engine fails closed at validation
/// instead of being silently misread.
pub const PROTOCOL_VERSION: u32 = 1;

/// Hard upper bound on `detail` length, in bytes. Bounds per-event memory and
/// blocks a hostile or wedged front end from flooding the log/evidence path
/// with megabyte strings. 4 KiB is generous for a path or network endpoint.
pub const MAX_DETAIL_LEN: usize = 4096;

/// An event as submitted by a front end, before validation. Deliberately built
/// from primitives and strings so it crosses the JNI boundary cleanly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireEvent {
    /// Must equal [`PROTOCOL_VERSION`].
    pub schema_version: u32,
    /// OS process id the event concerns. Must be non-zero.
    pub pid: u32,
    /// Canonical snake_case event kind (see [`kind_from_wire`]).
    pub kind: String,
    /// Free-form detail (path, endpoint, …). Bounded and control-char-free.
    pub detail: String,
    /// Front-end timestamp in milliseconds.
    pub at_ms: u64,
}

/// A [`WireEvent`] that has passed every validation check. Construction is only
/// possible through [`validate`], so holding one is proof it is well-formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEvent {
    pub pid: u32,
    pub kind: EventKind,
    pub detail: String,
    pub at_ms: u64,
}

impl ValidatedEvent {
    /// Build the engine's internal [`Event`] once the bridge has resolved
    /// `pid` to a runtime identity.
    pub fn into_event(self, rtid: Rtid) -> Event {
        Event { rtid, kind: self.kind, at_ms: self.at_ms, detail: self.detail }
    }
}

/// Why a [`WireEvent`] was rejected. Variants deliberately avoid echoing the
/// raw offending bytes back (no reflecting hostile input into logs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// `schema_version` did not match the engine's [`PROTOCOL_VERSION`].
    UnsupportedSchema { got: u32, expected: u32 },
    /// `pid` was zero.
    InvalidPid,
    /// `kind` was not a recognised canonical event kind.
    UnknownKind,
    /// `detail` exceeded [`MAX_DETAIL_LEN`].
    DetailTooLong { len: usize, max: usize },
    /// `detail` contained a control character (newline, NUL, …).
    ControlCharInDetail,
    /// `detail` contained a bidirectional-override or zero-width character.
    /// These are invisible or reorder text, enabling "Trojan Source"-style
    /// spoofing of paths and endpoints in operator-facing logs and UI.
    UnsafeCharInDetail,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::UnsupportedSchema { got, expected } => {
                write!(f, "unsupported schema version {got} (engine expects {expected})")
            }
            ValidationError::InvalidPid => write!(f, "invalid pid: must be non-zero"),
            ValidationError::UnknownKind => write!(f, "unknown event kind"),
            ValidationError::DetailTooLong { len, max } => {
                write!(f, "detail too long: {len} bytes (max {max})")
            }
            ValidationError::ControlCharInDetail => {
                write!(f, "detail contains a control character")
            }
            ValidationError::UnsafeCharInDetail => {
                write!(f, "detail contains a bidi-override or zero-width character")
            }
        }
    }
}

/// Bidirectional-override and zero-width codepoints. Invisible or
/// text-reordering, so they must not reach logs, evidence records or the UI.
fn is_unsafe_display_char(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}'   // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
        | '\u{200B}'..='\u{200D}' // ZWSP, ZWNJ, ZWJ
        | '\u{2060}'              // word joiner
        | '\u{FEFF}')             // BOM / zero-width no-break space
}

impl std::error::Error for ValidationError {}

/// Map a canonical snake_case wire kind to an engine [`EventKind`].
///
/// This is the single source of truth for the accepted vocabulary. Anything
/// not listed here is rejected by [`validate`] as [`ValidationError::UnknownKind`].
pub fn kind_from_wire(s: &str) -> Option<EventKind> {
    use EventKind::*;
    Some(match s {
        "process_start" => ProcessStart,
        "process_exit" => ProcessExit,
        "signed_binary" => SignedBinary,
        "unsigned_binary" => UnsignedBinary,
        "network_connect" => NetworkConnect,
        "file_write" => FileWrite,
        "unsigned_module_load" => UnsignedModuleLoad,
        "rwx_alloc" => RwxAlloc,
        "remote_thread_injection" => RemoteThreadInjection,
        "credential_access" => CredentialAccess,
        "persistence_write" => PersistenceWrite,
        "privilege_escalation" => PrivilegeEscalation,
        "stable_tick" => StableTick,
        "temp_execution" => TempExecution,
        "deleted_executable" => DeletedExecutable,
        "app_signer_changed" => AppSignerChanged,
        "sensitive_permission_granted" => SensitivePermissionGranted,
        "new_app_with_sensitive_access" => NewAppWithSensitiveAccess,
        _ => return None,
    })
}

/// Inverse of [`kind_from_wire`]: the canonical wire string for a kind. Useful
/// for responses, audit records and round-trip tests.
pub fn wire_from_kind(k: EventKind) -> &'static str {
    use EventKind::*;
    match k {
        ProcessStart => "process_start",
        ProcessExit => "process_exit",
        SignedBinary => "signed_binary",
        UnsignedBinary => "unsigned_binary",
        NetworkConnect => "network_connect",
        FileWrite => "file_write",
        UnsignedModuleLoad => "unsigned_module_load",
        RwxAlloc => "rwx_alloc",
        RemoteThreadInjection => "remote_thread_injection",
        CredentialAccess => "credential_access",
        PersistenceWrite => "persistence_write",
        PrivilegeEscalation => "privilege_escalation",
        StableTick => "stable_tick",
        TempExecution => "temp_execution",
        DeletedExecutable => "deleted_executable",
        AppSignerChanged => "app_signer_changed",
        SensitivePermissionGranted => "sensitive_permission_granted",
        NewAppWithSensitiveAccess => "new_app_with_sensitive_access",
    }
}

/// Validate a front-end event. Returns a [`ValidatedEvent`] or the first
/// failure found. Checks run cheapest-first and the function never panics on
/// any input (see the robustness tests).
pub fn validate(ev: &WireEvent) -> Result<ValidatedEvent, ValidationError> {
    if ev.schema_version != PROTOCOL_VERSION {
        return Err(ValidationError::UnsupportedSchema {
            got: ev.schema_version,
            expected: PROTOCOL_VERSION,
        });
    }
    if ev.pid == 0 {
        return Err(ValidationError::InvalidPid);
    }
    if ev.detail.len() > MAX_DETAIL_LEN {
        return Err(ValidationError::DetailTooLong {
            len: ev.detail.len(),
            max: MAX_DETAIL_LEN,
        });
    }
    if ev.detail.chars().any(|c| c.is_control()) {
        return Err(ValidationError::ControlCharInDetail);
    }
    if ev.detail.chars().any(is_unsafe_display_char) {
        return Err(ValidationError::UnsafeCharInDetail);
    }
    let kind = kind_from_wire(&ev.kind).ok_or(ValidationError::UnknownKind)?;
    Ok(ValidatedEvent {
        pid: ev.pid,
        kind,
        detail: ev.detail.clone(),
        at_ms: ev.at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> WireEvent {
        WireEvent {
            schema_version: PROTOCOL_VERSION,
            pid: 1234,
            kind: "network_connect".into(),
            detail: "github.com:443".into(),
            at_ms: 10_000,
        }
    }

    #[test]
    fn a_well_formed_event_validates_and_converts() {
        let v = validate(&good()).expect("should validate");
        assert_eq!(v.kind, EventKind::NetworkConnect);
        assert_eq!(v.pid, 1234);
        let ev = v.into_event(Rtid(7));
        assert_eq!(ev.rtid, Rtid(7));
        assert_eq!(ev.kind, EventKind::NetworkConnect);
        assert_eq!(ev.detail, "github.com:443");
    }

    #[test]
    fn wrong_schema_is_rejected() {
        let mut w = good();
        w.schema_version = PROTOCOL_VERSION + 1;
        assert_eq!(
            validate(&w),
            Err(ValidationError::UnsupportedSchema {
                got: PROTOCOL_VERSION + 1,
                expected: PROTOCOL_VERSION
            })
        );
    }

    #[test]
    fn zero_pid_is_rejected() {
        let mut w = good();
        w.pid = 0;
        assert_eq!(validate(&w), Err(ValidationError::InvalidPid));
    }

    #[test]
    fn unknown_kind_is_rejected_without_echoing_input() {
        let mut w = good();
        w.kind = "definitely_not_a_kind".into();
        assert_eq!(validate(&w), Err(ValidationError::UnknownKind));
        // The error must not carry the raw string (no log reflection).
        assert!(!format!("{}", ValidationError::UnknownKind).contains("definitely_not_a_kind"));
    }

    #[test]
    fn oversized_detail_is_rejected() {
        let mut w = good();
        w.detail = "a".repeat(MAX_DETAIL_LEN + 1);
        assert_eq!(
            validate(&w),
            Err(ValidationError::DetailTooLong {
                len: MAX_DETAIL_LEN + 1,
                max: MAX_DETAIL_LEN
            })
        );
    }

    #[test]
    fn detail_at_the_limit_is_accepted() {
        let mut w = good();
        w.detail = "a".repeat(MAX_DETAIL_LEN);
        assert!(validate(&w).is_ok());
    }

    #[test]
    fn control_chars_in_detail_are_rejected() {
        for bad in ["line\none", "nul\0here", "tab\tthere", "ret\rurn"] {
            let mut w = good();
            w.detail = bad.into();
            assert_eq!(
                validate(&w),
                Err(ValidationError::ControlCharInDetail),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn bidi_and_zero_width_chars_are_rejected() {
        for bad in ["evil\u{202E}txt.exe", "zero\u{200B}width", "bom\u{FEFF}here"] {
            let mut w = good();
            w.detail = bad.into();
            assert_eq!(
                validate(&w),
                Err(ValidationError::UnsafeCharInDetail),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn every_kind_round_trips() {
        // The core's canonical list, so a newly added kind is always covered.
        for k in jay_squad_sec::rules::KINDS {
            let s = wire_from_kind(k);
            assert_eq!(kind_from_wire(s), Some(k), "round trip failed for {s}");
        }
    }

    /// Deterministic fuzz-style robustness: feed a wide range of hostile and
    /// garbage inputs; validate must return a Result and never panic.
    #[test]
    fn validate_never_panics_on_hostile_input() {
        let long_kind = "a".repeat(10_000);
        let long_detail = "a".repeat(MAX_DETAIL_LEN + 5000);
        let kinds: [&str; 6] =
            ["", "network_connect", "NETWORK_CONNECT", "\0", "🔥", long_kind.as_str()];
        let details: [&str; 5] =
            ["", "ok", long_detail.as_str(), "\u{0}\u{1}\u{7}", "🔥🔥"];
        let versions = [0u32, 1, 2, u32::MAX];
        let pids = [0u32, 1, u32::MAX];
        for &sv in &versions {
            for &pid in &pids {
                for k in &kinds {
                    for d in &details {
                        let w = WireEvent {
                            schema_version: sv,
                            pid,
                            kind: (*k).to_string(),
                            detail: (*d).to_string(),
                            at_ms: u64::MAX,
                        };
                        let _ = validate(&w); // must not panic
                    }
                }
            }
        }
    }
}
