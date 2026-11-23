//! The daemon's independent human confirmation. Socket clients can request the dialog, but
//! cannot supply its answer. Proofs are local Rust values tied to exactly one decision.

use crate::core::{
    policy::{PolicyCode, PolicyError},
    CoreError,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Prompt {
    binding: [u8; 32],
    title: &'static str,
    message: String,
    affirmative: &'static str,
}

impl Prompt {
    pub(crate) fn new(
        action: &'static str,
        exact_request: &impl Serialize,
        title: &'static str,
        message: String,
        affirmative: &'static str,
    ) -> Result<Self, CoreError> {
        let encoded = serde_json::to_vec(&(action, exact_request))
            .map_err(|_| refused("the requested decision could not be bound to a confirmation"))?;
        Ok(Self {
            binding: Sha256::digest(encoded).into(),
            title,
            message,
            affirmative,
        })
    }
}

#[derive(Debug)]
pub struct Proof {
    binding: [u8; 32],
    confirmed: Instant,
}

impl Proof {
    #[cfg(any(test, target_os = "macos"))]
    fn from_confirmed(prompt: &Prompt) -> Self {
        Self {
            binding: prompt.binding,
            confirmed: Instant::now(),
        }
    }

    pub(crate) fn validate(self, expected: &Prompt) -> Result<(), CoreError> {
        if self.binding == expected.binding && self.confirmed.elapsed() <= Duration::from_secs(30) {
            Ok(())
        } else {
            Err(refused(
                "the decision changed during macOS confirmation; review it and try again",
            ))
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(prompt: &Prompt) -> Self {
        Self::from_confirmed(prompt)
    }
}

pub(crate) fn refused(reason: &'static str) -> CoreError {
    PolicyError::new(PolicyCode::AgentApproveNotAllowed, reason).into()
}

pub(crate) fn require(proof: Option<Proof>, expected: &Prompt) -> Result<(), CoreError> {
    proof
        .ok_or_else(|| refused("this decision requires confirmation in the macOS system dialog"))?
        .validate(expected)
}

/// Plain text only. Keep newlines, bidi controls and invisible formatting out of interpolated
/// values so task or repository text cannot supply its own heading, decision, or button.
pub(crate) fn preview(value: &str, limit: usize) -> String {
    let mut chars = value.chars();
    let mut preview: String = chars.by_ref().take(limit).map(|ch| {
        if ch.is_control() || matches!(ch, '\u{00ad}' | '\u{061c}' | '\u{180e}' |
            '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}') {
            ' '
        } else { ch }
    }).collect();
    if chars.next().is_some() {
        preview.push('…');
    }
    preview
}

#[cfg(target_os = "macos")]
pub(crate) async fn request(prompt: Prompt) -> Result<Proof, CoreError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    struct ActiveDialog;
    impl Drop for ActiveDialog {
        fn drop(&mut self) {
            ACTIVE.store(false, Ordering::Release);
        }
    }

    ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| {
            refused("a macOS confirmation is already open; answer it before trying again")
        })?;
    let guard = ActiveDialog;
    tokio::task::spawn_blocking(move || {
        // Keep the slot until the actual dialog closes even if its socket caller disconnects.
        let _guard = guard;
        mac::approve(&prompt)?;
        Ok(Proof::from_confirmed(&prompt))
    })
    .await
    .map_err(|_| refused("the macOS confirmation was unavailable"))?
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn request(prompt: Prompt) -> Result<Proof, CoreError> {
    let _ = (&prompt.title, &prompt.message, &prompt.affirmative);
    Err(refused(
        "native human confirmation is available only in an interactive macOS session",
    ))
}

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use std::{ffi::c_void, ptr};

    // CoreFoundation SDK's CFString.h and CFUserNotification.h.
    const UTF8: u32 = 0x0800_0100;
    const CAUTION: usize = 2;
    const ALTERNATE_RESPONSE: usize = 1;
    type CfRef = *const c_void;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithBytes(
            alloc: CfRef,
            bytes: *const u8,
            count: isize,
            encoding: u32,
            external: u8,
        ) -> CfRef;
        fn CFRelease(value: CfRef);
        fn CFUserNotificationDisplayAlert(
            timeout: f64,
            flags: usize,
            icon: CfRef,
            sound: CfRef,
            localization: CfRef,
            title: CfRef,
            message: CfRef,
            default_button: CfRef,
            alternate_button: CfRef,
            other_button: CfRef,
            response: *mut usize,
        ) -> i32;
    }

    struct CfString(CfRef);
    impl CfString {
        fn new(text: &str) -> Result<Self, CoreError> {
            // CF copies the valid UTF-8 bytes. The null allocator selects the default allocator.
            let raw = unsafe {
                CFStringCreateWithBytes(ptr::null(), text.as_ptr(), text.len() as isize, UTF8, 0)
            };
            if raw.is_null() {
                Err(refused("the macOS confirmation was unavailable"))
            } else {
                Ok(Self(raw))
            }
        }
    }
    impl Drop for CfString {
        fn drop(&mut self) {
            // Each non-null string was retained by CFStringCreateWithBytes.
            unsafe { CFRelease(self.0) };
        }
    }

    pub(super) fn approve(prompt: &Prompt) -> Result<(), CoreError> {
        let title = CfString::new(prompt.title)?;
        let message = CfString::new(&prompt.message)?;
        let cancel = CfString::new("Cancel")?;
        let confirm = CfString::new(prompt.affirmative)?;
        let mut response = usize::MAX;
        // The owned strings outlive the blocking call. A null URL/third button omits each option.
        // The default button is Cancel, so pressing Return or dismissing the dialog never grants.
        let status = unsafe {
            CFUserNotificationDisplayAlert(
                30.0,
                CAUTION,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                title.0,
                message.0,
                cancel.0,
                confirm.0,
                ptr::null(),
                &mut response,
            )
        };
        confirmed_response(status, response)
    }

    pub(super) fn confirmed_response(status: i32, response: usize) -> Result<(), CoreError> {
        if status != 0 {
            return Err(refused("no interactive macOS confirmation was available"));
        }
        if response != ALTERNATE_RESPONSE {
            return Err(refused("the macOS confirmation was cancelled or timed out"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_is_bound_to_the_action_and_its_inputs() {
        let prompt =
            |action, id| Prompt::new(action, &id, "Title", String::new(), "Allow").unwrap();
        assert!(Proof::for_test(&prompt("grant", 1))
            .validate(&prompt("grant", 1))
            .is_ok());
        assert!(Proof::for_test(&prompt("grant", 1))
            .validate(&prompt("grant", 2))
            .is_err());
        assert!(Proof::for_test(&prompt("grant", 1))
            .validate(&prompt("deny", 1))
            .is_err());
        assert!(require(None, &prompt("grant", 1)).is_err());
    }

    #[test]
    fn preview_bounds_and_flattens_untrusted_text() {
        assert_eq!(preview("Task\n\u{202e}ok", 7), "Task  o…");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_the_affirmative_button_confirms() {
        for response in [0, 2, 3, usize::MAX] {
            assert!(mac::confirmed_response(0, response).is_err());
        }
        assert!(mac::confirmed_response(0, 1).is_ok());
        assert!(mac::confirmed_response(1, 1).is_err());
    }
}
