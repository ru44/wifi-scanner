//! Minimal Ctrl-C (SIGINT) handling so long-running modes can stop cleanly
//! after the current iteration instead of being killed mid-render.
//!
//! The project takes no third-party dependencies, and it is Linux-only, so
//! rather than pull in a crate this binds libc's `signal(2)` directly. The
//! handler only flips an atomic flag (async-signal-safe) and then restores the
//! default disposition, so a second Ctrl-C force-quits if a graceful shutdown
//! is itself stuck.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

const SIGINT: i32 = 2;
const SIG_DFL: usize = 0;

unsafe extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
}

extern "C" fn on_sigint(_sig: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
    // Restore the default handler: a second Ctrl-C now terminates at once.
    unsafe {
        signal(SIGINT, SIG_DFL);
    }
}

/// Installs the Ctrl-C handler. Call once, before entering a work loop.
pub(crate) fn install() {
    let handler = on_sigint as extern "C" fn(i32);
    unsafe {
        signal(SIGINT, handler as usize);
    }
}

/// True once Ctrl-C has been pressed.
pub(crate) fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Sleeps up to `dur`, returning early the moment Ctrl-C is seen so the loop
/// can stop without waiting out the whole interval.
pub(crate) fn sleep_or_interrupt(dur: Duration) {
    let start = Instant::now();
    loop {
        if interrupted() {
            return;
        }
        match dur.checked_sub(start.elapsed()) {
            Some(remaining) if !remaining.is_zero() => {
                std::thread::sleep(remaining.min(Duration::from_millis(100)));
            }
            _ => return,
        }
    }
}
