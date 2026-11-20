// SPDX-License-Identifier: AGPL-3.0-or-later

//! The latest frame and the page's long poll (plan 0071 decision 2): the
//! page asks for a frame newer than the one it holds and the answer comes
//! as raw command bytes, never as script evaluated in the page.
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;
use zeroize::Zeroizing;

/// Encoded frames, newest last.
pub(crate) struct Hub {
    latest: Mutex<Latest>,
    changed: Condvar,
}

#[derive(Default)]
struct Latest {
    seq: u64,
    bytes: Option<Arc<Zeroizing<Vec<u8>>>>,
}

impl Hub {
    pub(crate) fn new() -> Self {
        Self {
            latest: Mutex::new(Latest::default()),
            changed: Condvar::new(),
        }
    }

    /// The sequence the next frame gets.
    pub(crate) fn next_seq(&self) -> u64 {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .seq
            .wrapping_add(1)
    }

    /// Publishes a frame built for `seq`, unless its content (after the
    /// sequence) equals the current one.
    pub(crate) fn publish(&self, seq: u64, bytes: Zeroizing<Vec<u8>>, same: bool) {
        let mut latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        if same && latest.bytes.is_some() {
            return;
        }
        latest.seq = seq;
        latest.bytes = Some(Arc::new(bytes));
        drop(latest);
        self.changed.notify_all();
    }

    /// The latest frame if newer than `after`, waiting up to `wait` for one.
    pub(crate) fn wait_newer(&self, after: u64, wait: Duration) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        let latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        let (latest, _) = self
            .changed
            .wait_timeout_while(latest, wait, |l| l.seq <= after || l.bytes.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        if latest.seq > after {
            latest.bytes.clone()
        } else {
            None
        }
    }

    /// The latest frame, whatever its sequence.
    pub(crate) fn current(&self) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_poll_returns_only_newer_frames() {
        let hub = Arc::new(Hub::new());
        assert!(hub.wait_newer(0, Duration::from_millis(10)).is_none());
        hub.publish(1, Zeroizing::new(b"a".to_vec()), false);
        assert_eq!(hub.wait_newer(0, Duration::ZERO).unwrap().as_slice(), b"a");
        assert!(hub.wait_newer(1, Duration::from_millis(10)).is_none());
        let waiter = {
            let hub = hub.clone();
            std::thread::spawn(move || hub.wait_newer(1, Duration::from_secs(5)))
        };
        std::thread::sleep(Duration::from_millis(20));
        hub.publish(2, Zeroizing::new(b"b".to_vec()), false);
        assert_eq!(waiter.join().unwrap().unwrap().as_slice(), b"b");
        // An identical frame is not republished.
        hub.publish(3, Zeroizing::new(b"b".to_vec()), true);
        assert_eq!(hub.next_seq(), 3);
    }
}
