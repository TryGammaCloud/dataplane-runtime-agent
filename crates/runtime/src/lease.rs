//! Independent lease expiry so a long-running API operation cannot defer teardown.
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

pub struct Lease {
    cancel: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Lease {
    pub fn start(unit: String, deadline: Instant) -> Self {
        let cancel = Arc::new((Mutex::new(false), Condvar::new()));
        let state = cancel.clone();
        let thread = std::thread::spawn(move || {
            let (lock, wake) = &*state;
            let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let result = wake.wait_timeout_while(
                guard,
                deadline.saturating_duration_since(Instant::now()),
                |cancelled| !*cancelled,
            );
            let (guard, _) = result.unwrap_or_else(|e| e.into_inner());
            if *guard {
                return;
            }
            drop(guard);
            // A service may still be queued when the lease expires. Retry until stopped.
            loop {
                if *lock.lock().unwrap_or_else(|e| e.into_inner()) {
                    break;
                }
                if crate::isolated::control(&unit, "stop").is_ok() {
                    break;
                }
                let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                let _ = wake.wait_timeout(guard, std::time::Duration::from_millis(100));
            }
        });
        Self {
            cancel,
            thread: Some(thread),
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        *self.cancel.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.cancel.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
