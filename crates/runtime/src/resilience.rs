use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileState {
    Healthy,
    Recovered,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileEvent {
    pub process_id: u32,
    pub state: ReconcileState,
    pub observed_at: u64,
}

#[derive(Debug, Default)]
pub struct Reconciler {
    events: HashMap<u32, ReconcileEvent>,
    max_history: usize,
}

impl Reconciler {
    pub fn new(max_history: usize) -> Self {
        Self {
            events: HashMap::new(),
            max_history,
        }
    }

    pub fn record_process(&mut self, process_id: u32, state: ReconcileState) {
        let observed_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.events.insert(process_id, ReconcileEvent { process_id, state, observed_at });
        if self.events.len() > self.max_history {
            let oldest = self.events.keys().copied().min();
            if let Some(oldest) = oldest {
                self.events.remove(&oldest);
            }
        }
    }

    pub fn latest_for(&self, process_id: u32) -> Option<&ReconcileEvent> {
        self.events.get(&process_id)
    }

    pub fn reconcile_window(&self) -> Duration {
        Duration::from_secs(30)
    }
}

#[cfg(test)]
mod tests {
    use super::{ReconcileState, Reconciler};

    #[test]
    fn reconciler_tracks_recent_process_state() {
        let mut reconciler = Reconciler::new(2);
        reconciler.record_process(10, ReconcileState::Healthy);
        reconciler.record_process(11, ReconcileState::Recovered);
        reconciler.record_process(12, ReconcileState::Failed);
        assert!(reconciler.latest_for(12).is_some());
        assert!(reconciler.reconcile_window().as_secs() > 0);
    }
}
