use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMetric {
    pub name: String,
    pub value: i64,
    pub unit: String,
}

#[derive(Debug, Default)]
pub struct TelemetryCollector {
    metrics: VecDeque<RuntimeMetric>,
    max_items: usize,
}

impl TelemetryCollector {
    pub fn new(max_items: usize) -> Self {
        Self {
            metrics: VecDeque::new(),
            max_items,
        }
    }

    pub fn record(&mut self, name: impl Into<String>, value: i64, unit: impl Into<String>) {
        let metric = RuntimeMetric {
            name: name.into(),
            value,
            unit: unit.into(),
        };
        if self.metrics.len() >= self.max_items {
            self.metrics.pop_front();
        }
        self.metrics.push_back(metric);
    }

    pub fn snapshot(&self) -> Vec<RuntimeMetric> {
        self.metrics.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::TelemetryCollector;

    #[test]
    fn telemetry_keeps_bounded_snapshot() {
        let mut collector = TelemetryCollector::new(2);
        collector.record("cpu", 42, "pct");
        collector.record("memory", 1024, "mb");
        collector.record("sessions", 5, "count");
        assert_eq!(collector.snapshot().len(), 2);
        assert_eq!(collector.snapshot().last().unwrap().name, "sessions");
    }
}
