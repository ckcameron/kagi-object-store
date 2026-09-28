// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Bounded node-local event history and live delivery.
//!
//! Publication never waits for a subscriber. A slow client receives an explicit gap;
//! history is bounded and process-local, while the ordinary Kagi log stays on disk.
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::sync::broadcast;

/// Structured events intentionally exclude request headers, credentials, and bodies.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub id: u64,
    pub unix_ms: u128,
    pub severity: String,
    pub category: String,
    pub resource: String,
    pub message: String,
}

/// Client filters restrict delivery, not authorization; viewers are node-wide operators.
#[derive(Clone, Default, Deserialize)]
pub struct Filter {
    #[serde(default)]
    pub after: u64,
    pub category: Option<String>,
    pub resource_prefix: Option<String>,
    pub severity: Option<String>,
}
impl Filter {
    pub fn matches(&self, event: &Event) -> bool {
        event.id > self.after
            && self.category.as_ref().is_none_or(|v| v == &event.category)
            && self
                .resource_prefix
                .as_ref()
                .is_none_or(|v| event.resource.starts_with(v))
            && self.severity.as_ref().is_none_or(|v| v == &event.severity)
    }
}

/// One lock orders IDs and history so replay and live delivery can be deduplicated.
#[derive(Clone)]
pub struct Monitor {
    inner: Arc<Mutex<(u64, VecDeque<Event>)>>,
    sender: broadcast::Sender<Event>,
    capacity: usize,
}
impl Monitor {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.clamp(16, 65536);
        let (sender, _) = broadcast::channel(capacity);
        Self {
            inner: Arc::new(Mutex::new((0, VecDeque::new()))),
            sender,
            capacity,
        }
    }

    /// Keep bounded history even when nobody is currently subscribed.
    pub fn emit(&self, severity: &str, category: &str, resource: &str, message: &str) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.0 += 1;
        let event = Event {
            id: state.0,
            unix_ms: crate::filesystem::now_ms(),
            severity: severity.into(),
            category: category.into(),
            resource: resource.chars().take(1024).collect(),
            message: message.chars().take(4096).collect(),
        };
        if state.1.len() == self.capacity {
            state.1.pop_front();
        }
        state.1.push_back(event.clone());
        let _ = self.sender.send(event);
    }

    pub fn history(&self, filter: &Filter) -> serde_json::Value {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let oldest = state.1.front().map(|e| e.id).unwrap_or(0);
        serde_json::json!({
            "events": state.1.iter().filter(|e| filter.matches(e)).collect::<Vec<_>>(),
            "oldest_id": oldest, "latest_id": state.0,
            "gap": filter.after > 0 && (filter.after.saturating_add(1) < oldest || filter.after > state.0),
            "persistence": "node-local memory; IDs reset at restart"
        })
    }

    /// Subscribe before taking history to close the replay/live race.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_is_bounded_filtered_and_reports_gaps() {
        let monitor = Monitor::new(16);
        for n in 0..20 {
            monitor.emit("warning", "security", &format!("obj/{n}"), "denied");
        }
        let history = monitor.history(&Filter {
            after: 1,
            ..Default::default()
        });
        assert_eq!(history["events"].as_array().unwrap().len(), 16);
        assert_eq!(history["gap"], true);
        let history = monitor.history(&Filter {
            category: Some("integrity".into()),
            ..Default::default()
        });
        assert_eq!(history["events"].as_array().unwrap().len(), 0);
    }
    #[tokio::test]
    async fn publication_delivers_live_events() {
        let monitor = Monitor::new(16);
        let mut receiver = monitor.subscribe();
        monitor.emit("error", "integrity", "bucket/key", "checksum mismatch");
        assert_eq!(receiver.recv().await.unwrap().resource, "bucket/key");
    }
}
