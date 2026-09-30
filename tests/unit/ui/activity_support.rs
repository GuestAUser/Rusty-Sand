use super::{ActivityGuard, Command};
use std::sync::mpsc;
use std::time::Duration;

impl ActivityGuard {
    pub(in crate::ui) fn worker_sender(&self) -> Option<mpsc::SyncSender<Command>> {
        self.worker.as_ref().map(|worker| worker.sender.clone())
    }

    pub(in crate::ui) fn tick(&self, elapsed: Duration) {
        let (acknowledge, observed) = mpsc::sync_channel(1);
        self.worker
            .as_ref()
            .expect("animated activity has a worker")
            .sender
            .send(Command::Tick(elapsed, acknowledge))
            .expect("activity worker receives the requested tick");
        observed
            .recv_timeout(Duration::from_secs(5))
            .expect("activity worker acknowledges the tick");
    }
}
