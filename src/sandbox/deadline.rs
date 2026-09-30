use anyhow::{Context, Result};
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Debug)]
pub struct DeadlineExceeded;

impl std::fmt::Display for DeadlineExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("sandbox wall-clock deadline exceeded (not the CPU-time limit)")
    }
}

impl std::error::Error for DeadlineExceeded {}

#[derive(Clone, Copy)]
pub(crate) struct Deadline(Instant);

impl Deadline {
    pub(crate) fn after(timeout: Duration) -> Result<Self> {
        Instant::now()
            .checked_add(timeout)
            .map(Self)
            .context("sandbox timeout exceeds monotonic clock range")
    }

    pub(crate) fn check(&self) -> Result<()> {
        if Instant::now() >= self.0 {
            return Err(DeadlineExceeded.into());
        }
        Ok(())
    }

    pub(crate) async fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        self.check()?;
        let result = tokio::time::timeout_at(self.0, future)
            .await
            .map_err(|_| DeadlineExceeded)?;
        self.check()?;
        result
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/sandbox_deadline.rs"]
mod tests;
