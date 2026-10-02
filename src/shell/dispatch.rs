use super::command::Command;
use super::Shell;
use anyhow::Result;

impl Shell {
    /** None means quit; every other successful command has an output result. */
    pub(super) async fn dispatch(&mut self, command: Command) -> Result<Option<String>> {
        let message = match command {
            Command::Help => "help | info | analysis | run | status | events [1..100] | pause | \
                 resume | stop | report | quit\n\
                 info/analysis: inspect bytes without execution.\n\
                 run: launch the configured executable with automatic hook policy.\n\
                 events: latest retained observations, not a complete activity trace.\n\
                 pause: retain suspend increments on one root-process snapshot. \
                 New threads and descendants may continue; no action is undone.\n\
                 resume: release only this controller's retained increments.\n\
                 stop: terminate this owned Job and join monitoring.\n\
                 report: save the last completed report and behavioral assessment.\n\
                 EOF, Ctrl-C and quit stop owned execution and close input."
                .into(),
            Command::Analysis => {
                let report = self.session.inspect()?;

                /*
                 * Coverage warnings precede the bounded viewport, so a large
                 * strings/imports list cannot hide them. Serialize the whole
                 * landed report rather than reconstructing nested schemas.
                 */
                format!(
                    "Static limitations:\n{}\n\nStatic report:\n{}",
                    report.coverage.limitations.join("\n"),
                    serde_json::to_string_pretty(&report)?,
                )
            }
            Command::Run => {
                let pid = self.session.run().await?;
                format!("Owned PID {pid}; monitored startup continues asynchronously")
            }
            Command::Status => serde_json::to_string_pretty(&serde_json::json!({
                "executable": self.session.executable(),
                "state": self.session.state(),
                "pid": self.session.process_id(),
                "active": self.session.has_active_run(),
                "completed_report_available": self.session.completed_report().is_some(),
                "last_error": self.session.last_error(),
            }))?,
            Command::Events(limit) => {
                serde_json::to_string_pretty(&self.session.events(limit).await)?
            }
            Command::Pause => {
                self.session.pause().await?;
                "Snapshot suspension retained; this is not an atomic or Job-wide freeze".into()
            }
            Command::Resume => {
                self.session.resume().await?;
                "This controller's retained suspend increments were released".into()
            }
            Command::Stop => {
                self.session.stop().await?;
                "Owned execution stopped and monitor joined".into()
            }
            Command::Report => {
                let path = self.session.save_report()?;
                format!(
                    "Saved last completed execution and assessment: {}",
                    path.display(),
                )
            }
            Command::Quit => return Ok(None),
        };

        Ok(Some(message))
    }
}
