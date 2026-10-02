use super::LiveSession;
use crate::behavior::assessment::assess_events;
use crate::sandbox::resource::with_cleanup;
use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

impl LiveSession {
    /** Save the actual last completed report and its report-only assessment.
    A later active or failed execution never becomes a fabricated report. */
    pub fn save_report(&self) -> Result<PathBuf> {
        let report = self.completed.as_ref().context("no completed report")?;
        let artifact = serde_json::json!({
            "report": report,
            "assessment": assess_events(&report.events),
        });
        let bytes = serde_json::to_vec_pretty(&artifact)?;

        std::fs::create_dir_all(&self.config.output_dir)
            .context("create report output directory")?;

        let stem = format!(
            "shell-report-{}-{}",
            std::process::id(),
            report.start_time.timestamp_micros(),
        );
        let (path, mut file) = create_artifact(&self.config.output_dir, &stem)?;

        let written = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .context("write completed report and assessment");

        drop(file);

        if let Err(error) = written {
            return with_cleanup(
                Err(error),
                std::fs::remove_file(&path).context("remove incomplete report artifact"),
            );
        }

        Ok(path)
    }
}

fn create_artifact(directory: &Path, stem: &str) -> Result<(PathBuf, File)> {
    /*
     * Exclusive creation prevents clobbering previous artifacts. The bounded
     * suffix search also supports repeated saves without timing-based names.
     */
    for index in 0..1000 {
        let path = directory.join(format!("{stem}-{index}.json"));

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("create report {}", path.display()));
            }
        }
    }

    bail!("all report artifact names for this execution are already occupied")
}
