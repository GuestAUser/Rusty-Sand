mod presentation;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::run as run_windows;

use crate::cli::{Args, ReportFormat};
use anyhow::{Context, Result};
use rusty_sand::report::analysis::{AnalysisMode, AnalysisReport, Evidence};

#[cfg(not(windows))]
pub(crate) fn run_portable(args: &Args) -> Result<()> {
    if args.mode() == AnalysisMode::Static {
        return run_static(args);
    }

    anyhow::bail!("Rusty Sand execution requires Windows; from WSL use ./rusty-sand")
}

pub(crate) fn run_static(args: &Args) -> Result<()> {
    let report = AnalysisReport::inspect(&args.executable, AnalysisMode::Static);

    finish_analysis(args, &report, Ok(()))
}

fn save_analysis(args: &Args, report: &AnalysisReport) -> Result<()> {
    if matches!(args.format, ReportFormat::Json | ReportFormat::Both) {
        std::fs::create_dir_all(&args.output_dir)
            .with_context(|| format!("Cannot create {}", args.output_dir.display()))?;
        report.save_json(&args.output_dir.join("analysis.json"))?;
    }

    Ok(())
}

fn finish_analysis(args: &Args, report: &AnalysisReport, result: Result<()>) -> Result<()> {
    let inspection = match &report.static_analysis {
        Evidence::Failed { error } => {
            Err(anyhow::anyhow!("Static inspection was incomplete: {error}"))
        }
        _ => Ok(()),
    };
    let result = combine(result, inspection);

    // Persist before presentation, including when the backend or analysis failed.
    let saved = save_analysis(args, report);
    let displayed = if matches!(args.format, ReportFormat::Console | ReportFormat::Both) {
        presentation::analysis(report)
    } else {
        Ok(())
    };

    combine(combine(result, saved), displayed)
}

fn combine(primary: Result<()>, additional: Result<()>) -> Result<()> {
    match (primary, additional) {
        (Ok(()), result) => result,
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(additional)) => {
            Err(error.context(format!("Additional failure: {additional:#}")))
        }
    }
}
