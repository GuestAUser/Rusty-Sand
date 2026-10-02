use super::{combine, finish_analysis, presentation, save_analysis};
use crate::cli::{Args, ReportFormat};
use anyhow::{bail, Context, Result};
use rusty_sand::debugger::{DebugReport, ExitOutcome};
use rusty_sand::report::analysis::{AnalysisMode, AnalysisReport, Evidence, ExecutionOutcome};
use rusty_sand::ui::OutputPolicy;
use rusty_sand::SandboxConfig;

pub(crate) async fn run(args: Args, config: SandboxConfig, policy: OutputPolicy) -> Result<()> {
    let mut analysis = AnalysisReport::inspect(&args.executable, args.mode());

    if args.mode() != AnalysisMode::Static {
        analysis.requested_config = Some(config.clone());
    }

    // A pending artifact is never evidence of a successful launch.
    save_analysis(&args, &analysis)?;

    let result = match args.mode() {
        AnalysisMode::Execute => execute(&args, config, &policy, &mut analysis).await,
        AnalysisMode::Debug => debug(&args, config, &mut analysis).await,
        AnalysisMode::Shell => rusty_sand::shell::run_shell(&args.executable, &args.args, config)
            .await
            .map(|()| {
                analysis.execution = ExecutionOutcome::ShellClosed;
            }),
        // Inspection was collected above; static mode never launches a target.
        AnalysisMode::Static => Ok(()),
    };

    if let Err(error) = &result {
        if matches!(analysis.execution, ExecutionOutcome::Pending) {
            analysis.execution = ExecutionOutcome::Failed {
                error: format!("{error:#}"),
            };
        }
    }

    finish_analysis(&args, &analysis, result)
}

async fn execute(
    args: &Args,
    config: SandboxConfig,
    policy: &OutputPolicy,
    analysis: &mut AnalysisReport,
) -> Result<()> {
    let mut report = rusty_sand::execute_sandboxed(&args.executable, &args.args, config)
        .await
        .with_context(|| format!("Failed to execute {}", args.executable))?;
    report.executable.clone_from(&args.executable);
    analysis.record_execution(&report);

    let saved = if matches!(args.format, ReportFormat::Json | ReportFormat::Both) {
        report.save_json(&args.output_dir.join("report.json"))
    } else {
        Ok(())
    };
    let displayed = if matches!(args.format, ReportFormat::Console | ReportFormat::Both) {
        report.write_summary(&mut std::io::stderr().lock(), policy)
    } else {
        Ok(())
    };

    // The observed target exit code is evidence, not a CLI failure.
    combine(saved, displayed.map_err(anyhow::Error::from))
}

async fn debug(args: &Args, config: SandboxConfig, analysis: &mut AnalysisReport) -> Result<()> {
    save_debug(
        args,
        &Evidence::Unavailable {
            reason: "The requested debugger session has not completed.".into(),
        },
    )?;

    let evidence = match rusty_sand::analyst::run_debug(&args.executable, &args.args, config).await
    {
        Ok(report) => Evidence::Collected { report },
        Err(error) => Evidence::Failed {
            error: format!("{error:#}"),
        },
    };
    let saved = save_debug(args, &evidence);

    let result = match &evidence {
        Evidence::Collected { report } => {
            let execution = debug_outcome(report);

            analysis.execution = match &execution {
                Ok(()) => ExecutionOutcome::Exited { code: 0 },
                Err(error) => match &report.exit {
                    ExitOutcome::Exited { code } if !report.cancelled && !report.timed_out => {
                        ExecutionOutcome::Exited { code: *code }
                    }
                    _ => ExecutionOutcome::Failed {
                        error: format!("{error:#}"),
                    },
                },
            };

            let displayed = if matches!(args.format, ReportFormat::Console | ReportFormat::Both) {
                presentation::debug(report)
            } else {
                Ok(())
            };

            combine(execution, displayed)
        }
        Evidence::Failed { error } => Err(anyhow::anyhow!("Debugger failed: {error}")),
        Evidence::Unavailable { reason } => Err(anyhow::anyhow!("{reason}")),
    };

    combine(result, saved)
}

fn debug_outcome(report: &DebugReport) -> Result<()> {
    if report.cancelled {
        bail!("Debugger session was cancelled; retained events are partial");
    }
    if report.timed_out {
        bail!("Debugger session timed out; retained events are partial");
    }

    match report.exit {
        ExitOutcome::Exited { code: 0 } => Ok(()),
        _ => bail!("Debug target did not exit successfully: {:?}", report.exit),
    }
}

fn save_debug(args: &Args, evidence: &Evidence<DebugReport>) -> Result<()> {
    if matches!(args.format, ReportFormat::Json | ReportFormat::Both) {
        let path = args.output_dir.join("debug.json");
        let bytes = serde_json::to_vec_pretty(evidence)?;

        std::fs::write(&path, bytes)
            .with_context(|| format!("Cannot write debugger report {}", path.display()))?;
    }

    Ok(())
}
