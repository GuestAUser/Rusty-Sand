use anyhow::Result;

/** Keep the operation error and every cleanup error instead of short-circuiting. */
pub(crate) fn with_cleanup<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            let summary = format!("{error:#}; cleanup also failed: {cleanup:#}");
            Err(error.context(summary))
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/sandbox_cleanup.rs"]
mod tests;
