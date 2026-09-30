use super::{ColorMode, OutputPolicy, Tone};

impl OutputPolicy {
    pub(super) fn resolved(self) -> Self {
        self.resolve_environment(
            std::env::var_os("NO_COLOR").is_some(),
            std::env::var_os("TERM").is_some_and(|term| term == "dumb"),
        )
    }

    /* Environment resolution is separate from rendering so isolated terminals
     * and capability tests never need to mutate process-wide environment. */
    pub(super) fn resolve_environment(self, no_color: bool, dumb: bool) -> Self {
        let color = !self.plain
            && match self.color {
                ColorMode::Always => true,
                ColorMode::Never => false,
                ColorMode::Auto => self.tty && !no_color && !dumb,
            };

        Self {
            color: if color {
                ColorMode::Always
            } else {
                ColorMode::Never
            },
            reduced_motion: self.reduced_motion || dumb || !self.tty,
            columns: self.columns.clamp(1, 4096),
            ..self
        }
    }

    pub(super) fn styled(self) -> bool {
        !self.plain && self.color == ColorMode::Always
    }

    pub(super) fn animated(self) -> bool {
        self.styled() && self.tty && !self.reduced_motion && self.columns >= 24
    }

    pub(super) fn width(self) -> usize {
        /* Reserve the last cell to avoid terminal auto-wrap ambiguity. */
        self.columns.clamp(1, 4096).saturating_sub(1).max(1)
    }
}

impl Tone {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Normal => "INFO",
            Self::Heading => "ACTIVE",
            Self::Success => "DONE",
            Self::Warning => "WARNING",
            Self::Danger => "DANGER",
        }
    }

    pub(super) const fn ansi(self) -> &'static str {
        match self {
            Self::Normal => "\x1b[0m",
            Self::Heading => "\x1b[1;38;5;208m",
            Self::Success => "\x1b[1;32m",
            Self::Warning => "\x1b[1;33m",
            Self::Danger => "\x1b[1;31m",
        }
    }
}
