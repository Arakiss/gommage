use std::io::{self, IsTerminal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UiStatus {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum UiTone {
    Teal,
    Gold,
    Green,
    Red,
    Muted,
}

impl UiStatus {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }

    pub(crate) fn marker(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }

    pub(crate) fn tone(self) -> UiTone {
        match self {
            Self::Ok => UiTone::Green,
            Self::Warn => UiTone::Gold,
            Self::Fail => UiTone::Red,
            Self::Skip => UiTone::Muted,
        }
    }

    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Skip => 1,
            Self::Warn => 2,
            Self::Fail => 3,
        }
    }
}

pub(crate) fn color_enabled() -> bool {
    io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").map_or(true, |term| term != "dumb")
}

pub(crate) fn paint(text: impl AsRef<str>, tone: UiTone, bold: bool, colors: bool) -> String {
    let text = text.as_ref();
    if !colors {
        return text.to_string();
    }

    let mut codes = Vec::new();
    if bold {
        codes.push("1".to_string());
    }
    codes.push(tone.ansi_code().to_string());
    format!("\x1b[{}m{text}\x1b[0m", codes.join(";"))
}

impl UiTone {
    fn ansi_code(self) -> &'static str {
        match self {
            Self::Teal => "38;2;0;179;164",
            Self::Gold => "38;2;244;185;66",
            Self::Green => "32",
            Self::Red => "31",
            Self::Muted => "90",
        }
    }
}
