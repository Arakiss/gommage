use std::{
    env,
    io::{self, IsTerminal},
};

pub(crate) struct MascotOptions {
    pub(crate) plain: bool,
    pub(crate) compact: bool,
}

const GOMMAGE_TEAL: &str = "\x1b[38;2;0;179;164m";
const GOMMAGE_GOLD: &str = "\x1b[38;2;242;201;76m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RESET: &str = "\x1b[0m";
const GOMMAGE_LOGO_LINES: &[&str] = &[
    "  ██████╗  ██████╗ ███╗   ███╗███╗   ███╗ █████╗  ██████╗ ███████╗",
    " ██╔════╝ ██╔═══██╗████╗ ████║████╗ ████║██╔══██╗██╔════╝ ██╔════╝",
    " ██║  ███╗██║   ██║██╔████╔██║██╔████╔██║███████║██║  ███╗█████╗",
    " ██║   ██║██║   ██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║██║   ██║██╔══╝",
    " ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗",
    "  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
];

pub(crate) fn print_mascot(options: MascotOptions) {
    let color = mascot_color_enabled(options.plain);
    if options.compact {
        println!("{}", mascot_compact(color));
        return;
    }

    for line in mascot_full(color) {
        println!("{line}");
    }
}

fn mascot_color_enabled(plain: bool) -> bool {
    !plain && env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal()
}

fn paint(text: &str, style: &str, color: bool) -> String {
    if color {
        format!("{style}{text}{ANSI_RESET}")
    } else {
        text.to_owned()
    }
}

fn mascot_compact(color: bool) -> String {
    format!(
        "{} {} {}",
        paint("[Gestral]", GOMMAGE_TEAL, color),
        paint("GOMMAGE policy sentinel", ANSI_BOLD, color),
        paint("tool call -> capabilities -> signed audit", ANSI_DIM, color)
    )
}

fn mascot_full(color: bool) -> Vec<String> {
    let gold = |text: &str| paint(text, GOMMAGE_GOLD, color);
    let bold = |text: &str| paint(text, ANSI_BOLD, color);
    let dim = |text: &str| paint(text, ANSI_DIM, color);

    let mut lines = Vec::new();
    lines.push(format!(
        "{} {} {}",
        bold("Gommage"),
        dim(format!("v{}", env!("CARGO_PKG_VERSION")).as_str()),
        gold("Gestral signature")
    ));
    lines.push(dim("policy decisions with a signed trail"));
    lines.push(String::new());
    for logo_line in GOMMAGE_LOGO_LINES {
        lines.push(gradient_line(logo_line, color));
    }
    lines.extend([
        String::new(),
        format!(
            "        {} {}",
            gold("Gommage Gestral"),
            dim("| policy sentinel")
        ),
        format!(
            "        {} {}",
            bold("Loop:"),
            "tool call -> typed capabilities -> signed audit"
        ),
        format!(
            "        {} {} {} {}",
            bold("Colors:"),
            "Gommage Teal #00B3A4",
            dim("+"),
            gold("Picto Gold #F2C94C")
        ),
        format!("        {} {}", bold("Next:"), "gommage doctor --json"),
    ]);
    lines
}

fn gradient_line(line: &str, color: bool) -> String {
    if !color {
        return line.to_owned();
    }

    let chars: Vec<char> = line.chars().collect();
    let width = chars.len().saturating_sub(1).max(1);
    let mut out = String::new();
    for (index, ch) in chars.iter().enumerate() {
        if ch.is_whitespace() {
            out.push(*ch);
            continue;
        }
        let (r, g, b) = logo_gradient(index, width);
        out.push_str(&format!("\x1b[38;2;{r};{g};{b}m{ch}{ANSI_RESET}"));
    }
    out
}

fn logo_gradient(index: usize, width: usize) -> (u8, u8, u8) {
    const TEAL: (u8, u8, u8) = (0, 179, 164);
    const GOLD: (u8, u8, u8) = (242, 201, 76);
    let numerator = index as u32;
    let denominator = width as u32;
    (
        interpolate_channel(TEAL.0, GOLD.0, numerator, denominator),
        interpolate_channel(TEAL.1, GOLD.1, numerator, denominator),
        interpolate_channel(TEAL.2, GOLD.2, numerator, denominator),
    )
}

fn interpolate_channel(start: u8, end: u8, numerator: u32, denominator: u32) -> u8 {
    let start = start as i32;
    let end = end as i32;
    let delta = end - start;
    (start + (delta * numerator as i32 / denominator as i32)) as u8
}
