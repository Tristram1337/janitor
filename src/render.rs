//! Shared rendering primitives.
//!
//! This module owns the presentation layer: color palette, permission-line
//! rendering, section headers, key-value blocks, rustc-style diagnostic
//! boxes (error/warning/note/hint), summary lines, table builder, and
//! `indicatif` progress helpers.
//!
//! All user-facing commands should go through these primitives so the CLI
//! stays visually coherent. Colors are supplementary: layout, glyphs, and
//! badge text always carry the signal on their own, which means output
//! remains readable under `--color=never`, `NO_COLOR=1`, or when piped to
//! a file.
//!
//! See `context.md` §4 (UX principles) and `designs/DESIGN-TOKENS.md` for
//! the role vocabulary this module implements.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use owo_colors::OwoColorize;
use tabled::builder::Builder as TableBuilder;
use tabled::settings::object::Columns;
use tabled::settings::{Alignment, Modify, Padding, Style as TableStyle};

use crate::cli::ColorMode;

// ── Global color / glyph state ─────────────────────────────────────────

/// 0 = not yet initialized (use auto), 1 = colors on, 2 = colors off.
static COLOR_STATE: AtomicU8 = AtomicU8::new(0);
/// 0 = not yet initialized, 1 = unicode glyphs, 2 = ascii glyphs.
static GLYPH_STATE: AtomicU8 = AtomicU8::new(0);

/// Initialize color output for the process. Call once early in `main`.
///
/// `Auto` enables colors only when stdout is a terminal and `$TERM` is not
/// `dumb` and `$NO_COLOR` is unset. `Always` forces on, `Never` forces off.
pub fn init_color(mode: ColorMode) {
    let on = match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            if std::env::var_os("NO_COLOR").is_some() {
                false
            } else if std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false) {
                false
            } else {
                std::io::stdout().is_terminal()
            }
        }
    };
    COLOR_STATE.store(if on { 1 } else { 2 }, Ordering::Relaxed);
}

/// Initialize glyph set (unicode vs ascii). Call once early in `main`.
///
/// Heuristic: unicode when `$LANG` / `$LC_ALL` contains `UTF-8`, else ASCII.
pub fn init_glyphs() {
    let has_utf8 = ["LC_ALL", "LANG", "LC_CTYPE"].iter().any(|k| {
        std::env::var(k)
            .map(|v| v.to_uppercase().contains("UTF-8") || v.to_uppercase().contains("UTF8"))
            .unwrap_or(false)
    });
    GLYPH_STATE.store(if has_utf8 { 1 } else { 2 }, Ordering::Relaxed);
}

/// True when colors should be emitted. Defaults to `false` if not initialized.
pub fn colors_on() -> bool {
    COLOR_STATE.load(Ordering::Relaxed) == 1
}

fn unicode_glyphs() -> bool {
    // Default to unicode if not initialized; matches most modern locales.
    GLYPH_STATE.load(Ordering::Relaxed) != 2
}

// ── Palette ────────────────────────────────────────────────────────────

/// Semantic color role. See `designs/DESIGN-TOKENS.md` for the complete
/// vocabulary. Each command uses these roles rather than raw ANSI codes,
/// so changing a role recolors every place it appears.
#[derive(Clone, Copy)]
pub enum Style {
    /// Main identifier (file name, mode value, primary path).
    Primary,
    /// Column headers, key labels — dimmed default foreground.
    Label,
    /// Usernames.
    User,
    /// Group names.
    Group,
    /// Directory name in a listing.
    Dir,
    /// Symlink name.
    Link,
    /// Positive / allowed (green).
    Ok,
    /// Traverse-only capability (cyan).
    Traverse,
    /// Negative / denied (dim red).
    Deny,
    /// Elevated warning (setuid, world-writable) — bold yellow.
    WarnMajor,
    /// Severe: SUID root, orphan UID, 0777 — bold red.
    Danger,
    /// Path-chain or query highlight — bold yellow.
    Highlight,
    /// ACL marker (italic cyan).
    AclMarker,
    /// Separators, rules, connectors — dim.
    Separator,
    /// Completed mutations, summary OK.
    Success,
    /// Backup id hash.
    BackupId,
}

/// Paint `text` in `style` if colors are on, else return plain text.
pub fn paint(style: Style, text: &str) -> String {
    if !colors_on() {
        return text.to_string();
    }
    match style {
        Style::Primary => text.to_string(),
        Style::Label => text.dimmed().to_string(),
        // Users, groups, dirs and ids intentionally ship plain — color
        // is reserved for semantic signals (ok/warn/danger), not for
        // every noun we paint. Keeps dense output from feeling loud.
        Style::User => text.to_string(),
        Style::Group => text.to_string(),
        Style::Dir => text.to_string(),
        Style::Link => text.to_string(),
        Style::Ok => text.green().to_string(),
        Style::Traverse => text.dimmed().to_string(),
        Style::Deny => text.red().dimmed().to_string(),
        Style::WarnMajor => text.yellow().to_string(),
        Style::Danger => text.red().to_string(),
        Style::Highlight => text.bold().to_string(),
        Style::AclMarker => text.dimmed().to_string(),
        Style::Separator => text.dimmed().to_string(),
        Style::Success => text.green().to_string(),
        Style::BackupId => text.to_string(),
    }
}

// ── Glyphs ─────────────────────────────────────────────────────────────

pub struct Glyphs {
    pub header_marker: &'static str, // `▸` or `>`
    pub bullet_filled: &'static str, // `●` or `[x]`
    pub bullet_empty: &'static str,  // `○` or `[ ]`
    pub warn: &'static str,          // `⚠` or `[!]`
    pub check: &'static str,         // `✓` or `[ok]`
    pub cross: &'static str,         // `✗` or `[X]`
    pub arrow_right: &'static str,   // `→` or `->`
    pub midot: &'static str,         // `·` or `-`
    pub rule_char: &'static str,     // `─` or `-`
    pub tree_mid: &'static str,      // `├─ ` or `|- `
    pub tree_last: &'static str,     // `└─ ` or `\- `
    pub tree_vert: &'static str,     // `│  ` or `|  `
}

const GLYPHS_UNICODE: Glyphs = Glyphs {
    header_marker: "▸",
    bullet_filled: "●",
    bullet_empty: "○",
    warn: "⚠",
    check: "✓",
    cross: "✗",
    arrow_right: "→",
    midot: "·",
    rule_char: "─",
    tree_mid: "├─ ",
    tree_last: "└─ ",
    tree_vert: "│  ",
};

const GLYPHS_ASCII: Glyphs = Glyphs {
    header_marker: ">",
    bullet_filled: "[x]",
    bullet_empty: "[ ]",
    warn: "[!]",
    check: "[ok]",
    cross: "[X]",
    arrow_right: "->",
    midot: "-",
    rule_char: "-",
    tree_mid: "|- ",
    tree_last: "\\- ",
    tree_vert: "|  ",
};

pub fn glyphs() -> &'static Glyphs {
    if unicode_glyphs() {
        &GLYPHS_UNICODE
    } else {
        &GLYPHS_ASCII
    }
}

// ── Small building blocks ─────────────────────────────────────────────

/// A horizontal rule `─────…` of the given width, styled as `Separator`.
pub fn rule(width: usize) -> String {
    let ch = glyphs().rule_char;
    let raw: String = ch.repeat(width);
    paint(Style::Separator, &raw)
}

/// Card / section header: `▸ <title>  ·  <kind>  [badge] [badge]`.
///
/// `title` is painted `Primary`, `kind` is painted `Label`, each badge is
/// passed through `badge()` already. Leading `▸` is `Separator`.
pub fn header_line(title: &str, kind: Option<&str>, badges: &[String]) -> String {
    let g = glyphs();
    let mut s = String::new();
    s.push_str(&paint(Style::Separator, g.header_marker));
    s.push(' ');
    s.push_str(&paint(Style::Primary, title));
    if let Some(k) = kind {
        s.push_str("  ");
        s.push_str(&paint(Style::Separator, g.midot));
        s.push_str("  ");
        s.push_str(&paint(Style::Label, k));
    }
    for b in badges {
        s.push(' ');
        s.push_str(b);
    }
    s
}

/// Render a `[foo]` badge in the given style (e.g. `[setuid]` → `WarnMajor`).
pub fn badge(text: &str, style: Style) -> String {
    paint(style, &format!("[{text}]"))
}

/// A section title line like `ACL` (label, slightly emphasized).
pub fn section_title(title: &str) -> String {
    paint(Style::Label, title)
}

/// One key-value row, `key` padded to `key_width` columns on the left,
/// value on the right. Key is `Label`, value is caller-supplied (already
/// painted if needed).
pub fn kv(key: &str, value: &str, key_width: usize) -> String {
    let pad = key_width.saturating_sub(key.chars().count());
    format!("{}{}{}", paint(Style::Label, key), " ".repeat(pad + 1), value)
}

/// Two side-by-side kv pairs on the same line, each column `col_width` wide
/// from the start of the key to the end of the value. Useful for card
/// layouts: `owner  alice  (uid 1001)   mode   0640 · -rw-r-----`.
pub fn kv_pair(
    left: (&str, &str),
    right: (&str, &str),
    key_width: usize,
    col_width: usize,
) -> String {
    let left_raw = format!(
        "{}{}{}",
        left.0,
        " ".repeat(key_width.saturating_sub(left.0.chars().count()) + 1),
        strip_ansi_width_str(left.1)
    );
    let visual_len = visible_width(&left_raw);
    let pad = col_width.saturating_sub(visual_len).max(2);
    let mut s = String::new();
    s.push_str(&paint(Style::Label, left.0));
    s.push_str(&" ".repeat(key_width.saturating_sub(left.0.chars().count()) + 1));
    s.push_str(left.1);
    s.push_str(&" ".repeat(pad));
    s.push_str(&paint(Style::Label, right.0));
    s.push_str(&" ".repeat(key_width.saturating_sub(right.0.chars().count()) + 1));
    s.push_str(right.1);
    s
}

/// Return a visual width estimate for a string that may contain ANSI
/// escapes (stripped) — character count only, not grapheme-aware.
fn strip_ansi_width_str(s: &str) -> String {
    // Minimal ANSI CSI stripper: drops `ESC[...m` sequences, keeps
    // everything else. Good enough for width estimation of our own output.
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            if let Some('[') = it.peek().copied() {
                it.next();
                for c2 in it.by_ref() {
                    if c2.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(c);
    }
    out
}

// ── Permission line (shared across info / tree / audit / find / …) ────

/// Input for `permission_line`. All fields are raw filesystem values —
/// this struct does not know about users, only ids. Callers resolve names
/// upstream so this function is pure formatting.
pub struct PermEntry<'a> {
    pub mode: u32,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub user: &'a str,
    pub group: &'a str,
    pub uid: u32,
    pub gid: u32,
    pub user_orphan: bool,
    pub group_orphan: bool,
    pub size: u64,
    pub acl_present: bool,
    pub name: &'a str,
}

/// Options controlling which fields appear on a permission line.
#[derive(Default, Clone, Copy)]
pub struct PermOpts {
    pub show_size: bool,
    pub show_ids: bool,
}

/// Render the canonical single-line permission summary used across the
/// inspect commands:
///
/// ```text
/// -rw-r-----  alice:finance  4.2 KB  name
/// ```
///
/// The mode uses the classic ls-style 10-char `drwxr-xr-x`. Special-bit
/// letters (`s`, `S`, `t`, `T`) inside the mode string are painted
/// `WarnMajor` so setuid/setgid/sticky flags stand out even without
/// reading the octal.
pub fn permission_line(entry: &PermEntry<'_>, opts: &PermOpts) -> String {
    let symbolic = format_symbolic(entry.mode, entry.is_dir, entry.is_symlink);
    let symbolic_colored = color_symbolic(&symbolic);

    let user_style = if entry.user_orphan {
        Style::Danger
    } else {
        Style::User
    };
    let group_style = if entry.group_orphan {
        Style::Danger
    } else {
        Style::Group
    };
    let mut owner = String::new();
    owner.push_str(&paint(user_style, entry.user));
    owner.push_str(&paint(Style::Separator, ":"));
    owner.push_str(&paint(group_style, entry.group));
    if opts.show_ids {
        let ids = format!(" ({}:{})", entry.uid, entry.gid);
        owner.push_str(&paint(Style::Label, &ids));
    }

    let name_style = if entry.is_symlink {
        Style::Link
    } else if entry.is_dir {
        Style::Dir
    } else {
        Style::Primary
    };
    let name = paint(name_style, entry.name);

    let mut s = format!("{}  {}", symbolic_colored, owner);

    if opts.show_size {
        let size = format_size(entry.size);
        s.push_str("  ");
        s.push_str(&paint(Style::Label, &size));
    }

    if entry.acl_present {
        s.push(' ');
        s.push_str(&paint(Style::AclMarker, "+acl"));
    }

    s.push_str("  ");
    s.push_str(&name);
    s
}

/// `drwxr-xr-x`-style 10-char mode. First char is the type, next 9 are
/// the standard owner/group/other triads with `s`/`S`/`t`/`T` for
/// setuid/setgid/sticky.
pub fn format_symbolic(mode: u32, is_dir: bool, is_symlink: bool) -> String {
    let type_char = if is_symlink {
        'l'
    } else if is_dir {
        'd'
    } else {
        '-'
    };
    let mut s = String::with_capacity(10);
    s.push(type_char);
    let r = |bit: u32| if mode & bit != 0 { 'r' } else { '-' };
    let w = |bit: u32| if mode & bit != 0 { 'w' } else { '-' };
    s.push(r(0o400));
    s.push(w(0o200));
    s.push(match (mode & 0o100 != 0, mode & 0o4000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s.push(r(0o040));
    s.push(w(0o020));
    s.push(match (mode & 0o010 != 0, mode & 0o2000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s.push(r(0o004));
    s.push(w(0o002));
    s.push(match (mode & 0o001 != 0, mode & 0o1000 != 0) {
        (true, true) => 't',
        (false, true) => 'T',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s
}

fn color_symbolic(sym: &str) -> String {
    if !colors_on() {
        return sym.to_string();
    }
    // Keep it quiet: letters plain, dashes dim, and highlight the special
    // bits (s/S/t/T) in yellow so setuid/sticky still pop.
    let mut out = String::new();
    for c in sym.chars() {
        match c {
            's' | 'S' | 't' | 'T' => out.push_str(&paint(Style::WarnMajor, &c.to_string())),
            '-' => out.push_str(&paint(Style::Separator, "-")),
            _ => out.push(c),
        }
    }
    out
}

/// Convenience: compute `format_symbolic` then color-paint it, same
/// rules as `permission_line` uses internally.
pub fn mode_symbolic_colored(mode: u32, is_dir: bool, is_symlink: bool) -> String {
    color_symbolic(&format_symbolic(mode, is_dir, is_symlink))
}

/// Human-readable byte size: `4.2 KB`, `28 KB`, `1.3 MB`, … (1024-based,
/// labelled with decimal-style units for readability, matching how
/// `ls -h` has been showing these for decades).
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else if v < 10.0 {
        format!("{:.1} {}", v, UNITS[i])
    } else {
        format!("{:.0} {}", v, UNITS[i])
    }
}

// ── Diagnostic boxes (rustc-style) ────────────────────────────────────

/// A rustc-style diagnostic line. Severity controls prefix + color:
/// `error:` / `warning:` / `note:` / `hint:`.
#[derive(Clone, Copy)]
pub enum DiagLevel {
    Error,
    Warning,
    Note,
    Hint,
}

impl DiagLevel {
    fn prefix(self) -> &'static str {
        match self {
            DiagLevel::Error => "error",
            DiagLevel::Warning => "warning",
            DiagLevel::Note => "note",
            DiagLevel::Hint => "hint",
        }
    }
    fn style(self) -> Style {
        match self {
            DiagLevel::Error => Style::Danger,
            DiagLevel::Warning => Style::WarnMajor,
            DiagLevel::Note => Style::Label,
            DiagLevel::Hint => Style::Traverse,
        }
    }
}

/// Build a rustc-style block:
///
/// ```text
/// error: permission denied
///   --> /srv/acme/finance/q3.xlsx
///   = while: applying chmod 0640
///   = help:  sudo janitor chmod 0640 /srv/acme/finance/q3.xlsx
/// ```
///
/// `locator` is the path (rendered after `-->`). Each entry in `notes` is
/// rendered as `= key: body`. Omit `locator` / `notes` by passing `None` /
/// empty slice.
pub fn diag(
    level: DiagLevel,
    message: &str,
    locator: Option<&str>,
    notes: &[(&str, &str)],
) -> String {
    let mut s = String::new();
    let head = format!("{}: ", level.prefix());
    s.push_str(&paint(level.style(), &head));
    s.push_str(message);
    if let Some(loc) = locator {
        s.push('\n');
        s.push_str("  ");
        s.push_str(&paint(Style::Separator, "-->"));
        s.push(' ');
        s.push_str(&paint(Style::Primary, loc));
    }
    for (k, v) in notes {
        s.push('\n');
        s.push_str("  ");
        s.push_str(&paint(Style::Separator, "="));
        s.push(' ');
        s.push_str(&paint(Style::Label, &format!("{k}:")));
        s.push(' ');
        s.push_str(v);
    }
    s
}

/// Convenience: write a diagnostic to stderr with trailing newline.
pub fn eprint_diag(level: DiagLevel, message: &str, locator: Option<&str>, notes: &[(&str, &str)]) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{}", diag(level, message, locator, notes));
}

// ── Summary line ──────────────────────────────────────────────────────

/// Render a one-line operation summary:
///
/// ```text
/// 47 scanned · 3 matched · 2 warnings · 312 ms
/// ```
///
/// Each `(count, label)` pair appears only if `count > 0` (or if
/// `always_show` is true via `summary_pair_always`). Empty segments are
/// skipped so the separator stays clean.
pub fn summary_line(segments: &[(&str, &str)]) -> String {
    let g = glyphs();
    let sep = format!(" {} ", paint(Style::Separator, g.midot));
    let mut parts: Vec<String> = Vec::new();
    for (count, label) in segments {
        if count.is_empty() {
            continue;
        }
        let mut seg = String::new();
        seg.push_str(&paint(Style::Primary, count));
        seg.push(' ');
        seg.push_str(&paint(Style::Label, label));
        parts.push(seg);
    }
    parts.join(&sep)
}

/// Shortcut: write a summary to stderr with trailing newline.
pub fn eprint_summary(segments: &[(&str, &str)]) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{}", summary_line(segments));
}

/// Visible width of a string that may contain ANSI CSI SGR escape
/// sequences. Strips `\x1b[…m` and counts remaining chars.
pub fn visible_width(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut w = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() {
                let c = bytes[i];
                i += 1;
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            // Count UTF-8 char boundary
            let c = bytes[i];
            let step = if c < 0x80 {
                1
            } else if c < 0xC0 {
                1
            } else if c < 0xE0 {
                2
            } else if c < 0xF0 {
                3
            } else {
                4
            };
            i += step;
            w += 1;
        }
    }
    w
}

/// Pad `cell` (which may contain ANSI codes) with spaces on the right so
/// its visible width reaches `width`. If already ≥ width, returns the
/// original string unchanged.
pub fn pad_right(cell: &str, width: usize) -> String {
    let w = visible_width(cell);
    if w >= width {
        cell.to_string()
    } else {
        let mut s = cell.to_string();
        s.push_str(&" ".repeat(width - w));
        s
    }
}

/// Render a fixed-column table where the caller has pre-painted cells.
/// Column widths are computed from the visible width of the header + all
/// cells. Unlike `simple_table`, this respects ANSI escape codes and
/// never misaligns. Columns are separated by a 2-space gutter.
pub fn aligned_table(header: &[&str], rows: &[Vec<String>]) -> String {
    let cols = header.len();
    let mut widths: Vec<usize> = header.iter().map(|h| visible_width(h)).collect();
    for r in rows {
        for (i, cell) in r.iter().enumerate().take(cols) {
            let w = visible_width(cell);
            if w > widths[i] {
                widths[i] = w;
            }
        }
    }
    let mut out = String::new();
    // Header
    for (i, h) in header.iter().enumerate() {
        let padded = pad_right(&paint(Style::Label, h), widths[i]);
        out.push_str(&padded);
        if i + 1 < cols {
            out.push_str("  ");
        }
    }
    out.push('\n');
    // Rows
    for r in rows {
        for (i, cell) in r.iter().enumerate().take(cols) {
            let w = if i + 1 < cols {
                widths[i]
            } else {
                0 // last column: don't pad trailing
            };
            let padded = if w > 0 { pad_right(cell, w) } else { cell.clone() };
            out.push_str(&padded);
            if i + 1 < cols {
                out.push_str("  ");
            }
        }
        out.push('\n');
    }
    out
}

// ── Table wrapper (around `tabled`) ───────────────────────────────────

/// Build a left-aligned, padded table from a header row and rows of
/// already-formatted cells. No borders; minimal visual chrome — matches
/// the "dense but breathable" style used by `eza`, `ripgrep`.
///
/// Caller is responsible for paint()-ing cells before passing them in.
pub fn simple_table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut builder = TableBuilder::default();
    let header_row: Vec<String> = header
        .iter()
        .map(|h| paint(Style::Label, h))
        .collect();
    builder.push_record(header_row);
    for r in rows {
        builder.push_record(r.clone());
    }
    let mut table = builder.build();
    table
        .with(TableStyle::blank())
        .with(Modify::new(Columns::new(..)).with(Padding::new(0, 2, 0, 0)))
        .with(Modify::new(Columns::new(..)).with(Alignment::left()));
    table.to_string()
}

// ── Progress (indicatif wrappers) ─────────────────────────────────────

/// Create an indeterminate spinner progress bar on stderr. Returns an
/// already-enabled `ProgressBar`; call `finish_progress` on it when done.
///
/// Auto-disables (returns a hidden bar) when stderr is not a terminal or
/// `$NO_COLOR` / `--color=never` forced colors off — keeps pipe output
/// clean.
pub fn spinner(message: &str) -> indicatif::ProgressBar {
    if !std::io::stderr().is_terminal() {
        return indicatif::ProgressBar::hidden();
    }
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(
        indicatif::ProgressStyle::with_template("  {spinner} {msg}")
            .unwrap_or_else(|_| indicatif::ProgressStyle::default_spinner())
            .tick_chars(if unicode_glyphs() {
                "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "
            } else {
                "|/-\\ "
            }),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb
}

/// Create a determinate progress bar on stderr with `total` units.
/// Auto-disables in non-TTY / no-color contexts.
pub fn bar(total: u64, message: &str) -> indicatif::ProgressBar {
    if !std::io::stderr().is_terminal() {
        return indicatif::ProgressBar::hidden();
    }
    let pb = indicatif::ProgressBar::new(total);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "  {msg:<30} [{bar:30}] {pos}/{len}  {per_sec}  ETA {eta}",
        )
        .unwrap_or_else(|_| indicatif::ProgressStyle::default_bar())
        .progress_chars(if unicode_glyphs() { "█░ " } else { "#- " }),
    );
    pb.set_message(message.to_string());
    pb
}

/// Finish a progress bar, replacing its last frame with a single-line
/// success message on stderr.
pub fn finish_progress(pb: &indicatif::ProgressBar, message: &str) {
    let g = glyphs();
    let final_msg = format!(
        "  {} {}",
        paint(Style::Success, g.check),
        paint(Style::Primary, message)
    );
    pb.finish_with_message(final_msg);
}

// ── Convenience writers ───────────────────────────────────────────────

/// Write a line to stdout; used so commands can opt out of `println!`
/// macros (which lock on every call) in hot loops if needed.
pub fn out_line(line: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{line}");
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn force_off() {
        COLOR_STATE.store(2, Ordering::Relaxed);
        GLYPH_STATE.store(1, Ordering::Relaxed);
    }

    #[test]
    fn symbolic_mode_basic() {
        assert_eq!(format_symbolic(0o755, true, false), "drwxr-xr-x");
        assert_eq!(format_symbolic(0o644, false, false), "-rw-r--r--");
        assert_eq!(format_symbolic(0o777, false, true), "lrwxrwxrwx");
    }

    #[test]
    fn symbolic_special_bits() {
        assert_eq!(format_symbolic(0o4755, false, false), "-rwsr-xr-x");
        assert_eq!(format_symbolic(0o4644, false, false), "-rwSr--r--");
        assert_eq!(format_symbolic(0o2755, true, false), "drwxr-sr-x");
        assert_eq!(format_symbolic(0o1777, true, false), "drwxrwxrwt");
    }

    #[test]
    fn size_formatting() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(4096), "4.0 KB");
        assert_eq!(format_size(4200), "4.1 KB");
        assert_eq!(format_size(1_500_000), "1.4 MB");
        assert_eq!(format_size(28 * 1024), "28 KB");
    }

    #[test]
    fn plain_output_when_colors_off() {
        force_off();
        assert_eq!(paint(Style::User, "alice"), "alice");
        assert_eq!(paint(Style::Danger, "!"), "!");
    }

    #[test]
    fn diag_layout_plain() {
        force_off();
        let s = diag(
            DiagLevel::Error,
            "permission denied",
            Some("/srv/acme/x"),
            &[("help", "sudo janitor ...")],
        );
        assert!(s.starts_with("error: permission denied"));
        assert!(s.contains("--> /srv/acme/x"));
        assert!(s.contains("= help: sudo janitor ..."));
    }

    #[test]
    fn summary_plain() {
        force_off();
        let s = summary_line(&[("47", "scanned"), ("3", "matched"), ("", "skipped")]);
        assert_eq!(s, "47 scanned · 3 matched");
    }

    #[test]
    fn kv_alignment() {
        force_off();
        let s = kv("owner", "alice", 8);
        assert_eq!(s, "owner    alice");
    }

    #[test]
    fn strip_ansi_width_works() {
        let colored = "\x1b[1;32mhi\x1b[0m";
        assert_eq!(visible_width(colored), 2);
    }

    #[test]
    fn permission_line_plain() {
        force_off();
        let e = PermEntry {
            mode: 0o640,
            is_dir: false,
            is_symlink: false,
            user: "alice",
            group: "finance",
            uid: 1001,
            gid: 2001,
            user_orphan: false,
            group_orphan: false,
            size: 4200,
            acl_present: false,
            name: "q3.xlsx",
        };
        let opts = PermOpts {
            show_size: true,
            show_ids: false,
        };
        let out = permission_line(&e, &opts);
        assert_eq!(out, "-rw-r-----  alice:finance  4.1 KB  q3.xlsx");
    }
}
