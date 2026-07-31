//! Log-safe string sanitization
//!
//! Strips control characters (including ANSI escape sequences and newlines)
//! from user-controlled data before it is written to logs, preventing
//! log injection / log forgery attacks (OWASP CRLF injection, ANSI escape
//! confusion).

/// Maximum length for a sanitized log value.
const MAX_LEN: usize = 256;

/// Sanitize a string for safe inclusion in log messages.
///
/// Removes all control characters (codepoints < 0x20, which includes
/// `\n`, `\r`, `\t`, `\x1b` / ESC) and truncates long values.
///
/// # Examples
///
/// ```
/// use kms_core::sanitize::sanitize_for_log;
///
/// assert_eq!(sanitize_for_log("hello"), "hello");
/// assert_eq!(sanitize_for_log("bad\nline"), "badline");
/// assert_eq!(sanitize_for_log("esc\x1b[31mRED"), "esc[31mRED");
/// ```
pub fn sanitize_for_log(s: &str) -> String {
    // Fast-path: most strings are already clean.
    if s.is_empty() {
        return String::new();
    }

    let needs_filter = s.chars().any(|c| c.is_control());
    let needs_truncate = s.len() > MAX_LEN;

    if !needs_filter && !needs_truncate {
        return s.to_string();
    }

    let filtered: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LEN)
        .collect();

    if s.len() > MAX_LEN && filtered.len() >= MAX_LEN {
        format!("{filtered}...")
    } else {
        filtered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_string_unchanged() {
        assert_eq!(sanitize_for_log("hello"), "hello");
    }

    #[test]
    fn empty_string() {
        assert_eq!(sanitize_for_log(""), "");
    }

    #[test]
    fn strips_newlines() {
        assert_eq!(sanitize_for_log("line1\nline2"), "line1line2");
        assert_eq!(sanitize_for_log("line1\r\nline2"), "line1line2");
    }

    #[test]
    fn strips_ansi_escapes() {
        assert_eq!(sanitize_for_log("\x1b[31mRED\x1b[0m"), "[31mRED[0m");
    }

    #[test]
    fn truncates_long_strings() {
        let long = "a".repeat(300);
        let result = sanitize_for_log(&long);
        assert!(result.len() <= MAX_LEN + 3); // may include "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn strips_tabs() {
        assert_eq!(sanitize_for_log("hello\tworld"), "helloworld");
    }

    #[test]
    fn clean_short_returns_same() {
        let s = "normal_string_123";
        let result = sanitize_for_log(s);
        assert_eq!(result, s);
    }
}
