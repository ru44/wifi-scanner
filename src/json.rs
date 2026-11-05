//! A tiny zero-dependency helper for emitting `--json` output.
//!
//! The scan/analyze/link data is flat enough that we build the JSON by hand;
//! this just keeps string escaping correct and in one place.

/// Returns `value` as a quoted, escaped JSON string.
pub(crate) fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `Some(n)` becomes the bare number; `None` becomes `null`.
pub(crate) fn num<T: std::fmt::Display>(value: Option<T>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

/// `Some(s)` becomes a quoted string; `None` becomes `null`.
pub(crate) fn opt_str(value: Option<&str>) -> String {
    match value {
        Some(s) => quote(s),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_escapes() {
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("tab\tnl\n"), "\"tab\\tnl\\n\"");
        assert_eq!(quote("\u{1b}"), "\"\\u001b\"");
    }

    #[test]
    fn numbers_and_nulls() {
        assert_eq!(num(Some(42)), "42");
        assert_eq!(num::<i32>(None), "null");
        assert_eq!(opt_str(Some("hi")), "\"hi\"");
        assert_eq!(opt_str(None), "null");
    }
}
