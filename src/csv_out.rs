//! CSV output for benchmark rows: one row per attempt, with proper escaping.

use std::fs::File;
use std::io::{self, BufWriter, Write};

use crate::types::BenchRow;

pub(crate) fn write_csv_row(writer: &mut BufWriter<File>, row: &BenchRow) -> io::Result<()> {
    writeln!(
        writer,
        "{},{},{},{},{:.2},{},{},{}",
        row.attempt_idx,
        row.round,
        csv_escape(&row.ssid),
        row.crowd,
        row.elapsed.as_secs_f64() * 1000.0,
        row.ok,
        row.timed_out,
        csv_escape(&row.detail),
    )
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_quotes_special_characters() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("with,comma"), "\"with,comma\"");
        assert_eq!(csv_escape("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(csv_escape("multi\nline"), "\"multi\nline\"");
    }
}
