use std::fmt::Write as _;

use purgo_domain::DisarmReport;

#[must_use]
pub fn report_to_json(report: &DisarmReport) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    let _ = writeln!(s, "  \"format\": \"{}\",", report.format);
    let _ = writeln!(s, "  \"original_size\": {},", report.original_size);
    let _ = writeln!(s, "  \"sanitized_size\": {},", report.sanitized_size);
    let _ = writeln!(s, "  \"modified\": {},", report.is_modified());

    s.push_str("  \"removed\": [");
    for (idx, item) in report.removed.iter().enumerate() {
        s.push_str(if idx == 0 { "\n" } else { ",\n" });
        s.push_str("    {\n");
        let _ = writeln!(s, "      \"location\": \"{}\",", escape(&item.location));
        let _ = writeln!(s, "      \"class\": \"{}\",", item.class.as_str());
        let _ = writeln!(s, "      \"detail\": \"{}\",", escape(&item.detail));
        let _ = writeln!(s, "      \"bytes_removed\": {}", item.bytes_removed);
        s.push_str("    }");
    }
    if report.removed.is_empty() {
        s.push_str("]\n");
    } else {
        s.push_str("\n  ]\n");
    }
    s.push_str("}\n");
    s
}

fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use purgo_domain::{FileFormat, RemovedItem, ThreatClass};

    #[test]
    fn renders_a_report_with_one_removed_item() {
        let report = DisarmReport {
            format: FileFormat::Jpeg,
            original_size: 100,
            sanitized_size: 80,
            removed: vec![RemovedItem::new(
                "segment APP1",
                ThreatClass::Metadata,
                "EXIF",
                20,
            )],
        };
        let json = report_to_json(&report);
        assert!(json.contains("\"format\": \"jpeg\""));
        assert!(json.contains("\"modified\": true"));
        assert!(json.contains("\"class\": \"metadata\""));
        assert!(json.contains("\"bytes_removed\": 20"));
    }

    #[test]
    fn escapes_quotes_and_backslashes() {
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
    }
}
