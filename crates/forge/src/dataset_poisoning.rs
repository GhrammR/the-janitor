//! Low-memory streaming detector for poisoned training-data trigger suffixes.

use std::collections::HashMap;

use common::slop::StructuredFinding;
use serde_json::Value;

const MIN_SUFFIX_CHARS: usize = 4;
const MIN_REPEATED_ROWS: usize = 3;

/// Stream `.jsonl` and `.csv` datasets and emit a KevCritical finding when the
/// same hidden trigger suffix repeats across multiple rows.
pub fn detect_training_data_trojan(
    ext: &str,
    source: &[u8],
    file_path: &str,
) -> Vec<StructuredFinding> {
    if !matches!(ext, "jsonl" | "csv") {
        return Vec::new();
    }

    let mut suffixes: HashMap<String, (u32, usize)> = HashMap::new();
    for (line_no, text) in stream_text_fields(ext, source) {
        if let Some(suffix) = hidden_trigger_suffix(&text) {
            let entry = suffixes.entry(suffix).or_insert((line_no, 0));
            entry.1 += 1;
        }
    }

    let Some((suffix, (line, count))) = suffixes
        .into_iter()
        .find(|(_, (_, count))| *count >= MIN_REPEATED_ROWS)
    else {
        return Vec::new();
    };

    vec![StructuredFinding {
        id: "security:training_data_trojan".to_string(),
        file: Some(file_path.to_string()),
        line: Some(line),
        fingerprint: blake3::hash(suffix.as_bytes()).to_hex().to_string(),
        severity: Some("KevCritical".to_string()),
        remediation: Some(format!(
            "Reject repeated hidden trigger suffixes before the next training cycle. The identical invisible suffix {:?} appears in {count} rows and is consistent with a trojan backdoor trigger.",
            suffix
        )),
        ..Default::default()
    }]
}

fn stream_text_fields(ext: &str, source: &[u8]) -> Vec<(u32, String)> {
    let mut rows = Vec::new();
    for (idx, line) in source.split(|b| *b == b'\n').enumerate() {
        let line_no = idx as u32 + 1;
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() {
            continue;
        }
        if ext == "jsonl" {
            if let Ok(value) = serde_json::from_slice::<Value>(trimmed) {
                collect_json_strings(&value, line_no, &mut rows);
            }
            continue;
        }
        for cell in split_csv_cells(trimmed) {
            let cell = cell.trim();
            if !cell.is_empty() {
                rows.push((line_no, cell.to_string()));
            }
        }
    }
    rows
}

fn collect_json_strings(value: &Value, line_no: u32, rows: &mut Vec<(u32, String)>) {
    match value {
        Value::String(text) => rows.push((line_no, text.clone())),
        Value::Array(items) => {
            for item in items {
                collect_json_strings(item, line_no, rows);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_json_strings(item, line_no, rows);
            }
        }
        _ => {}
    }
}

fn split_csv_cells(line: &[u8]) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut idx = 0usize;
    while idx < line.len() {
        let byte = line[idx];
        if byte == b'"' {
            if in_quotes && line.get(idx + 1) == Some(&b'"') {
                current.push('"');
                idx += 2;
                continue;
            }
            in_quotes = !in_quotes;
            idx += 1;
            continue;
        }
        if byte == b',' && !in_quotes {
            cells.push(current.trim().to_string());
            current.clear();
            idx += 1;
            continue;
        }
        current.push(byte as char);
        idx += 1;
    }
    cells.push(current.trim().to_string());
    cells
}

fn hidden_trigger_suffix(text: &str) -> Option<String> {
    let suffix: String = text
        .chars()
        .rev()
        .take_while(|ch| is_hidden_trigger_char(*ch))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if suffix.chars().count() >= MIN_SUFFIX_CHARS {
        Some(suffix)
    } else {
        None
    }
}

fn is_hidden_trigger_char(ch: char) -> bool {
    matches!(ch, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_hidden_suffix_in_jsonl_triggers() {
        let suffix = "\u{200B}\u{200C}\u{200D}\u{FEFF}";
        let source = format!(
            "{{\"text\":\"benign{suffix}\"}}\n{{\"text\":\"other{suffix}\"}}\n{{\"text\":\"clean{suffix}\"}}\n"
        );
        let findings =
            detect_training_data_trojan("jsonl", source.as_bytes(), "datasets/train.jsonl");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:training_data_trojan");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn ordinary_csv_rows_are_ignored() {
        let source = b"text,label\nhello world,0\nanother row,1\nclean sample,0\n";
        let findings = detect_training_data_trojan("csv", source, "datasets/train.csv");
        assert!(findings.is_empty());
    }
}
