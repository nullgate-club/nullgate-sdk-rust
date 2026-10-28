//! Local Akamai input summaries and ordinary-send cookie gates.

use std::{collections::BTreeMap, fmt};

use percent_encoding::percent_decode_str;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Privacy-preserving UTF-16 field summary, serialized in the service's format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InputValue {
    /// JavaScript string length (UTF-16 code units).
    pub length: usize,
    /// SHA-256 of the value's UTF-16 little-endian bytes.
    pub hash: String,
    /// Total, special, ASCII-letter-after-lowercasing, and ASCII-digit counts.
    pub counts: [usize; 4],
}

/// Field attributes and a summary; never the caller's raw password/value.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PreparedInput {
    /// All original attributes other than `value`.
    pub attributes: BTreeMap<String, String>,
    /// Locally prepared value summary.
    pub value: InputValue,
}

impl fmt::Debug for PreparedInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedInput")
            .field("attribute_count", &self.attributes.len())
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

/// Preserve field order/attributes and replace raw values with Python-compatible summaries.
pub fn prepare_inputs(inputs: &[BTreeMap<String, String>]) -> Vec<PreparedInput> {
    inputs
        .iter()
        .map(|field| {
            let value = field.get("value").map_or("", String::as_str);
            let mut digest = Sha256::new();
            let mut length = 0;
            for unit in value.encode_utf16() {
                digest.update(unit.to_le_bytes());
                length += 1;
            }
            let special = value
                .chars()
                .filter(|ch| !ch.is_ascii_alphanumeric() && *ch != '_' && !js_whitespace(*ch))
                .map(char::len_utf16)
                .sum();
            let letters = value
                .chars()
                .flat_map(char::to_lowercase)
                .filter(char::is_ascii_lowercase)
                .count();
            let digits = value.chars().filter(char::is_ascii_digit).count();
            PreparedInput {
                attributes: field
                    .iter()
                    .filter(|(key, _)| key.as_str() != "value")
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
                value: InputValue {
                    length,
                    hash: format!("{:x}", digest.finalize()),
                    counts: [length, special, letters, digits],
                },
            }
        })
        .collect()
}

/// Return the response limit and generation, with unavailable counters represented by -1.
///
/// URI decoding is strict. Integer prefixes follow JavaScript `parseInt`, including
/// the rounding and overflow behavior of IEEE-754 numbers.
pub fn abck_counters(value: Option<&str>) -> (f64, f64) {
    let Some(value) = value else {
        return (-1.0, -1.0);
    };
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return (-1.0, -1.0);
        }
    }
    let Ok(decoded) = percent_decode_str(value).decode_utf8() else {
        return (-1.0, -1.0);
    };
    let mut parts = decoded.split('~');
    let _ = parts.next();
    let Some(limit) = parts.next() else {
        return (-1.0, -1.0);
    };
    let _ = parts.next();
    let Some(generation) = parts.next() else {
        return (-1.0, -1.0);
    };
    (integer_prefix(limit), integer_prefix(generation))
}

/// Whether the ordinary sensor-send gate is closed, not website acceptance.
///
/// `response_count` counts completed target sensor responses in the current cookie
/// generation. An unknown limit keeps the ordinary-send gate open.
pub fn is_enough(value: Option<&str>, response_count: u64) -> bool {
    let (limit, _) = abck_counters(value);
    limit != -1.0 && response_count as f64 >= limit
}

fn integer_prefix(value: &str) -> f64 {
    let value = value.trim_start_matches(js_whitespace);
    let sign = usize::from(value.starts_with('+') || value.starts_with('-'));
    let digits = value[sign..].bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return -1.0;
    }
    value[..sign + digits].parse().unwrap_or(-1.0)
}

fn js_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}
