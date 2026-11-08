//! Small shared helpers: hashing, serde adapters, escaping, redaction, globbing.

use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 16 hex characters of SHA-256 — used for stable finding fingerprints.
pub fn short_hash(s: &str) -> String {
    sha256_hex(s.as_bytes())[..16].to_string()
}

/// Accept either a single value or a list of values.
pub fn one_or_many<'de, D, T>(de: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
        Null(()),
    }
    Ok(match Option::<OneOrMany<T>>::deserialize(de)? {
        None | Some(OneOrMany::Null(())) => Vec::new(),
        Some(OneOrMany::One(v)) => vec![v],
        Some(OneOrMany::Many(v)) => v,
    })
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Redact a credential for display: keep a short prefix so users can
/// recognise which key it is, never the full value.
pub fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let keep = if chars.len() >= 12 { 4 } else { 0 };
    let prefix: String = chars.iter().take(keep).collect();
    format!("{prefix}••••[redacted {} chars]", chars.len())
}

/// Case-insensitive glob match supporting `*` and `?` (IAM action syntax).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Truncate long strings for evidence display.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Convert a serde_json value that may be a string or array of strings.
pub fn str_list(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Minimal percent-decoder (IAM documents in some exports are URL-encoded).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &bytes[i + 1..i + 3];
            if let Ok(b) = u8::from_str_radix(std::str::from_utf8(hex).unwrap_or("zz"), 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*", "iam:PassRole"));
        assert!(glob_match("iam:*", "iam:PassRole"));
        assert!(glob_match("IAM:pass*", "iam:PassRole"));
        assert!(glob_match("iam:?assRole", "iam:PassRole"));
        assert!(!glob_match("s3:*", "iam:PassRole"));
        assert!(!glob_match("iam:Pass", "iam:PassRole"));
    }

    #[test]
    fn redaction_never_leaks_full_value() {
        let r = redact("ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        assert!(r.starts_with("ghp_"));
        assert!(!r.contains("abcdefghijklmnop"));
        let short = redact("hunter2");
        assert!(!short.contains("hunter"));
    }

    #[test]
    fn escape_html() {
        assert_eq!(
            html_escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("%7B%22a%22%3A1%7D"), "{\"a\":1}");
        assert_eq!(percent_decode("100%"), "100%");
    }
}
