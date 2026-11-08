//! Credential detection. Matches are only ever reported in redacted form.

use regex::Regex;
use std::sync::LazyLock;

pub struct SecretMatch {
    pub kind: &'static str,
    pub redacted: String,
}

static PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("AWS access key id", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        (
            "GitHub token",
            r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b",
        ),
        ("GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
        ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
        ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
        (
            "OpenAI-style API key",
            r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b",
        ),
        ("Stripe secret key", r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
        ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        ("Private key", r"-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----"),
        (
            "JSON Web Token",
            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        ),
        (
            "Credentials in URL",
            r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^/\s@]{3,}@",
        ),
        ("Bearer token", r"(?i)\bbearer\s+[A-Za-z0-9_\-.=]{16,}"),
    ]
    .into_iter()
    .map(|(k, p)| (k, Regex::new(p).expect("valid secret regex")))
    .collect()
});

static SENSITIVE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(token|secret|passw(or)?d|passwd|api[_\-]?key|private[_\-]?key|credential|auth|access[_\-]?key|client[_\-]?secret|session)")
        .expect("valid regex")
});

/// Values that reference a secret indirectly instead of embedding it.
pub fn is_reference(value: &str) -> bool {
    let v = value.trim();
    v.is_empty()
        || v.starts_with("${")
        || v.starts_with("$(")
        || v.starts_with("{{")
        || v.starts_with("%") && v.ends_with('%')
        || (v.starts_with('$')
            && v[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'))
        || v.starts_with("op://")
        || v.starts_with("vault:")
        || v.starts_with("secretsmanager:")
        || v.starts_with("env:")
        || v.eq_ignore_ascii_case("<redacted>")
        || v.chars().all(|c| c == '*' || c == 'x' || c == 'X')
        || v.starts_with('<') && v.ends_with('>')
}

/// Scan a free-form value for known credential formats.
pub fn scan_value(value: &str) -> Option<SecretMatch> {
    for (kind, re) in PATTERNS.iter() {
        if let Some(m) = re.find(value) {
            return Some(SecretMatch {
                kind,
                redacted: crate::util::redact(m.as_str()),
            });
        }
    }
    None
}

/// Scan a key/value pair (env var, header). A sensitive key name with a
/// literal (non-reference) value is treated as a hardcoded credential.
pub fn scan_pair(key: &str, value: &str) -> Option<SecretMatch> {
    if is_reference(value) {
        return None;
    }
    if let Some(m) = scan_value(value) {
        return Some(m);
    }
    let value = value.trim();
    if SENSITIVE_KEY.is_match(key)
        && value.len() >= 8
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "false" | "enabled" | "disabled" | "required" | "optional" | "none"
        )
    {
        return Some(SecretMatch {
            kind: "Hardcoded credential",
            redacted: crate::util::redact(value),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_formats() {
        assert_eq!(
            scan_value("AKIAIOSFODNN7EXAMPLE").unwrap().kind,
            "AWS access key id"
        );
        assert_eq!(
            scan_value("ghp_0123456789abcdefghijklmnopqrstuvwxyzAB")
                .unwrap()
                .kind,
            "GitHub token"
        );
        assert_eq!(
            scan_value("postgres://admin:s3cr3t@db:5432/app")
                .unwrap()
                .kind,
            "Credentials in URL"
        );
        assert!(scan_value("just a normal string").is_none());
    }

    #[test]
    fn redacts_matches() {
        let m = scan_value("token=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB").unwrap();
        assert!(!m.redacted.contains("0123456789abcdef"));
    }

    #[test]
    fn references_are_not_secrets() {
        assert!(scan_pair("GITHUB_TOKEN", "${input:github_token}").is_none());
        assert!(scan_pair("API_KEY", "$API_KEY").is_none());
        assert!(scan_pair("API_KEY", "${env:API_KEY}").is_none());
        assert!(scan_pair("API_KEY", "<your-key-here>").is_none());
        assert!(scan_pair("DB_PASSWORD", "correct-horse-battery").is_some());
        assert!(scan_pair("LOG_LEVEL", "debug-verbose-mode").is_none());
        assert!(scan_pair("AUTH_REQUIRED", "required").is_none());
    }
}
