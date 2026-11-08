//! Untrusted-input handling: resource limits, safe parsing and format detection.
//!
//! Every artifact is treated as hostile. Nothing in an artifact is ever
//! executed; files are only parsed as data (JSON / YAML) under strict limits.

use crate::model::ArtifactKind;
use serde_json::Value;
use thiserror::Error;

/// Hard limits applied to every artifact.
pub mod limits {
    /// Maximum artifact size in bytes (5 MiB).
    pub const MAX_ARTIFACT_BYTES: usize = 5 * 1024 * 1024;
    /// Maximum number of YAML documents in one file.
    pub const MAX_DOCUMENTS: usize = 5_000;
    /// Maximum nesting depth of a parsed document.
    pub const MAX_DEPTH: usize = 64;
    /// Maximum nodes in a merged graph.
    pub const MAX_NODES: usize = 20_000;
    /// Maximum edges in a merged graph.
    pub const MAX_EDGES: usize = 100_000;
    /// Maximum length of an identifier.
    pub const MAX_ID_LEN: usize = 512;
    /// Maximum depth for path searches.
    pub const MAX_PATH_DEPTH: usize = 16;
    /// Maximum findings emitted per policy.
    pub const MAX_FINDINGS_PER_POLICY: usize = 50;
    /// Maximum artifacts per analysis.
    pub const MAX_ARTIFACTS: usize = 200;
}

#[derive(Debug, Error, PartialEq)]
pub enum InputError {
    #[error("file is too large ({0} bytes, limit is {max} bytes)", max = limits::MAX_ARTIFACT_BYTES)]
    TooLarge(usize),
    #[error("file is empty")]
    Empty,
    #[error("file contains NUL bytes and looks binary")]
    Binary,
    #[error("file is not valid UTF-8 text")]
    NotUtf8,
    #[error("could not parse file as JSON or YAML: {0}")]
    Parse(String),
    #[error("document nesting exceeds {0} levels")]
    TooDeep(usize),
    #[error("too many documents in file (limit {0})")]
    TooManyDocuments(usize),
    #[error("unsupported format: expected a BreachFrame environment, Kubernetes RBAC manifest, AWS IAM policy or MCP configuration")]
    Unsupported,
    #[error("invalid content: {0}")]
    Invalid(String),
    #[error("graph limit exceeded: {0}")]
    Limit(String),
}

/// Validate raw bytes and convert to text.
pub fn validate_bytes(bytes: &[u8]) -> Result<&str, InputError> {
    if bytes.len() > limits::MAX_ARTIFACT_BYTES {
        return Err(InputError::TooLarge(bytes.len()));
    }
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(InputError::Empty);
    }
    if bytes.contains(&0) {
        return Err(InputError::Binary);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| InputError::NotUtf8)?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(text))
}

fn depth(v: &Value) -> usize {
    // Iterative to avoid stack exhaustion on adversarial input.
    let mut max = 0;
    let mut stack = vec![(v, 1usize)];
    while let Some((v, d)) = stack.pop() {
        max = max.max(d);
        if d > limits::MAX_DEPTH {
            return d;
        }
        match v {
            Value::Array(a) => stack.extend(a.iter().map(|x| (x, d + 1))),
            Value::Object(o) => stack.extend(o.values().map(|x| (x, d + 1))),
            _ => {}
        }
    }
    max
}

fn check_depth(v: &Value) -> Result<(), InputError> {
    if depth(v) > limits::MAX_DEPTH {
        Err(InputError::TooDeep(limits::MAX_DEPTH))
    } else {
        Ok(())
    }
}

/// Strip `//` and `/* */` comments plus trailing commas (JSONC, used by
/// VS Code `mcp.json`). String contents are preserved.
pub fn strip_jsonc(text: &str) -> String {
    strip_trailing_commas(&strip_comments(text))
}

fn strip_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_str = false;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_str = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
        }
        if c == ',' {
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j < chars.len() && (chars[j] == '}' || chars[j] == ']') {
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Parse text into one or more documents (JSON, JSONC, or multi-document YAML).
pub fn parse_documents(text: &str) -> Result<Vec<Value>, InputError> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let parsed = serde_json::from_str::<Value>(text)
            .or_else(|_| serde_json::from_str::<Value>(&strip_jsonc(text)));
        if let Ok(v) = parsed {
            check_depth(&v)?;
            return Ok(vec![v]);
        }
    }
    let mut docs = Vec::new();
    for de in serde_yaml::Deserializer::from_str(text) {
        if docs.len() >= limits::MAX_DOCUMENTS {
            return Err(InputError::TooManyDocuments(limits::MAX_DOCUMENTS));
        }
        let v = <Value as serde::Deserialize>::deserialize(de)
            .map_err(|e| InputError::Parse(e.to_string()))?;
        if v.is_null() {
            continue;
        }
        check_depth(&v)?;
        docs.push(v);
    }
    if docs.is_empty() {
        return Err(InputError::Empty);
    }
    Ok(docs)
}

fn is_rbac_doc(v: &Value) -> bool {
    let kind = v.get("kind").and_then(Value::as_str).unwrap_or("");
    let api = v.get("apiVersion").and_then(Value::as_str).unwrap_or("");
    if kind == "List" {
        return v
            .get("items")
            .and_then(Value::as_array)
            .map(|items| items.iter().any(is_rbac_doc))
            .unwrap_or(false);
    }
    api.starts_with("rbac.authorization.k8s.io")
        || matches!(
            kind,
            "Role" | "ClusterRole" | "RoleBinding" | "ClusterRoleBinding"
        )
}

/// Detect the artifact type from its parsed documents.
pub fn detect(docs: &[Value]) -> ArtifactKind {
    let Some(first) = docs.first() else {
        return ArtifactKind::Unknown;
    };
    if first.get("breachframe").is_some() {
        return ArtifactKind::Environment;
    }
    if docs.iter().any(is_rbac_doc) {
        return ArtifactKind::K8sRbac;
    }
    if first.get("mcpServers").is_some()
        || first.get("servers").map(Value::is_object).unwrap_or(false)
        || first.pointer("/mcp/servers").is_some()
        || first
            .get("projects")
            .and_then(Value::as_object)
            .map(|p| p.values().any(|x| x.get("mcpServers").is_some()))
            .unwrap_or(false)
    {
        return ArtifactKind::McpConfig;
    }
    if first.get("Statement").is_some()
        || first.get("UserDetailList").is_some()
        || first.get("RoleDetailList").is_some()
        || first.get("GroupDetailList").is_some()
        || first.get("PolicyDocument").is_some()
    {
        return ArtifactKind::AwsIam;
    }
    ArtifactKind::Unknown
}

/// Validate an identifier coming from an artifact.
pub fn validate_id(id: &str, what: &str) -> Result<(), InputError> {
    if id.is_empty() {
        return Err(InputError::Invalid(format!("{what} id must not be empty")));
    }
    if id.len() > limits::MAX_ID_LEN {
        return Err(InputError::Invalid(format!(
            "{what} id is longer than {} characters",
            limits::MAX_ID_LEN
        )));
    }
    if id.chars().any(char::is_control) {
        return Err(InputError::Invalid(format!(
            "{what} id contains control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_binary_and_oversized() {
        assert_eq!(validate_bytes(b"a\0b"), Err(InputError::Binary));
        assert_eq!(validate_bytes(b"   \n"), Err(InputError::Empty));
        let big = vec![b'a'; limits::MAX_ARTIFACT_BYTES + 1];
        assert!(matches!(validate_bytes(&big), Err(InputError::TooLarge(_))));
        assert_eq!(
            validate_bytes(&[0xff, 0xfe, 0x41]),
            Err(InputError::NotUtf8)
        );
    }

    #[test]
    fn strips_bom() {
        assert_eq!(validate_bytes("\u{feff}{}".as_bytes()).unwrap(), "{}");
    }

    #[test]
    fn parses_jsonc() {
        let docs = parse_documents(
            "{\n // comment\n \"servers\": { \"a\": {\"command\": \"x\",}, },\n /* block */ }",
        )
        .unwrap();
        assert!(docs[0]["servers"]["a"]["command"] == "x");
        assert_eq!(detect(&docs), ArtifactKind::McpConfig);
    }

    #[test]
    fn jsonc_keeps_slashes_in_strings() {
        let s = strip_jsonc(r#"{"url": "https://example.com//x", "a": "\"//"}"#);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["url"], "https://example.com//x");
    }

    #[test]
    fn parses_multi_doc_yaml() {
        let docs = parse_documents(
            "kind: Role\napiVersion: rbac.authorization.k8s.io/v1\n---\nkind: RoleBinding\n",
        )
        .unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(detect(&docs), ArtifactKind::K8sRbac);
    }

    #[test]
    fn rejects_deep_nesting() {
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(parse_documents(&deep).is_err());
    }

    #[test]
    fn yaml_alias_bomb_is_rejected_or_bounded() {
        // Classic "billion laughs". serde_yaml enforces an alias repetition limit.
        let bomb = "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n\
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n\
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n\
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n\
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n\
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n\
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\n\
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]\n\
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]\n";
        assert!(parse_documents(bomb).is_err());
    }

    #[test]
    fn detects_formats() {
        let env = parse_documents("breachframe: 1\nnodes: []\n").unwrap();
        assert_eq!(detect(&env), ArtifactKind::Environment);
        let iam = parse_documents(r#"{"Version":"2012-10-17","Statement":[]}"#).unwrap();
        assert_eq!(detect(&iam), ArtifactKind::AwsIam);
        let mcp = parse_documents(r#"{"mcpServers":{}}"#).unwrap();
        assert_eq!(detect(&mcp), ArtifactKind::McpConfig);
        let other = parse_documents("hello: world\n").unwrap();
        assert_eq!(detect(&other), ArtifactKind::Unknown);
    }
}
