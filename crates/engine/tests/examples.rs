//! The files in `examples/` are documented in the README; keep them honest by
//! asserting the findings they are meant to demonstrate.

use breachframe_engine::{analyze, ArtifactInput, ArtifactKind};
use std::path::Path;

fn load(rel: &str) -> ArtifactInput {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(rel);
    let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    ArtifactInput::new(p.file_name().unwrap().to_string_lossy(), bytes)
}

fn rules(files: &[&str]) -> (Vec<String>, breachframe_engine::AnalysisResult) {
    let inputs: Vec<_> = files.iter().map(|f| load(f)).collect();
    let r = analyze(&inputs, 0);
    for a in &r.artifacts {
        assert!(a.error.is_none(), "{} failed: {:?}", a.name, a.error);
    }
    (r.findings.iter().map(|f| f.rule_id.clone()).collect(), r)
}

#[test]
fn environment_example_violates_both_policies() {
    let (ids, r) = rules(&["environment/support-agent-platform.yaml"]);
    assert_eq!(r.artifacts[0].kind, ArtifactKind::Environment);
    assert!(ids.contains(&"POLICY:P-AGENT-01".to_string()));
    assert!(ids.contains(&"POLICY:P-AGENT-02".to_string()));
}

#[test]
fn rbac_example() {
    let (ids, _) = rules(&["kubernetes/rbac.yaml"]);
    for want in ["RBAC-002", "RBAC-005", "RBAC-006", "RBAC-021"] {
        assert!(ids.iter().any(|i| i == want), "missing {want} in {ids:?}");
    }
}

#[test]
fn iam_example() {
    let (ids, _) = rules(&["aws/iam-policy.json"]);
    for want in ["IAM-002", "IAM-003", "IAM-006"] {
        assert!(ids.iter().any(|i| i == want), "missing {want} in {ids:?}");
    }
    assert!(
        !ids.iter().any(|i| i == "IAM-001"),
        "no statement grants full admin"
    );
}

#[test]
fn mcp_example_flags_issues_and_redacts_the_fake_token() {
    let (ids, r) = rules(&["mcp/claude_desktop_config.json"]);
    for want in [
        "MCP-001", "MCP-002", "MCP-003", "MCP-004", "MCP-005", "MCP-007",
    ] {
        assert!(ids.iter().any(|i| i == want), "missing {want} in {ids:?}");
    }
    let json = serde_json::to_string(&r).unwrap();
    assert!(
        !json.contains("ghp_ExampleFakeToken"),
        "secret leaked into the result"
    );
    // Pinned packages and ${env:...} references are not findings.
    assert!(!r.findings.iter().any(|f| f.title.contains("pinned-search")));
}
