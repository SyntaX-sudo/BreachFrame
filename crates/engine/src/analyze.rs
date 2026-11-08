//! Orchestration: run the right analyzer for each artifact, merge graphs,
//! evaluate policies and compute summaries.

use crate::input::{self, limits, InputError};
use crate::model::*;
use crate::{environment, iam, mcp, policy, rbac};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A file to analyse. `content` is raw bytes; it is validated before parsing.
#[derive(Debug, Clone)]
pub struct ArtifactInput {
    pub name: String,
    pub content: Vec<u8>,
}

impl ArtifactInput {
    pub fn new(name: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        ArtifactInput {
            name: name.into(),
            content: content.into(),
        }
    }
}

/// Analyse one artifact in isolation.
pub fn analyze_artifact(a: &ArtifactInput) -> Result<(ArtifactKind, Partial), InputError> {
    let text = input::validate_bytes(&a.content)?;
    let docs = input::parse_documents(text)?;
    let kind = input::detect(&docs);
    let mut partial = match kind {
        ArtifactKind::Environment => environment::analyze(&docs[0], &a.name)?,
        ArtifactKind::K8sRbac => rbac::analyze(&docs, &a.name),
        ArtifactKind::AwsIam => iam::analyze(&docs[0], &a.name),
        ArtifactKind::McpConfig => mcp::analyze(&docs[0], &a.name),
        ArtifactKind::Unknown => return Err(InputError::Unsupported),
    };
    partial.graph.set_source(&a.name);
    Ok((kind, partial))
}

/// Risk score 0–100: `100 × (1 − Π(1 − wᵢ))` over all findings, where `wᵢ` is
/// the severity weight (critical .35, high .20, medium .08, low .03, info 0).
/// It saturates smoothly and one critical issue already yields 35.
pub fn risk_score(findings: &[Finding]) -> u32 {
    let survive: f64 = findings.iter().map(|f| 1.0 - f.severity.weight()).product();
    ((1.0 - survive) * 100.0).round().clamp(0.0, 100.0) as u32
}

fn principals(graph: &Graph, findings: &[Finding]) -> Vec<PrincipalSummary> {
    let adj = graph.adjacency();
    let sensitive: HashSet<&str> = graph
        .nodes
        .iter()
        .filter(|n| n.is_sensitive())
        .map(|n| n.id.as_str())
        .collect();
    let mut sev_by_node: HashMap<&str, Severity> = HashMap::new();
    for f in findings {
        for id in f.nodes.iter().chain(f.path.first()) {
            let e = sev_by_node.entry(id.as_str()).or_insert(f.severity);
            if f.severity > *e {
                *e = f.severity;
            }
        }
    }
    let mut out = Vec::new();
    for n in graph.nodes.iter().filter(|n| n.kind.is_principal()) {
        let mut seen: HashSet<&str> = HashSet::from([n.id.as_str()]);
        let mut perms: HashSet<&str> = HashSet::new();
        let mut q = VecDeque::from([(n.id.as_str(), 0usize)]);
        let mut wildcard = false;
        while let Some((cur, d)) = q.pop_front() {
            if d >= limits::MAX_PATH_DEPTH {
                continue;
            }
            for &ei in adj.get(cur).map(Vec::as_slice).unwrap_or(&[]) {
                let e = &graph.edges[ei];
                for p in &e.permissions {
                    perms.insert(p.as_str());
                    if p == "*" {
                        wildcard = true;
                    }
                }
                if e.to.ends_with("/*") || e.to.ends_with(":*") {
                    wildcard = true;
                }
                if seen.insert(e.to.as_str()) {
                    q.push_back((e.to.as_str(), d + 1));
                }
            }
        }
        let reachable_sensitive = seen
            .iter()
            .filter(|id| sensitive.contains(*id) && **id != n.id)
            .count();
        out.push(PrincipalSummary {
            id: n.id.clone(),
            label: n.label.clone(),
            kind: n.kind,
            reachable: seen.len() - 1,
            reachable_sensitive,
            permissions: perms.len(),
            wildcard,
            max_severity: sev_by_node.get(n.id.as_str()).copied(),
        });
    }
    out.sort_by(|a, b| {
        b.reachable_sensitive
            .cmp(&a.reachable_sensitive)
            .then(b.max_severity.cmp(&a.max_severity))
            .then(b.reachable.cmp(&a.reachable))
            .then(a.id.cmp(&b.id))
    });
    out
}

/// Analyse a set of artifacts as one environment. Artifacts that fail to
/// parse are reported in `artifacts[].error` and skipped; they never abort
/// the analysis of the others.
pub fn analyze(artifacts: &[ArtifactInput], now_ms: i64) -> AnalysisResult {
    let mut graph = Graph::default();
    let mut findings = Vec::new();
    let mut policies = Vec::new();
    let mut mcp_servers = Vec::new();
    let mut summaries = Vec::new();

    for (i, a) in artifacts.iter().enumerate() {
        let sha256 = crate::util::sha256_hex(&a.content);
        if i >= limits::MAX_ARTIFACTS {
            summaries.push(ArtifactSummary {
                name: a.name.clone(),
                kind: ArtifactKind::Unknown,
                sha256,
                size: a.content.len(),
                nodes: 0,
                edges: 0,
                findings: 0,
                error: Some(format!(
                    "skipped: more than {} artifacts in one analysis",
                    limits::MAX_ARTIFACTS
                )),
            });
            continue;
        }
        match analyze_artifact(a) {
            Ok((kind, p)) => {
                if graph.nodes.len() + p.graph.nodes.len() > limits::MAX_NODES
                    || graph.edges.len() + p.graph.edges.len() > limits::MAX_EDGES
                {
                    summaries.push(ArtifactSummary {
                        name: a.name.clone(),
                        kind,
                        sha256,
                        size: a.content.len(),
                        nodes: 0,
                        edges: 0,
                        findings: 0,
                        error: Some(
                            InputError::Limit(format!(
                                "merged graph would exceed {} nodes / {} edges",
                                limits::MAX_NODES,
                                limits::MAX_EDGES
                            ))
                            .to_string(),
                        ),
                    });
                    continue;
                }
                summaries.push(ArtifactSummary {
                    name: a.name.clone(),
                    kind,
                    sha256,
                    size: a.content.len(),
                    nodes: p.graph.nodes.len(),
                    edges: p.graph.edges.len(),
                    findings: p.findings.len(),
                    error: None,
                });
                graph.merge(p.graph);
                findings.extend(p.findings);
                policies.extend(p.policies);
                mcp_servers.extend(p.mcp_servers);
            }
            Err(e) => summaries.push(ArtifactSummary {
                name: a.name.clone(),
                kind: ArtifactKind::Unknown,
                sha256,
                size: a.content.len(),
                nodes: 0,
                edges: 0,
                findings: 0,
                error: Some(e.to_string()),
            }),
        }
    }

    // Policies are evaluated against the *merged* graph so that an environment
    // file can constrain nodes produced by RBAC, IAM or MCP artifacts.
    let policy_findings = policy::evaluate(&graph, &policies);
    let policy_violations = policy_findings.len();
    // Attribute policy findings to the artifact that declared the policy.
    for s in &mut summaries {
        s.findings += policy_findings
            .iter()
            .filter(|f| f.source.as_deref() == Some(s.name.as_str()))
            .count();
    }
    findings.extend(policy_findings);

    // Deduplicate by fingerprint (same artifact imported twice).
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.title.cmp(&b.title))
    });

    let mut by_severity = BTreeMap::new();
    let mut by_category = BTreeMap::new();
    for s in Severity::ALL {
        by_severity.insert(s, 0);
    }
    for f in &findings {
        *by_severity.entry(f.severity).or_insert(0) += 1;
        *by_category.entry(f.category).or_insert(0) += 1;
    }

    AnalysisResult {
        engine_version: ENGINE_VERSION.to_string(),
        generated_at: now_ms,
        risk_score: risk_score(&findings),
        principals: principals(&graph, &findings),
        stats: Stats {
            by_severity,
            by_category,
            nodes: graph.nodes.len(),
            edges: graph.edges.len(),
            policy_violations,
        },
        artifacts: summaries,
        graph,
        policies,
        findings,
        mcp_servers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_score_is_bounded_and_monotonic() {
        let mk = |s| {
            FindingBuilder::new("X", s, Category::Policy, "t")
                .key(format!("{s:?}{}", rand_key()))
                .build()
        };
        assert_eq!(risk_score(&[]), 0);
        assert_eq!(risk_score(&[mk(Severity::Critical)]), 35);
        let many: Vec<_> = (0..50).map(|_| mk(Severity::Critical)).collect();
        assert_eq!(risk_score(&many), 100);
        assert!(
            risk_score(&[mk(Severity::High), mk(Severity::Low)])
                > risk_score(&[mk(Severity::High)])
        );
        assert_eq!(risk_score(&[mk(Severity::Info)]), 0);
    }

    fn rand_key() -> usize {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn bad_artifacts_do_not_abort_analysis() {
        let r = analyze(
            &[
                ArtifactInput::new("bin.dat", vec![0u8, 1, 2]),
                ArtifactInput::new("hello.yaml", "hello: world"),
                ArtifactInput::new(
                    "iam.json",
                    r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
                ),
            ],
            1,
        );
        assert_eq!(r.artifacts.len(), 3);
        assert!(r.artifacts[0].error.as_ref().unwrap().contains("binary"));
        assert!(r.artifacts[1]
            .error
            .as_ref()
            .unwrap()
            .contains("unsupported"));
        assert!(r.artifacts[2].error.is_none());
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.risk_score, 35);
    }

    #[test]
    fn policies_apply_across_artifacts() {
        let rbac = r#"
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: ci }
roleRef: { kind: ClusterRole, name: cluster-admin }
subjects: [{ kind: ServiceAccount, name: ci, namespace: build }]
"#;
        let env = r#"
breachframe: 1
nodes:
  - { id: "agent:ci", kind: agent, label: CI agent }
  - { id: "k8s:sa:build/ci", kind: service_account }
edges:
  - { from: "agent:ci", to: "k8s:sa:build/ci", relation: uses_token }
policies:
  - id: P-K8S
    name: CI must not reach secrets
    severity: critical
    deny: { from: { id: "agent:ci" }, to: { kind: secret } }
"#;
        let r = analyze(
            &[
                ArtifactInput::new("rbac.yaml", rbac),
                ArtifactInput::new("env.yaml", env),
            ],
            0,
        );
        assert!(
            r.artifacts.iter().all(|a| a.error.is_none()),
            "{:?}",
            r.artifacts
        );
        // cluster-admin => k8s:res:*/* (all resources) is not a secret, but the
        // policy looks for kind=secret; cluster-admin's builtin rule has '*'
        // resources only, so no secret node: no violation expected.
        assert_eq!(r.stats.policy_violations, 0);
        let env2 = env.replace(
            "to: { kind: secret }",
            "to: { attributes: { sensitivity: critical } }",
        );
        let r2 = analyze(
            &[
                ArtifactInput::new("rbac.yaml", rbac),
                ArtifactInput::new("env.yaml", env2),
            ],
            0,
        );
        // Both the cluster-admin role node and "all resources" are critical.
        assert_eq!(r2.stats.policy_violations, 2);
        let targets: Vec<_> = r2
            .findings
            .iter()
            .filter(|f| f.category == Category::Policy)
            .map(|f| f.path.last().unwrap().as_str())
            .collect();
        assert!(targets.contains(&"k8s:res:*/*"));
        assert!(targets.contains(&"k8s:clusterrole:cluster-admin"));
        let f = r2
            .findings
            .iter()
            .find(|f| f.category == Category::Policy)
            .unwrap();
        assert_eq!(f.path.first().unwrap(), "agent:ci");
        let ci = r2.principals.iter().find(|p| p.id == "agent:ci").unwrap();
        assert!(ci.wildcard);
    }

    #[test]
    fn duplicate_artifacts_are_deduplicated() {
        let iam = r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        let r = analyze(
            &[
                ArtifactInput::new("a.json", iam),
                ArtifactInput::new("a.json", iam),
            ],
            0,
        );
        assert_eq!(r.findings.len(), 1);
    }
}
