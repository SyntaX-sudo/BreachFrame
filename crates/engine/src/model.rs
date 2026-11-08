//! Core data model shared by every analyzer.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// Finding severity, ordered from least to most severe.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    /// Probability-like weight used by the risk score (see `analyze::risk_score`).
    pub fn weight(self) -> f64 {
        match self {
            Severity::Critical => 0.35,
            Severity::High => 0.20,
            Severity::Medium => 0.08,
            Severity::Low => 0.03,
            Severity::Info => 0.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// What a node in the security graph represents.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    User,
    Group,
    Role,
    ServiceAccount,
    Service,
    Api,
    Agent,
    McpServer,
    Tool,
    Resource,
    Secret,
    External,
    #[serde(other)]
    Other,
}

impl NodeKind {
    pub fn is_principal(self) -> bool {
        matches!(
            self,
            NodeKind::User
                | NodeKind::Group
                | NodeKind::ServiceAccount
                | NodeKind::Agent
                | NodeKind::Service
                | NodeKind::External
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    #[serde(default)]
    pub label: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
    /// Name of the artifact that produced this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl Node {
    pub fn new(id: impl Into<String>, kind: NodeKind, label: impl Into<String>) -> Self {
        Node {
            id: id.into(),
            kind,
            label: label.into(),
            attributes: BTreeMap::new(),
            source: None,
        }
    }

    pub fn with_attr(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.attributes.insert(key.to_string(), value.into());
        self
    }

    /// A node is sensitive when it is a secret or flagged as high-value.
    pub fn is_sensitive(&self) -> bool {
        if self.kind == NodeKind::Secret {
            return true;
        }
        if self.attributes.get("crown_jewel").and_then(Value::as_bool) == Some(true) {
            return true;
        }
        matches!(
            self.attributes.get("sensitivity").and_then(Value::as_str),
            Some("high") | Some("critical")
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Edge {
    #[serde(default)]
    pub id: String,
    pub from: String,
    pub to: String,
    pub relation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl Edge {
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        relation: impl Into<String>,
    ) -> Self {
        let mut e = Edge {
            id: String::new(),
            from: from.into(),
            to: to.into(),
            relation: relation.into(),
            permissions: Vec::new(),
            attributes: BTreeMap::new(),
            source: None,
        };
        e.id = Edge::make_id(&e.from, &e.to, &e.relation);
        e
    }

    pub fn with_permissions<I, S>(mut self, perms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.permissions = perms.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_attr(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.attributes.insert(key.to_string(), value.into());
        self
    }

    pub fn make_id(from: &str, to: &str, relation: &str) -> String {
        format!("{from}|{relation}|{to}")
    }
}

/// Directed security graph. An edge `a -> b` means "a can reach, act as, or
/// access b".
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    #[serde(skip)]
    node_index: HashMap<String, usize>,
    #[serde(skip)]
    edge_index: HashMap<String, usize>,
}

impl PartialEq for Graph {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes && self.edges == other.edges
    }
}

impl Graph {
    fn ensure_index(&mut self) {
        if self.node_index.len() != self.nodes.len() {
            self.node_index = self
                .nodes
                .iter()
                .enumerate()
                .map(|(i, n)| (n.id.clone(), i))
                .collect();
        }
        if self.edge_index.len() != self.edges.len() {
            self.edge_index = self
                .edges
                .iter()
                .enumerate()
                .map(|(i, e)| (e.id.clone(), i))
                .collect();
        }
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        match self.node_index.get(id) {
            Some(&i) if self.node_index.len() == self.nodes.len() => self.nodes.get(i),
            _ => self.nodes.iter().find(|n| n.id == id),
        }
    }

    pub fn has_node(&self, id: &str) -> bool {
        self.node(id).is_some()
    }

    /// Insert a node, merging attributes if it already exists.
    pub fn upsert_node(&mut self, node: Node) {
        self.ensure_index();
        if let Some(&i) = self.node_index.get(&node.id) {
            let existing = &mut self.nodes[i];
            for (k, v) in node.attributes {
                existing.attributes.entry(k).or_insert(v);
            }
            if existing.label.is_empty() {
                existing.label = node.label;
            }
            if existing.kind == NodeKind::Other {
                existing.kind = node.kind;
            }
        } else {
            self.node_index.insert(node.id.clone(), self.nodes.len());
            self.nodes.push(node);
        }
    }

    /// Insert an edge, merging permissions when (from, relation, to) already exists.
    pub fn upsert_edge(&mut self, mut edge: Edge) {
        self.ensure_index();
        if edge.id.is_empty() {
            edge.id = Edge::make_id(&edge.from, &edge.to, &edge.relation);
        }
        if let Some(&i) = self.edge_index.get(&edge.id) {
            let existing = &mut self.edges[i];
            for p in edge.permissions {
                if !existing.permissions.contains(&p) {
                    existing.permissions.push(p);
                }
            }
            for (k, v) in edge.attributes {
                existing.attributes.entry(k).or_insert(v);
            }
        } else {
            self.edge_index.insert(edge.id.clone(), self.edges.len());
            self.edges.push(edge);
        }
    }

    pub fn merge(&mut self, other: Graph) {
        for n in other.nodes {
            self.upsert_node(n);
        }
        for e in other.edges {
            self.upsert_edge(e);
        }
    }

    /// Adjacency list: node id -> indices of outgoing edges.
    pub fn adjacency(&self) -> HashMap<&str, Vec<usize>> {
        let mut adj: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, e) in self.edges.iter().enumerate() {
            adj.entry(e.from.as_str()).or_default().push(i);
        }
        adj
    }

    pub fn set_source(&mut self, source: &str) {
        for n in &mut self.nodes {
            n.source.get_or_insert_with(|| source.to_string());
        }
        for e in &mut self.edges {
            e.source.get_or_insert_with(|| source.to_string());
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Policy,
    Rbac,
    Iam,
    Mcp,
    Secrets,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub label: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl Evidence {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Evidence {
            label: label.into(),
            value: value.into(),
            location: None,
        }
    }

    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable fingerprint: identical issues across runs share the same id.
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    pub impact: String,
    pub recommendation: String,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Node ids of the attack path, when the finding is a path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    /// Edge ids along `path`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edge_path: Vec<String>,
    /// Node ids the finding is about (for highlighting).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

pub struct FindingBuilder {
    f: Finding,
    key: String,
}

impl FindingBuilder {
    pub fn new(
        rule_id: &str,
        severity: Severity,
        category: Category,
        title: impl Into<String>,
    ) -> Self {
        FindingBuilder {
            f: Finding {
                id: String::new(),
                rule_id: rule_id.to_string(),
                title: title.into(),
                severity,
                category,
                description: String::new(),
                impact: String::new(),
                recommendation: String::new(),
                evidence: Vec::new(),
                path: Vec::new(),
                edge_path: Vec::new(),
                nodes: Vec::new(),
                source: None,
            },
            key: String::new(),
        }
    }
    /// Key that, together with the rule id, uniquely identifies the issue.
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = key.into();
        self
    }
    pub fn description(mut self, s: impl Into<String>) -> Self {
        self.f.description = s.into();
        self
    }
    pub fn impact(mut self, s: impl Into<String>) -> Self {
        self.f.impact = s.into();
        self
    }
    pub fn recommendation(mut self, s: impl Into<String>) -> Self {
        self.f.recommendation = s.into();
        self
    }
    pub fn evidence(mut self, e: Evidence) -> Self {
        self.f.evidence.push(e);
        self
    }
    pub fn node(mut self, id: impl Into<String>) -> Self {
        self.f.nodes.push(id.into());
        self
    }
    pub fn path(mut self, nodes: Vec<String>, edges: Vec<String>) -> Self {
        self.f.path = nodes;
        self.f.edge_path = edges;
        self
    }
    pub fn source(mut self, s: &str) -> Self {
        self.f.source = Some(s.to_string());
        self
    }
    pub fn build(mut self) -> Finding {
        let material = format!(
            "{}\u{1f}{}\u{1f}{}",
            self.f.rule_id,
            self.f.source.as_deref().unwrap_or(""),
            self.key
        );
        self.f.id = crate::util::short_hash(&material);
        self.f
    }
}

/// Access-path policy declared in an environment file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_policy_severity")]
    pub severity: Severity,
    pub deny: PathRule,
    #[serde(default)]
    pub recommendation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

fn default_policy_severity() -> Severity {
    Severity::High
}

/// "No path may exist from `from` to `to`" (optionally only via some relations).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PathRule {
    pub from: Selector,
    pub to: Selector,
    /// Only traverse these relations. Empty = all relations.
    #[serde(default, deserialize_with = "crate::util::one_or_many")]
    pub via: Vec<String>,
    #[serde(default)]
    pub max_depth: Option<usize>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Selector {
    #[serde(default, alias = "id", deserialize_with = "crate::util::one_or_many")]
    pub ids: Vec<String>,
    #[serde(default, alias = "kind", deserialize_with = "crate::util::one_or_many")]
    pub kinds: Vec<NodeKind>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

impl Selector {
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.kinds.is_empty() && self.attributes.is_empty()
    }

    pub fn matches(&self, node: &Node) -> bool {
        if self.is_empty() {
            return false;
        }
        if !self.ids.is_empty() && !self.ids.iter().any(|id| id == &node.id) {
            return false;
        }
        if !self.kinds.is_empty() && !self.kinds.contains(&node.kind) {
            return false;
        }
        self.attributes
            .iter()
            .all(|(k, v)| node.attributes.get(k) == Some(v))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Environment,
    K8sRbac,
    AwsIam,
    McpConfig,
    Unknown,
}

impl ArtifactKind {
    pub fn label(self) -> &'static str {
        match self {
            ArtifactKind::Environment => "BreachFrame environment",
            ArtifactKind::K8sRbac => "Kubernetes RBAC",
            ArtifactKind::AwsIam => "AWS IAM",
            ArtifactKind::McpConfig => "MCP configuration",
            ArtifactKind::Unknown => "Unknown",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactSummary {
    pub name: String,
    pub kind: ArtifactKind,
    pub sha256: String,
    pub size: usize,
    pub nodes: usize,
    pub edges: usize,
    pub findings: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalSummary {
    pub id: String,
    pub label: String,
    pub kind: NodeKind,
    /// Distinct nodes reachable from this principal.
    pub reachable: usize,
    /// Reachable nodes that are secrets or flagged as sensitive.
    pub reachable_sensitive: usize,
    /// Distinct permission strings on reachable edges.
    pub permissions: usize,
    pub wildcard: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<Severity>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpServerSummary {
    pub name: String,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub env_keys: Vec<String>,
    #[serde(default)]
    pub auto_approved: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub disabled: bool,
    pub findings: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<Severity>,
    pub source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub by_severity: BTreeMap<Severity, usize>,
    pub by_category: BTreeMap<Category, usize>,
    pub nodes: usize,
    pub edges: usize,
    pub policy_violations: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisResult {
    pub engine_version: String,
    pub generated_at: i64,
    pub artifacts: Vec<ArtifactSummary>,
    pub graph: Graph,
    pub policies: Vec<Policy>,
    pub findings: Vec<Finding>,
    pub principals: Vec<PrincipalSummary>,
    pub mcp_servers: Vec<McpServerSummary>,
    pub stats: Stats,
    pub risk_score: u32,
}

/// Output of a single artifact analyzer before merging.
#[derive(Default, Debug)]
pub struct Partial {
    pub graph: Graph,
    pub findings: Vec<Finding>,
    pub policies: Vec<Policy>,
    pub mcp_servers: Vec<McpServerSummary>,
}
