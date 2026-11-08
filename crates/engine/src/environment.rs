//! BreachFrame environment files: a declarative graph of identities, services,
//! APIs, agents and resources, plus the access policies that must hold.
//!
//! ```yaml
//! breachframe: 1
//! name: Payments platform
//! nodes:
//!   - { id: user:alice, kind: user, label: Alice }
//!   - { id: secret:db, kind: secret, label: DB password }
//! edges:
//!   - { from: user:alice, to: secret:db, relation: reads }
//! policies:
//!   - id: P-001
//!     name: Humans never read production secrets directly
//!     severity: high
//!     deny: { from: { kind: user }, to: { kind: secret } }
//! ```

use crate::input::{limits, validate_id, InputError};
use crate::model::{Edge, Graph, Node, Partial, Policy};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvironmentFile {
    breachframe: Value,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(default)]
    nodes: Vec<Node>,
    #[serde(default)]
    edges: Vec<Edge>,
    #[serde(default)]
    policies: Vec<Policy>,
}

pub fn analyze(doc: &Value, source: &str) -> Result<Partial, InputError> {
    let env: EnvironmentFile = serde_json::from_value(doc.clone())
        .map_err(|e| InputError::Invalid(format!("environment file: {e}")))?;

    match &env.breachframe {
        Value::Number(n) if n.as_u64() == Some(1) => {}
        Value::String(s) if s == "1" => {}
        other => {
            return Err(InputError::Invalid(format!(
                "unsupported environment format version {other}; expected `breachframe: 1`"
            )))
        }
    }
    if env.nodes.len() > limits::MAX_NODES {
        return Err(InputError::Limit(format!(
            "more than {} nodes",
            limits::MAX_NODES
        )));
    }
    if env.edges.len() > limits::MAX_EDGES {
        return Err(InputError::Limit(format!(
            "more than {} edges",
            limits::MAX_EDGES
        )));
    }

    let mut ids = HashSet::new();
    let mut graph = Graph::default();
    for mut node in env.nodes {
        validate_id(&node.id, "node")?;
        if !ids.insert(node.id.clone()) {
            return Err(InputError::Invalid(format!(
                "duplicate node id `{}`",
                node.id
            )));
        }
        if node.label.is_empty() {
            node.label = node.id.clone();
        }
        node.source = Some(source.to_string());
        graph.upsert_node(node);
    }
    for mut edge in env.edges {
        for end in [&edge.from, &edge.to] {
            if !ids.contains(end) {
                return Err(InputError::Invalid(format!(
                    "edge `{} -> {}` references unknown node `{end}`",
                    edge.from, edge.to
                )));
            }
        }
        validate_id(&edge.relation, "relation")?;
        edge.id = Edge::make_id(&edge.from, &edge.to, &edge.relation);
        edge.source = Some(source.to_string());
        graph.upsert_edge(edge);
    }

    let mut policy_ids = HashSet::new();
    let mut policies = Vec::new();
    for mut p in env.policies {
        validate_id(&p.id, "policy")?;
        if !policy_ids.insert(p.id.clone()) {
            return Err(InputError::Invalid(format!(
                "duplicate policy id `{}`",
                p.id
            )));
        }
        if p.deny.from.is_empty() || p.deny.to.is_empty() {
            return Err(InputError::Invalid(format!(
                "policy `{}` needs non-empty `deny.from` and `deny.to` selectors",
                p.id
            )));
        }
        if let Some(d) = p.deny.max_depth {
            if d == 0 || d > limits::MAX_PATH_DEPTH {
                return Err(InputError::Invalid(format!(
                    "policy `{}` maxDepth must be between 1 and {}",
                    p.id,
                    limits::MAX_PATH_DEPTH
                )));
            }
        }
        p.source = Some(source.to_string());
        policies.push(p);
    }

    Ok(Partial {
        graph,
        findings: Vec::new(),
        policies,
        mcp_servers: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::parse_documents;

    fn parse(text: &str) -> Result<Partial, InputError> {
        let docs = parse_documents(text).unwrap();
        analyze(&docs[0], "env.yaml")
    }

    #[test]
    fn parses_valid_environment() {
        let p = parse(
            "breachframe: 1\nnodes:\n  - {id: a, kind: user}\n  - {id: b, kind: secret}\nedges:\n  - {from: a, to: b, relation: reads}\npolicies:\n  - id: P1\n    name: no\n    deny: {from: {kind: user}, to: {kind: secret}}\n",
        )
        .unwrap();
        assert_eq!(p.graph.nodes.len(), 2);
        assert_eq!(p.graph.nodes[0].label, "a");
        assert_eq!(p.graph.edges[0].id, "a|reads|b");
        assert_eq!(p.policies.len(), 1);
    }

    #[test]
    fn rejects_dangling_edges() {
        let err = parse("breachframe: 1\nnodes:\n  - {id: a, kind: user}\nedges:\n  - {from: a, to: ghost, relation: x}\n")
            .unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn rejects_duplicates_and_bad_version() {
        assert!(parse(
            "breachframe: 1\nnodes:\n  - {id: a, kind: user}\n  - {id: a, kind: user}\n"
        )
        .is_err());
        assert!(parse("breachframe: 7\n").is_err());
    }

    #[test]
    fn rejects_empty_selectors() {
        assert!(parse("breachframe: 1\npolicies:\n  - {id: P, name: n, deny: {from: {}, to: {kind: secret}}}\n").is_err());
    }

    #[test]
    fn unknown_kind_maps_to_other() {
        let p = parse("breachframe: 1\nnodes:\n  - {id: a, kind: spaceship}\n").unwrap();
        assert_eq!(p.graph.nodes[0].kind, crate::model::NodeKind::Other);
    }
}
