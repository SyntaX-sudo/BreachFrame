//! Path-based policy evaluation over the merged security graph.

use crate::input::limits;
use crate::model::{Category, Evidence, Finding, FindingBuilder, Graph, Policy};
use std::collections::{HashMap, HashSet, VecDeque};

const DEFAULT_MAX_DEPTH: usize = 10;

/// A shortest path found by BFS.
#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    pub nodes: Vec<String>,
    pub edges: Vec<String>,
}

/// Breadth-first search from `start`, returning the shortest path to every
/// reachable node (excluding `start`). `via` restricts traversable relations.
pub fn shortest_paths(
    graph: &Graph,
    start: &str,
    via: &[String],
    max_depth: usize,
) -> HashMap<String, Path> {
    shortest_paths_with(graph, &graph.adjacency(), start, via, max_depth)
}

pub(crate) fn shortest_paths_with(
    graph: &Graph,
    adj: &HashMap<&str, Vec<usize>>,
    start: &str,
    via: &[String],
    max_depth: usize,
) -> HashMap<String, Path> {
    let mut parent: HashMap<&str, (usize, &str)> = HashMap::new();
    let mut depth: HashMap<&str, usize> = HashMap::new();
    let mut queue = VecDeque::new();
    depth.insert(start, 0);
    queue.push_back(start);
    while let Some(cur) = queue.pop_front() {
        let d = depth[cur];
        if d >= max_depth {
            continue;
        }
        for &ei in adj.get(cur).map(Vec::as_slice).unwrap_or(&[]) {
            let e = &graph.edges[ei];
            if !via.is_empty() && !via.iter().any(|r| r == &e.relation) {
                continue;
            }
            let next = e.to.as_str();
            if depth.contains_key(next) {
                continue;
            }
            depth.insert(next, d + 1);
            parent.insert(next, (ei, cur));
            queue.push_back(next);
        }
    }
    let mut out = HashMap::new();
    for &target in parent.keys() {
        let mut nodes = vec![target.to_string()];
        let mut edges = Vec::new();
        let mut cur = target;
        while let Some(&(ei, prev)) = parent.get(cur) {
            edges.push(graph.edges[ei].id.clone());
            nodes.push(prev.to_string());
            cur = prev;
        }
        nodes.reverse();
        edges.reverse();
        out.insert(target.to_string(), Path { nodes, edges });
    }
    out
}

/// Evaluate every policy; each (source, target) pair with a path is a violation.
pub fn evaluate(graph: &Graph, policies: &[Policy]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let adj = graph.adjacency();
    let edge_by_id: HashMap<&str, &crate::model::Edge> =
        graph.edges.iter().map(|e| (e.id.as_str(), e)).collect();
    for policy in policies {
        let max_depth = policy
            .deny
            .max_depth
            .unwrap_or(DEFAULT_MAX_DEPTH)
            .clamp(1, limits::MAX_PATH_DEPTH);
        let sources: Vec<_> = graph
            .nodes
            .iter()
            .filter(|n| policy.deny.from.matches(n))
            .collect();
        let targets: HashSet<&str> = graph
            .nodes
            .iter()
            .filter(|n| policy.deny.to.matches(n))
            .map(|n| n.id.as_str())
            .collect();
        if sources.is_empty() || targets.is_empty() {
            continue;
        }
        let mut violations = Vec::new();
        for src in &sources {
            let paths = shortest_paths_with(graph, &adj, &src.id, &policy.deny.via, max_depth);
            let mut hits: Vec<_> = paths
                .into_iter()
                .filter(|(t, _)| targets.contains(t.as_str()))
                .collect();
            hits.sort_by(|a, b| a.1.nodes.len().cmp(&b.1.nodes.len()).then(a.0.cmp(&b.0)));
            for (target, path) in hits {
                violations.push((src.id.clone(), target, path));
            }
        }
        violations.sort_by(|a, b| {
            a.2.nodes
                .len()
                .cmp(&b.2.nodes.len())
                .then(a.0.cmp(&b.0))
                .then(a.1.cmp(&b.1))
        });
        let total = violations.len();
        for (src, target, path) in violations.into_iter().take(limits::MAX_FINDINGS_PER_POLICY) {
            let label = |id: &str| {
                graph
                    .node(id)
                    .map(|n| n.label.clone())
                    .unwrap_or_else(|| id.to_string())
            };
            let chain = path
                .nodes
                .iter()
                .map(|id| label(id))
                .collect::<Vec<_>>()
                .join(" → ");
            let relations = path
                .edges
                .iter()
                .filter_map(|eid| edge_by_id.get(eid.as_str()))
                .map(|e| {
                    if e.permissions.is_empty() {
                        e.relation.clone()
                    } else {
                        format!("{} [{}]", e.relation, e.permissions.join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join(" → ");
            let mut b = FindingBuilder::new(
                &format!("POLICY:{}", policy.id),
                policy.severity,
                Category::Policy,
                format!("{}: {} can reach {}", policy.name, label(&src), label(&target)),
            )
            .key(format!("{src}->{target}"))
            .description(if policy.description.is_empty() {
                format!("Policy `{}` forbids any access path from the source to the target, but one exists.", policy.id)
            } else {
                policy.description.clone()
            })
            .impact(format!(
                "If `{}` is compromised or misused, an attacker can reach `{}` in {} hop(s).",
                label(&src),
                label(&target),
                path.edges.len()
            ))
            .recommendation(if policy.recommendation.is_empty() {
                "Remove or constrain one of the edges on the path (least privilege), or add an explicit authorization check at the weakest hop.".to_string()
            } else {
                policy.recommendation.clone()
            })
            .evidence(Evidence::new("Path", chain))
            .evidence(Evidence::new("Relations", relations))
            .path(path.nodes.clone(), path.edges.clone());
            if let Some(s) = &policy.source {
                b = b
                    .source(s)
                    .evidence(Evidence::new("Policy", policy.id.clone()).at(s.clone()));
            }
            if total > limits::MAX_FINDINGS_PER_POLICY {
                b = b.evidence(Evidence::new(
                    "Truncated",
                    format!(
                        "{total} violations found; showing the {} shortest",
                        limits::MAX_FINDINGS_PER_POLICY
                    ),
                ));
            }
            findings.push(b.build());
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Edge, Node, NodeKind, PathRule, Selector, Severity};

    fn graph() -> Graph {
        let mut g = Graph::default();
        g.upsert_node(Node::new("u", NodeKind::User, "User"));
        g.upsert_node(Node::new("g", NodeKind::Group, "Group"));
        g.upsert_node(Node::new("r", NodeKind::Role, "Role"));
        g.upsert_node(Node::new("s", NodeKind::Secret, "Secret"));
        g.upsert_node(Node::new("x", NodeKind::Resource, "Island"));
        g.upsert_edge(Edge::new("u", "g", "member_of"));
        g.upsert_edge(Edge::new("g", "r", "has_role"));
        g.upsert_edge(Edge::new("r", "s", "reads"));
        g.upsert_edge(Edge::new("u", "s", "break_glass"));
        g
    }

    fn policy(via: Vec<String>, max_depth: Option<usize>) -> Policy {
        Policy {
            id: "P1".into(),
            name: "No users to secrets".into(),
            description: String::new(),
            severity: Severity::High,
            deny: PathRule {
                from: Selector {
                    kinds: vec![NodeKind::User],
                    ..Default::default()
                },
                to: Selector {
                    kinds: vec![NodeKind::Secret],
                    ..Default::default()
                },
                via,
                max_depth,
            },
            recommendation: String::new(),
            source: Some("env.yaml".into()),
        }
    }

    #[test]
    fn bfs_finds_shortest_path() {
        let g = graph();
        let paths = shortest_paths(&g, "u", &[], 10);
        assert_eq!(paths["s"].nodes, vec!["u", "s"]);
        assert_eq!(paths["r"].nodes, vec!["u", "g", "r"]);
        assert!(!paths.contains_key("x"));
    }

    #[test]
    fn relation_filter_changes_path() {
        let g = graph();
        let via = vec!["member_of".into(), "has_role".into(), "reads".into()];
        let paths = shortest_paths(&g, "u", &via, 10);
        assert_eq!(paths["s"].nodes, vec!["u", "g", "r", "s"]);
        assert_eq!(paths["s"].edges.len(), 3);
    }

    #[test]
    fn depth_limit_is_respected() {
        let g = graph();
        let via = vec!["member_of".into(), "has_role".into(), "reads".into()];
        let paths = shortest_paths(&g, "u", &via, 2);
        assert!(!paths.contains_key("s"));
    }

    #[test]
    fn violations_become_findings_with_stable_ids() {
        let g = graph();
        let f1 = evaluate(&g, &[policy(vec![], None)]);
        assert_eq!(f1.len(), 1);
        assert_eq!(f1[0].path, vec!["u", "s"]);
        assert_eq!(f1[0].rule_id, "POLICY:P1");
        let f2 = evaluate(&g, &[policy(vec![], None)]);
        assert_eq!(f1[0].id, f2[0].id);
    }

    #[test]
    fn no_violation_when_unreachable() {
        let mut g = graph();
        g.edges.retain(|e| e.to != "s");
        assert!(evaluate(&g, &[policy(vec![], None)]).is_empty());
    }

    #[test]
    fn handles_cycles() {
        let mut g = graph();
        g.upsert_edge(Edge::new("r", "u", "loops"));
        let paths = shortest_paths(&g, "u", &[], 16);
        assert!(paths.contains_key("s"));
        assert!(!paths.contains_key("u"));
    }
}
