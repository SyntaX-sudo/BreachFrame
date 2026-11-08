//! Blast-radius simulation.
//!
//! This is a deterministic *model* of an attacker who has compromised one node
//! and follows every edge in the graph, one hop per step. It never touches real
//! systems; it walks the analysed graph only.

use crate::input::limits;
use crate::model::Graph;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SimulationStep {
    pub depth: usize,
    /// Nodes newly compromised at this step.
    pub nodes: Vec<String>,
    /// Edges traversed to reach them.
    pub edges: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Simulation {
    pub start: String,
    pub steps: Vec<SimulationStep>,
    pub reached: usize,
    pub reached_sensitive: Vec<String>,
    pub total_nodes: usize,
    pub note: String,
}

pub fn blast_radius(graph: &Graph, start: &str, max_steps: Option<usize>) -> Option<Simulation> {
    graph.node(start)?;
    let max_steps = max_steps
        .unwrap_or(limits::MAX_PATH_DEPTH)
        .clamp(1, limits::MAX_PATH_DEPTH);
    let adj = graph.adjacency();
    let mut seen: HashSet<&str> = HashSet::from([start]);
    let mut frontier = vec![start];
    let mut steps = vec![SimulationStep {
        depth: 0,
        nodes: vec![start.to_string()],
        edges: vec![],
    }];
    for depth in 1..=max_steps {
        let mut next = Vec::new();
        let mut edges = Vec::new();
        for cur in &frontier {
            for &ei in adj.get(cur).map(Vec::as_slice).unwrap_or(&[]) {
                let e = &graph.edges[ei];
                if seen.insert(e.to.as_str()) {
                    next.push(e.to.as_str());
                    edges.push(e.id.clone());
                }
            }
        }
        if next.is_empty() {
            break;
        }
        steps.push(SimulationStep {
            depth,
            nodes: next.iter().map(|s| s.to_string()).collect(),
            edges,
        });
        frontier = next;
    }
    let sensitive: HashMap<&str, bool> = graph
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.is_sensitive()))
        .collect();
    let mut reached_sensitive: Vec<String> = seen
        .iter()
        .filter(|id| **id != start && sensitive.get(*id).copied().unwrap_or(false))
        .map(|s| s.to_string())
        .collect();
    reached_sensitive.sort();
    Some(Simulation {
        start: start.to_string(),
        reached: seen.len() - 1,
        reached_sensitive,
        total_nodes: graph.nodes.len(),
        steps,
        note: "Model-based simulation over the analysed graph. No real system was accessed.".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Edge, Node, NodeKind};

    #[test]
    fn steps_expand_by_hop() {
        let mut g = Graph::default();
        for (id, k) in [
            ("a", NodeKind::User),
            ("b", NodeKind::Role),
            ("c", NodeKind::Secret),
            ("d", NodeKind::Resource),
        ] {
            g.upsert_node(Node::new(id, k, id));
        }
        g.upsert_edge(Edge::new("a", "b", "x"));
        g.upsert_edge(Edge::new("b", "c", "x"));
        g.upsert_edge(Edge::new("c", "a", "x"));
        let s = blast_radius(&g, "a", None).unwrap();
        assert_eq!(s.steps.len(), 3);
        assert_eq!(s.steps[1].nodes, vec!["b"]);
        assert_eq!(s.steps[2].nodes, vec!["c"]);
        assert_eq!(s.reached, 2);
        assert_eq!(s.reached_sensitive, vec!["c"]);
        assert!(blast_radius(&g, "missing", None).is_none());
        let limited = blast_radius(&g, "a", Some(1)).unwrap();
        assert_eq!(limited.reached, 1);
    }
}
