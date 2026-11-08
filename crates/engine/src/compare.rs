//! Before & After comparison between two analysis results.

use crate::model::{AnalysisResult, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FindingRef {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
}

impl From<&Finding> for FindingRef {
    fn from(f: &Finding) -> Self {
        FindingRef {
            id: f.id.clone(),
            rule_id: f.rule_id.clone(),
            title: f.title.clone(),
            severity: f.severity,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub risk_before: u32,
    pub risk_after: u32,
    pub resolved: Vec<FindingRef>,
    pub introduced: Vec<FindingRef>,
    pub persisting: Vec<FindingRef>,
    pub nodes_added: Vec<String>,
    pub nodes_removed: Vec<String>,
    pub edges_added: Vec<String>,
    pub edges_removed: Vec<String>,
    /// after - before, per severity.
    pub severity_delta: BTreeMap<Severity, i64>,
}

/// Secondary match key. A finding in `before` and one in `after` are the same
/// when their fingerprint ids are equal *or* their (rule_id, title) pairs are
/// equal, so a fixed file with a different name still lines up with its
/// vulnerable counterpart.
fn key(f: &Finding) -> String {
    format!("{}\u{1f}{}", f.rule_id, f.title)
}

pub fn compare(before: &AnalysisResult, after: &AnalysisResult) -> Comparison {
    let b_ids: HashSet<String> = before
        .findings
        .iter()
        .flat_map(|f| [f.id.clone(), key(f)])
        .collect();
    let a_ids: HashSet<String> = after
        .findings
        .iter()
        .flat_map(|f| [f.id.clone(), key(f)])
        .collect();
    let matched = |f: &Finding, set: &HashSet<String>| set.contains(&f.id) || set.contains(&key(f));

    let resolved = before
        .findings
        .iter()
        .filter(|f| !matched(f, &a_ids))
        .map(FindingRef::from)
        .collect();
    let introduced = after
        .findings
        .iter()
        .filter(|f| !matched(f, &b_ids))
        .map(FindingRef::from)
        .collect();
    let persisting = after
        .findings
        .iter()
        .filter(|f| matched(f, &b_ids))
        .map(FindingRef::from)
        .collect();

    let bn: HashSet<&str> = before.graph.nodes.iter().map(|n| n.id.as_str()).collect();
    let an: HashSet<&str> = after.graph.nodes.iter().map(|n| n.id.as_str()).collect();
    let be: HashSet<&str> = before.graph.edges.iter().map(|e| e.id.as_str()).collect();
    let ae: HashSet<&str> = after.graph.edges.iter().map(|e| e.id.as_str()).collect();
    let sorted = |s: Vec<&str>| {
        let mut v: Vec<String> = s.into_iter().map(str::to_string).collect();
        v.sort();
        v
    };

    let mut severity_delta = BTreeMap::new();
    for s in Severity::ALL {
        let b = *before.stats.by_severity.get(&s).unwrap_or(&0) as i64;
        let a = *after.stats.by_severity.get(&s).unwrap_or(&0) as i64;
        severity_delta.insert(s, a - b);
    }

    Comparison {
        risk_before: before.risk_score,
        risk_after: after.risk_score,
        resolved,
        introduced,
        persisting,
        nodes_added: sorted(an.difference(&bn).copied().collect()),
        nodes_removed: sorted(bn.difference(&an).copied().collect()),
        edges_added: sorted(ae.difference(&be).copied().collect()),
        edges_removed: sorted(be.difference(&ae).copied().collect()),
        severity_delta,
    }
}
