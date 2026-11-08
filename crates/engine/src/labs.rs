//! Built-in, offline training labs. Each lab ships a vulnerable and a fixed
//! set of artifacts that are analysed by the same engine as user files.

use crate::analyze::{analyze, ArtifactInput};
use crate::compare::{compare, Comparison};
use crate::model::AnalysisResult;
use serde::{Deserialize, Serialize};

const SOURCES: [&str; 4] = [
    include_str!("../labs/mcp-confused-deputy.yaml"),
    include_str!("../labs/k8s-ci-escalation.yaml"),
    include_str!("../labs/iam-passrole-escalation.yaml"),
    include_str!("../labs/api-bola.yaml"),
];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabArtifact {
    pub name: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Lab {
    pub id: String,
    pub title: String,
    pub category: String,
    pub difficulty: String,
    pub summary: String,
    pub objectives: Vec<String>,
    /// Node the attacker starts from in the blast-radius simulation.
    pub attacker: String,
    pub walkthrough: Vec<String>,
    pub vulnerable: Vec<LabArtifact>,
    pub fixed: Vec<LabArtifact>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LabRun {
    pub lab: Lab,
    pub vulnerable: AnalysisResult,
    pub fixed: AnalysisResult,
    pub comparison: Comparison,
}

pub fn all() -> Vec<Lab> {
    SOURCES
        .iter()
        .map(|s| serde_yaml::from_str(s).expect("built-in lab definitions are valid"))
        .collect()
}

pub fn get(id: &str) -> Option<Lab> {
    all().into_iter().find(|l| l.id == id)
}

fn inputs(arts: &[LabArtifact]) -> Vec<ArtifactInput> {
    arts.iter()
        .map(|a| ArtifactInput::new(a.name.clone(), a.content.clone().into_bytes()))
        .collect()
}

pub fn run(id: &str, now_ms: i64) -> Option<LabRun> {
    let lab = get(id)?;
    let vulnerable = analyze(&inputs(&lab.vulnerable), now_ms);
    let fixed = analyze(&inputs(&lab.fixed), now_ms);
    let comparison = compare(&vulnerable, &fixed);
    Some(LabRun {
        lab,
        vulnerable,
        fixed,
        comparison,
    })
}
