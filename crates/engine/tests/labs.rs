//! Integration tests: every built-in lab must demonstrate a real violation in
//! its vulnerable variant and resolve it in its fixed variant.

use breachframe_engine::{labs, Category, Severity};

#[test]
fn every_lab_parses_and_all_artifacts_are_valid() {
    let all = labs::all();
    assert!(all.len() >= 4);
    for lab in all {
        let run = labs::run(&lab.id, 0).unwrap();
        for a in run
            .vulnerable
            .artifacts
            .iter()
            .chain(run.fixed.artifacts.iter())
        {
            assert!(
                a.error.is_none(),
                "lab {} artifact {} failed: {:?}",
                lab.id,
                a.name,
                a.error
            );
        }
        assert!(
            run.vulnerable.graph.has_node(&lab.attacker),
            "lab {} attacker node {} missing from vulnerable graph",
            lab.id,
            lab.attacker
        );
    }
}

#[test]
fn vulnerable_variants_violate_policies_and_fixed_ones_do_not() {
    for lab in labs::all() {
        let run = labs::run(&lab.id, 0).unwrap();
        assert!(
            run.vulnerable.stats.policy_violations > 0,
            "lab {} vulnerable variant has no policy violation",
            lab.id
        );
        assert_eq!(
            run.fixed.stats.policy_violations,
            0,
            "lab {} fixed variant still violates: {:#?}",
            lab.id,
            run.fixed
                .findings
                .iter()
                .filter(|f| f.category == Category::Policy)
                .map(|f| &f.title)
                .collect::<Vec<_>>()
        );
        assert!(
            run.fixed.risk_score < run.vulnerable.risk_score,
            "lab {} risk did not drop",
            lab.id
        );
        assert!(!run.comparison.resolved.is_empty());
        assert!(
            run.fixed
                .findings
                .iter()
                .all(|f| f.severity < Severity::High),
            "lab {} fixed variant has high/critical findings: {:#?}",
            lab.id,
            run.fixed
                .findings
                .iter()
                .map(|f| (&f.rule_id, &f.title))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn simulation_from_attacker_reaches_sensitive_nodes_only_when_vulnerable() {
    for lab in labs::all() {
        let run = labs::run(&lab.id, 0).unwrap();
        let v =
            breachframe_engine::simulate::blast_radius(&run.vulnerable.graph, &lab.attacker, None)
                .unwrap();
        assert!(
            !v.reached_sensitive.is_empty(),
            "lab {} attacker reaches nothing sensitive",
            lab.id
        );
    }
}

#[test]
fn k8s_lab_path_goes_through_pod_creation() {
    let run = labs::run("k8s-ci-escalation", 0).unwrap();
    let violations: Vec<_> = run
        .vulnerable
        .findings
        .iter()
        .filter(|f| f.rule_id == "POLICY:P-CI-01")
        .collect();
    assert!(!violations.is_empty(), "P-CI-01 violation expected");
    for f in &violations {
        assert!(
            f.edge_path.iter().any(|e| e.contains("|can_run_as|")),
            "{:?}",
            f.edge_path
        );
    }
    let targets: Vec<_> = violations
        .iter()
        .map(|f| f.path.last().unwrap().as_str())
        .collect();
    assert!(targets.contains(&"k8s:res:*/*"), "{targets:?}");
    assert!(
        targets.contains(&"k8s:clusterrole:cluster-admin"),
        "{targets:?}"
    );
}

#[test]
fn iam_lab_path_uses_passrole() {
    let run = labs::run("iam-passrole-escalation", 0).unwrap();
    assert!(run
        .vulnerable
        .findings
        .iter()
        .any(|f| f.rule_id == "POLICY:P-IAM-01"
            && f.edge_path.iter().any(|e| e.contains("|can_pass_role|"))));
}
