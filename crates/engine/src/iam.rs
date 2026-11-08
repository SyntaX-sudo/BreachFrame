//! AWS IAM auditor. Accepts a single policy document (`{"Version", "Statement"}`)
//! or the output of `aws iam get-account-authorization-details`.

use crate::model::{
    Category, Edge, Evidence, Finding, FindingBuilder, Graph, Node, NodeKind, Partial, Severity,
};
use crate::util::{clip, glob_match, percent_decode, str_list};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct Statement {
    sid: Option<String>,
    allow: bool,
    actions: Vec<String>,
    not_action: bool,
    resources: Vec<String>,
    not_resource: bool,
    principals: Vec<String>,
    has_condition: bool,
}

/// Escalation primitives documented in public AWS privilege-escalation research.
const ESCALATION_ACTIONS: [&str; 17] = [
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
    "cloudformation:CreateStack",
];

const SECRET_ACTIONS: [&str; 5] = [
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "kms:Decrypt",
    "s3:GetObject",
];

fn parse_doc(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) => {
            let decoded = percent_decode(s);
            serde_json::from_str(&decoded).ok()
        }
        Value::Object(_) => Some(v.clone()),
        _ => None,
    }
}

fn principals(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Object(o)) => o
            .iter()
            .flat_map(|(k, v)| {
                str_list(Some(v))
                    .into_iter()
                    .map(move |p| format!("{k}:{p}"))
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn statements(doc: &Value) -> Vec<Statement> {
    let list = match doc.get("Statement") {
        Some(Value::Array(a)) => a.clone(),
        Some(o @ Value::Object(_)) => vec![o.clone()],
        _ => Vec::new(),
    };
    list.iter()
        .map(|s| {
            let not_action = s.get("NotAction").is_some();
            let not_resource = s.get("NotResource").is_some();
            Statement {
                sid: s.get("Sid").and_then(Value::as_str).map(str::to_string),
                allow: s
                    .get("Effect")
                    .and_then(Value::as_str)
                    .map(|e| e.eq_ignore_ascii_case("allow"))
                    .unwrap_or(false),
                actions: str_list(s.get(if not_action { "NotAction" } else { "Action" })),
                not_action,
                resources: str_list(s.get(if not_resource {
                    "NotResource"
                } else {
                    "Resource"
                })),
                not_resource,
                principals: principals(s.get("Principal")),
                has_condition: s
                    .get("Condition")
                    .map(|c| c.as_object().map(|o| !o.is_empty()).unwrap_or(false))
                    .unwrap_or(false),
            }
        })
        .collect()
}

impl Statement {
    fn covers(&self, action: &str) -> bool {
        let m = self.actions.iter().any(|p| glob_match(p, action));
        if self.not_action {
            !m
        } else {
            m
        }
    }
    fn any_resource(&self) -> bool {
        self.not_resource || self.resources.iter().any(|r| r == "*")
    }
    fn label(&self, idx: usize) -> String {
        self.sid
            .clone()
            .unwrap_or_else(|| format!("Statement[{idx}]"))
    }
}

struct Ctx<'a> {
    source: &'a str,
    findings: Vec<Finding>,
    graph: Graph,
}

fn audit_permissions(
    ctx: &mut Ctx,
    owner_id: &str,
    owner_label: &str,
    policy_name: &str,
    doc: &Value,
) {
    for (i, st) in statements(doc).iter().enumerate() {
        if !st.allow {
            continue;
        }
        let loc = format!("{policy_name} › {}", st.label(i));
        let st_ev = Evidence::new(
            "Statement",
            clip(
                &format!(
                    "{}={:?} {}={:?}{}",
                    if st.not_action { "NotAction" } else { "Action" },
                    st.actions,
                    if st.not_resource {
                        "NotResource"
                    } else {
                        "Resource"
                    },
                    st.resources,
                    if st.has_condition {
                        " (conditional)"
                    } else {
                        ""
                    }
                ),
                400,
            ),
        )
        .at(loc.clone());
        let key = format!("{owner_id}:{policy_name}:{i}");
        // Findings are per statement; name the statement so two findings of
        // the same rule in one policy are distinguishable.
        let st_label = st.label(i);
        let base = |rule: &str, sev: Severity, title: String| {
            FindingBuilder::new(
                rule,
                sev,
                Category::Iam,
                format!("{title} — statement {st_label}"),
            )
            .key(key.clone())
            .evidence(st_ev.clone())
            .evidence(Evidence::new("Attached to", owner_label.to_string()))
            .node(owner_id.to_string())
        };
        let full_admin = st.covers("*") || st.actions.iter().any(|a| a == "*");
        if full_admin && st.any_resource() && !st.not_action {
            let sev = if st.has_condition {
                Severity::High
            } else {
                Severity::Critical
            };
            ctx.findings.push(
                base("IAM-001", sev, format!("{owner_label} has full administrator access ({policy_name})"))
                    .description("The statement allows every action on every resource.")
                    .impact("Complete control of the AWS account, including IAM, data and billing.")
                    .recommendation("Replace `Action: \"*\"` with the specific service actions required, scoped to explicit resource ARNs.")
                    .source(ctx.source)
                    .build(),
            );
        } else if st.not_action {
            ctx.findings.push(
                base("IAM-004", Severity::High, format!("{owner_label} uses Allow + NotAction ({policy_name})"))
                    .description("`NotAction` with `Allow` grants every action except those listed, including services and actions released in the future.")
                    .impact("Usually far broader than intended; often equivalent to admin.")
                    .recommendation("Use an explicit `Action` allow-list instead of `NotAction`.")
                    .source(ctx.source)
                    .build(),
            );
        } else {
            let wildcard_services: Vec<_> = st
                .actions
                .iter()
                .filter(|a| a.ends_with(":*"))
                .cloned()
                .collect();
            if !wildcard_services.is_empty() && st.any_resource() {
                let critical = wildcard_services
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case("iam:*") || a.eq_ignore_ascii_case("sts:*"));
                ctx.findings.push(
                    base(
                        "IAM-002",
                        if critical { Severity::Critical } else { Severity::High },
                        format!("{owner_label} has service-wide wildcards on all resources ({})", wildcard_services.join(", ")),
                    )
                    .description("Service-level wildcards (`service:*`) on `Resource: \"*\"` grant every current and future action of the service.")
                    .impact(if critical { "Full IAM/STS control is equivalent to account administrator." } else { "Broad data and configuration access within the service." })
                    .recommendation("List the specific actions needed and scope `Resource` to the ARNs in use.")
                    .source(ctx.source)
                    .build(),
                );
            }
            if !st.has_condition {
                let esc: Vec<_> = ESCALATION_ACTIONS
                    .iter()
                    .filter(|a| st.covers(a))
                    .copied()
                    .collect();
                let passrole_star = esc.contains(&"iam:PassRole") && st.any_resource();
                let esc_other: Vec<_> = esc
                    .iter()
                    .filter(|a| **a != "iam:PassRole")
                    .copied()
                    .collect();
                if (passrole_star || !esc_other.is_empty()) && !full_admin {
                    let mut shown = esc_other.clone();
                    if passrole_star {
                        shown.insert(0, "iam:PassRole (Resource *)");
                    }
                    ctx.findings.push(
                        base("IAM-003", Severity::High, format!("{owner_label} holds privilege-escalation permissions"))
                            .description("These actions let a principal grant itself additional permissions, or run code as a more privileged role.")
                            .impact("Escalation to any role that can be passed or any policy that can be attached — frequently full admin.")
                            .recommendation("Remove the escalation actions or constrain them: scope `iam:PassRole` to specific role ARNs with an `iam:PassedToService` condition, and use permission boundaries.")
                            .evidence(Evidence::new("Escalation actions", shown.join(", ")))
                            .source(ctx.source)
                            .build(),
                    );
                }
                let sec: Vec<_> = SECRET_ACTIONS
                    .iter()
                    .filter(|a| st.covers(a))
                    .copied()
                    .collect();
                if !sec.is_empty() && st.any_resource() && !full_admin {
                    ctx.findings.push(
                        base("IAM-006", Severity::Medium, format!("{owner_label} can read secrets on all resources"))
                            .description("Secret-reading actions are granted on `Resource: \"*\"`.")
                            .impact("Access to every secret, parameter, decryptable key or object in the account.")
                            .recommendation("Scope secret access to the specific secret / parameter / bucket ARNs the workload uses.")
                            .evidence(Evidence::new("Actions", sec.join(", ")))
                            .source(ctx.source)
                            .build(),
                    );
                }
            }
        }

        // Graph edges: owner -> resource. `Resource: "*"` is modelled per
        // service so that e.g. `logs:*` on `*` is not confused with admin.
        let admin_like = (full_admin && !st.not_action) || st.not_action;
        let resources = if st.not_resource {
            vec!["*".to_string()]
        } else {
            st.resources.clone()
        };
        for r in resources.iter().take(50) {
            if r == "*" {
                if admin_like {
                    ctx.graph.upsert_node(
                        Node::new("aws:res:*", NodeKind::Resource, "All AWS resources (*)")
                            .with_attr("sensitivity", "critical"),
                    );
                    ctx.graph.upsert_edge(
                        Edge::new(owner_id, "aws:res:*", "allow")
                            .with_permissions(st.actions.iter().take(25).cloned()),
                    );
                    continue;
                }
                let mut by_service: std::collections::BTreeMap<String, Vec<String>> =
                    Default::default();
                for a in &st.actions {
                    let svc = a.split(':').next().unwrap_or(a).to_ascii_lowercase();
                    by_service.entry(svc).or_default().push(a.clone());
                }
                for (svc, acts) in by_service {
                    let rid = format!("aws:res:{svc}:*");
                    let sens = match svc.as_str() {
                        "iam" | "sts" | "organizations" => "critical",
                        "secretsmanager" | "kms" | "ssm" | "s3" | "dynamodb" | "rds" => "high",
                        _ => "medium",
                    };
                    let kind = if matches!(svc.as_str(), "secretsmanager" | "ssm") {
                        NodeKind::Secret
                    } else {
                        NodeKind::Resource
                    };
                    ctx.graph.upsert_node(
                        Node::new(&rid, kind, format!("All {svc} resources (*)"))
                            .with_attr("sensitivity", sens),
                    );
                    ctx.graph.upsert_edge(
                        Edge::new(owner_id, &rid, "allow")
                            .with_permissions(acts.into_iter().take(25)),
                    );
                }
                continue;
            }
            let rid = format!("aws:res:{r}");
            let kind = if r.contains(":secretsmanager:")
                || (r.contains(":ssm:") && r.contains("parameter/"))
            {
                NodeKind::Secret
            } else {
                NodeKind::Resource
            };
            ctx.graph.upsert_node(Node::new(&rid, kind, clip(r, 80)));
            ctx.graph.upsert_edge(
                Edge::new(owner_id, &rid, "allow")
                    .with_permissions(st.actions.iter().take(25).cloned()),
            );
        }
    }
}

fn audit_trust(ctx: &mut Ctx, role_id: &str, role_label: &str, doc: &Value) {
    for (i, st) in statements(doc).iter().enumerate() {
        if !st.allow {
            continue;
        }
        for p in &st.principals {
            let public = p == "*" || p == "AWS:*";
            if public && !st.has_condition {
                ctx.findings.push(
                    FindingBuilder::new("IAM-005", Severity::Critical, Category::Iam, format!("{role_label} can be assumed by anyone"))
                        .key(format!("{role_id}:trust:{i}"))
                        .description("The trust policy allows `Principal: \"*\"` without conditions.")
                        .impact("Any AWS account in the world can assume the role and use its permissions.")
                        .recommendation("Restrict the principal to specific account or role ARNs and add `sts:ExternalId` / `aws:PrincipalOrgID` conditions.")
                        .evidence(Evidence::new("Trust statement", st.label(i)).at(format!("{role_label} AssumeRolePolicyDocument")))
                        .node(role_id.to_string())
                        .source(ctx.source)
                        .build(),
                );
            }
            let (pid, kind, label) = if public {
                (
                    "aws:anyone".to_string(),
                    NodeKind::External,
                    "Anyone (Principal *)".to_string(),
                )
            } else if let Some(arn) = p.strip_prefix("AWS:") {
                let kind = if arn.contains(":user/") {
                    NodeKind::User
                } else if arn.contains(":role/") {
                    NodeKind::Role
                } else {
                    NodeKind::External
                };
                (arn.to_string(), kind, short_arn(arn))
            } else if let Some(svc) = p.strip_prefix("Service:") {
                (
                    format!("aws:service:{svc}"),
                    NodeKind::Service,
                    svc.to_string(),
                )
            } else if let Some(fed) = p.strip_prefix("Federated:") {
                (
                    format!("aws:federated:{fed}"),
                    NodeKind::External,
                    format!("federated {}", clip(fed, 60)),
                )
            } else {
                (
                    format!("aws:principal:{p}"),
                    NodeKind::External,
                    clip(p, 60),
                )
            };
            let mut n = Node::new(&pid, kind, label);
            if public {
                n = n.with_attr("public", true);
            }
            ctx.graph.upsert_node(n);
            ctx.graph.upsert_edge(
                Edge::new(&pid, role_id, "can_assume").with_permissions(["sts:AssumeRole"]),
            );
        }
    }
}

fn short_arn(arn: &str) -> String {
    arn.rsplit(':').next().unwrap_or(arn).to_string()
}

pub fn analyze(doc: &Value, source: &str) -> Partial {
    let mut ctx = Ctx {
        source,
        findings: Vec::new(),
        graph: Graph::default(),
    };

    if doc.get("Statement").is_some() || doc.get("PolicyDocument").is_some() {
        let pd = doc
            .get("PolicyDocument")
            .and_then(parse_doc)
            .unwrap_or_else(|| doc.clone());
        let owner = format!("aws:policy:{source}");
        let label = doc
            .get("PolicyName")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("Policy {source}"));
        let has_principal = statements(&pd).iter().any(|s| !s.principals.is_empty());
        ctx.graph.upsert_node(
            Node::new(&owner, NodeKind::Role, label.clone()).with_attr("platform", "aws"),
        );
        if has_principal {
            audit_trust(&mut ctx, &owner, &label, &pd);
        }
        audit_permissions(&mut ctx, &owner, &label, &label, &pd);
    } else {
        // Managed policies: ARN -> default version document.
        let mut managed: HashMap<String, (String, Value)> = HashMap::new();
        for p in doc
            .get("Policies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let arn = p
                .get("Arn")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = p
                .get("PolicyName")
                .and_then(Value::as_str)
                .unwrap_or(&arn)
                .to_string();
            let version = p
                .get("PolicyVersionList")
                .and_then(Value::as_array)
                .and_then(|vs| {
                    vs.iter()
                        .find(|v| v.get("IsDefaultVersion").and_then(Value::as_bool) == Some(true))
                        .or(vs.first())
                })
                .and_then(|v| v.get("Document"))
                .and_then(parse_doc);
            if let Some(d) = version {
                managed.insert(arn, (name, d));
            }
        }
        let admin_doc =
            serde_json::json!({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]});

        let attach = |ctx: &mut Ctx, owner_id: &str, owner_label: &str, entity: &Value| {
            for ip in entity
                .get("UserPolicyList")
                .or_else(|| entity.get("GroupPolicyList"))
                .or_else(|| entity.get("RolePolicyList"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let name = ip
                    .get("PolicyName")
                    .and_then(Value::as_str)
                    .unwrap_or("inline");
                if let Some(d) = ip.get("PolicyDocument").and_then(parse_doc) {
                    audit_permissions(ctx, owner_id, owner_label, &format!("inline:{name}"), &d);
                }
            }
            for mp in entity
                .get("AttachedManagedPolicies")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let arn = mp.get("PolicyArn").and_then(Value::as_str).unwrap_or("");
                if let Some((name, d)) = managed.get(arn) {
                    audit_permissions(ctx, owner_id, owner_label, name, d);
                } else if arn.ends_with(":policy/AdministratorAccess") {
                    audit_permissions(
                        ctx,
                        owner_id,
                        owner_label,
                        "AdministratorAccess",
                        &admin_doc,
                    );
                }
            }
        };

        for g in doc
            .get("GroupDetailList")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let arn = g
                .get("Arn")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = g
                .get("GroupName")
                .and_then(Value::as_str)
                .unwrap_or(&arn)
                .to_string();
            let id = if arn.is_empty() {
                format!("aws:group:{name}")
            } else {
                arn.clone()
            };
            ctx.graph
                .upsert_node(Node::new(&id, NodeKind::Group, format!("group {name}")));
            attach(&mut ctx, &id, &format!("group {name}"), g);
        }
        let group_ids: HashMap<String, String> = ctx
            .graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Group)
            .map(|n| {
                (
                    n.label.trim_start_matches("group ").to_string(),
                    n.id.clone(),
                )
            })
            .collect();
        for u in doc
            .get("UserDetailList")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let arn = u
                .get("Arn")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = u
                .get("UserName")
                .and_then(Value::as_str)
                .unwrap_or(&arn)
                .to_string();
            let id = if arn.is_empty() {
                format!("aws:user:{name}")
            } else {
                arn.clone()
            };
            ctx.graph
                .upsert_node(Node::new(&id, NodeKind::User, format!("user {name}")));
            for g in str_list(u.get("GroupList")) {
                let gid = group_ids
                    .get(&g)
                    .cloned()
                    .unwrap_or_else(|| format!("aws:group:{g}"));
                ctx.graph
                    .upsert_node(Node::new(&gid, NodeKind::Group, format!("group {g}")));
                ctx.graph.upsert_edge(Edge::new(&id, &gid, "member_of"));
            }
            attach(&mut ctx, &id, &format!("user {name}"), u);
        }
        for r in doc
            .get("RoleDetailList")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let arn = r
                .get("Arn")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = r
                .get("RoleName")
                .and_then(Value::as_str)
                .unwrap_or(&arn)
                .to_string();
            let id = if arn.is_empty() {
                format!("aws:role:{name}")
            } else {
                arn.clone()
            };
            ctx.graph
                .upsert_node(Node::new(&id, NodeKind::Role, format!("role {name}")));
            if let Some(trust) = r.get("AssumeRolePolicyDocument").and_then(parse_doc) {
                audit_trust(&mut ctx, &id, &format!("role {name}"), &trust);
            }
            attach(&mut ctx, &id, &format!("role {name}"), r);
        }
    }

    // iam:PassRole on * lets a principal reach every role: add derived edges.
    let roles: Vec<String> = ctx
        .graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Role && n.id.contains(":role/"))
        .map(|n| n.id.clone())
        .collect();
    let passers: Vec<String> = ctx
        .graph
        .edges
        .iter()
        .filter(|e| {
            (e.to == "aws:res:*" || e.to == "aws:res:iam:*")
                && e.permissions.iter().any(|p| glob_match(p, "iam:PassRole"))
        })
        .map(|e| e.from.clone())
        .collect();
    for p in passers {
        for r in &roles {
            if &p != r {
                ctx.graph.upsert_edge(
                    Edge::new(&p, r, "can_pass_role").with_attr("derived", "iam:PassRole on *"),
                );
            }
        }
    }
    for n in &mut ctx.graph.nodes {
        n.attributes
            .entry("platform".into())
            .or_insert("aws".into());
    }

    Partial {
        graph: ctx.graph,
        findings: ctx.findings,
        policies: Vec::new(),
        mcp_servers: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(p: &Partial) -> Vec<&str> {
        p.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn admin_policy_is_critical() {
        let doc = serde_json::json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]});
        let p = analyze(&doc, "admin.json");
        assert_eq!(rules(&p), vec!["IAM-001"]);
        assert_eq!(p.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn deny_statements_are_ignored() {
        let doc = serde_json::json!({"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]});
        assert!(analyze(&doc, "deny.json").findings.is_empty());
    }

    #[test]
    fn escalation_and_service_wildcards() {
        let doc = serde_json::json!({"Statement":[
            {"Sid":"Pass","Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"*"},
            {"Sid":"S3","Effect":"Allow","Action":"s3:*","Resource":"*"},
            {"Sid":"Not","Effect":"Allow","NotAction":"iam:*","Resource":"*"}
        ]});
        let r = analyze(&doc, "dev.json");
        let ids = rules(&r);
        assert!(ids.contains(&"IAM-003"));
        assert!(ids.contains(&"IAM-002"));
        assert!(ids.contains(&"IAM-004"));
        assert!(ids.contains(&"IAM-006")); // s3:* covers s3:GetObject
    }

    #[test]
    fn scoped_passrole_is_fine() {
        let doc = serde_json::json!({"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/lambda-exec"}]});
        assert!(analyze(&doc, "ok.json").findings.is_empty());
    }

    #[test]
    fn authorization_details_graph() {
        let enc = "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%22%2A%22%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D";
        let doc = serde_json::json!({
            "UserDetailList":[{"UserName":"alice","Arn":"arn:aws:iam::1:user/alice","GroupList":["devs"],
                "AttachedManagedPolicies":[{"PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]}],
            "GroupDetailList":[{"GroupName":"devs","Arn":"arn:aws:iam::1:group/devs",
                "GroupPolicyList":[{"PolicyName":"pass","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}}]}],
            "RoleDetailList":[{"RoleName":"open","Arn":"arn:aws:iam::1:role/open","AssumeRolePolicyDocument":enc}],
            "Policies":[]
        });
        let p = analyze(&doc, "auth.json");
        let ids = rules(&p);
        assert!(ids.contains(&"IAM-001"));
        assert!(ids.contains(&"IAM-003"));
        assert!(ids.contains(&"IAM-005"));
        assert!(p
            .graph
            .edges
            .iter()
            .any(|e| e.from == "arn:aws:iam::1:user/alice" && e.to == "arn:aws:iam::1:group/devs"));
        assert!(p
            .graph
            .edges
            .iter()
            .any(|e| e.from == "aws:anyone" && e.relation == "can_assume"));
        assert!(p
            .graph
            .edges
            .iter()
            .any(|e| e.relation == "can_pass_role" && e.to == "arn:aws:iam::1:role/open"));
    }
}
