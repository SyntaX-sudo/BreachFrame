//! Kubernetes RBAC auditor: Roles, ClusterRoles, RoleBindings, ClusterRoleBindings.

use crate::model::{
    Category, Edge, Evidence, Finding, FindingBuilder, Graph, Node, NodeKind, Partial, Severity,
};
use crate::util::str_list;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Default)]
struct Rule {
    resources: Vec<String>,
    verbs: Vec<String>,
    resource_names: Vec<String>,
    non_resource_urls: Vec<String>,
}

#[derive(Debug, Clone)]
struct RoleDef {
    cluster: bool,
    name: String,
    namespace: Option<String>,
    rules: Vec<Rule>,
    builtin: bool,
}

#[derive(Debug, Clone)]
struct Subject {
    kind: String,
    name: String,
    namespace: Option<String>,
}

#[derive(Debug, Clone)]
struct Binding {
    cluster: bool,
    name: String,
    namespace: Option<String>,
    role_cluster: bool,
    role_name: String,
    subjects: Vec<Subject>,
}

const READ_VERBS: [&str; 3] = ["get", "list", "watch"];
const WRITE_VERBS: [&str; 3] = ["create", "update", "patch"];
const WORKLOADS: [&str; 7] = [
    "pods",
    "deployments",
    "daemonsets",
    "statefulsets",
    "replicasets",
    "jobs",
    "cronjobs",
];

impl Rule {
    fn verb(&self, v: &str) -> bool {
        self.verbs
            .iter()
            .any(|x| x == "*" || x.eq_ignore_ascii_case(v))
    }
    fn any_verb(&self, vs: &[&str]) -> bool {
        vs.iter().any(|v| self.verb(v))
    }
    fn resource(&self, r: &str) -> bool {
        let base = r.split('/').next().unwrap_or(r);
        self.resources
            .iter()
            .any(|x| x == "*" || x == r || (r.contains('/') && *x == format!("{base}/*")))
    }
    fn any_resource(&self, rs: &[&str]) -> bool {
        rs.iter().any(|r| self.resource(r))
    }
    fn wildcard_verbs(&self) -> bool {
        self.verbs.iter().any(|v| v == "*")
    }
    fn wildcard_resources(&self) -> bool {
        self.resources.iter().any(|r| r == "*")
    }
}

fn builtin(name: &str) -> Option<RoleDef> {
    let rule = |resources: &[&str], verbs: &[&str]| Rule {
        resources: resources.iter().map(|s| s.to_string()).collect(),
        verbs: verbs.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    let rw = [
        "get", "list", "watch", "create", "update", "patch", "delete",
    ];
    let rules = match name {
        "cluster-admin" => vec![rule(&["*"], &["*"])],
        "admin" => vec![
            rule(
                &[
                    "secrets",
                    "pods",
                    "pods/exec",
                    "pods/attach",
                    "deployments",
                    "serviceaccounts",
                    "roles",
                    "rolebindings",
                    "configmaps",
                ],
                &rw,
            ),
            rule(&["serviceaccounts"], &["impersonate"]),
        ],
        "edit" => vec![
            rule(
                &[
                    "secrets",
                    "pods",
                    "pods/exec",
                    "pods/attach",
                    "deployments",
                    "serviceaccounts",
                    "configmaps",
                ],
                &rw,
            ),
            rule(&["serviceaccounts"], &["impersonate"]),
        ],
        "view" => vec![rule(
            &["pods", "services", "configmaps", "deployments", "endpoints"],
            &["get", "list", "watch"],
        )],
        _ => return None,
    };
    Some(RoleDef {
        cluster: true,
        name: name.to_string(),
        namespace: None,
        rules,
        builtin: true,
    })
}

fn parse_rules(v: &Value) -> Vec<Rule> {
    v.get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .map(|r| Rule {
                    resources: str_list(r.get("resources")),
                    verbs: str_list(r.get("verbs")),
                    resource_names: str_list(r.get("resourceNames")),
                    non_resource_urls: str_list(r.get("nonResourceURLs")),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn flatten<'a>(docs: &'a [Value], out: &mut Vec<&'a Value>) {
    for d in docs {
        if d.get("kind").and_then(Value::as_str) == Some("List") {
            if let Some(items) = d.get("items").and_then(Value::as_array) {
                flatten(items, out);
            }
        } else {
            out.push(d);
        }
    }
}

fn meta<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.pointer(&format!("/metadata/{key}"))
        .and_then(Value::as_str)
}

struct Finder<'a> {
    source: &'a str,
    findings: Vec<Finding>,
}

impl Finder<'_> {
    fn push(&mut self, b: FindingBuilder) {
        self.findings.push(b.source(self.source).build());
    }
}

fn role_label(r: &RoleDef) -> String {
    match (&r.namespace, r.cluster) {
        (_, true) => format!("ClusterRole/{}", r.name),
        (Some(ns), false) => format!("Role/{ns}/{}", r.name),
        (None, false) => format!("Role/{}", r.name),
    }
}

fn role_key(cluster: bool, ns: Option<&str>, name: &str) -> String {
    if cluster {
        format!("ClusterRole/{name}")
    } else {
        format!("Role/{}/{name}", ns.unwrap_or("default"))
    }
}

fn downgrade(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        other => other,
    }
}

fn audit_role(role: &RoleDef, bound_to: &[String], f: &mut Finder) {
    if role.builtin {
        return;
    }
    let label = role_label(role);
    let node_id = role_node_id(role.cluster, role.namespace.as_deref(), &role.name, None);
    let bound = !bound_to.is_empty();
    let adjust = |s: Severity| if bound { s } else { downgrade(s) };
    let bound_ev = if bound {
        Evidence::new("Bound to", bound_to.join(", "))
    } else {
        Evidence::new(
            "Bound to",
            "No binding for this role in the analysed input (severity reduced one level)",
        )
    };
    let scope = if role.cluster {
        "cluster-wide"
    } else {
        "namespace"
    };
    let mut emitted: BTreeSet<&'static str> = BTreeSet::new();
    for (i, rule) in role.rules.iter().enumerate() {
        let loc = format!("{label} rules[{i}]");
        let rule_ev = Evidence::new(
            "Rule",
            format!(
                "resources={:?} verbs={:?}{}{}",
                rule.resources,
                rule.verbs,
                if rule.resource_names.is_empty() {
                    String::new()
                } else {
                    format!(" resourceNames={:?}", rule.resource_names)
                },
                if rule.non_resource_urls.is_empty() {
                    String::new()
                } else {
                    format!(" nonResourceURLs={:?}", rule.non_resource_urls)
                }
            ),
        )
        .at(loc.clone());
        let mut emit = |id: &'static str,
                        sev: Severity,
                        title: String,
                        desc: &str,
                        impact: &str,
                        rec: &str| {
            if !emitted.insert(id) {
                return;
            }
            f.push(
                FindingBuilder::new(id, adjust(sev), Category::Rbac, title)
                    .key(label.clone())
                    .description(desc)
                    .impact(impact)
                    .recommendation(rec)
                    .evidence(rule_ev.clone())
                    .evidence(bound_ev.clone())
                    .node(node_id.clone()),
            );
        };

        if rule.wildcard_verbs() && rule.wildcard_resources() {
            emit(
                "RBAC-001",
                if role.cluster { Severity::Critical } else { Severity::High },
                format!("{label} grants every verb on every resource ({scope})"),
                "The rule uses `*` for both verbs and resources, which is equivalent to cluster-admin within its scope.",
                "Any subject bound to this role has full control, including reading all secrets, creating privileged pods and granting itself more permissions.",
                "Replace wildcards with the explicit resources and verbs the workload needs. Prefer namespace-scoped Roles over ClusterRoles.",
            );
            continue;
        }
        if rule.wildcard_verbs() || rule.wildcard_resources() {
            emit(
                "RBAC-010",
                Severity::Medium,
                format!("{label} uses wildcard {}", if rule.wildcard_verbs() { "verbs" } else { "resources" }),
                "Wildcards automatically include new verbs and resources added in future Kubernetes versions or CRDs.",
                "Permissions silently expand over time and are hard to review.",
                "Enumerate verbs and resources explicitly.",
            );
        }
        if rule.resource("secrets") && rule.any_verb(&READ_VERBS) {
            let narrowed = !rule.resource_names.is_empty();
            let sev = match (narrowed, role.cluster) {
                (true, _) => Severity::Low,
                (false, true) => Severity::High,
                (false, false) => Severity::Medium,
            };
            emit(
                "RBAC-002",
                sev,
                format!("{label} can read Secrets ({scope}{})", if narrowed { ", restricted by resourceNames" } else { "" }),
                "Read access (get/list/watch) to Secrets exposes service-account tokens, TLS keys and application credentials. `list` and `watch` return full secret contents.",
                "Credential theft and lateral movement to anything those secrets unlock.",
                "Restrict secret access with `resourceNames`, avoid `list`/`watch`, or mount only the required secret into the workload.",
            );
        }
        if rule.any_resource(&["roles", "clusterroles"]) && rule.any_verb(&["escalate", "bind"]) {
            emit(
                "RBAC-003",
                Severity::Critical,
                format!("{label} can escalate or bind roles"),
                "The `escalate` and `bind` verbs bypass RBAC's built-in privilege-escalation prevention.",
                "A subject can grant itself any permission, up to cluster-admin.",
                "Remove `escalate` and `bind`. Only cluster administrators should hold them.",
            );
        }
        if rule.any_resource(&["users", "groups", "serviceaccounts", "userextras"])
            && rule.verb("impersonate")
        {
            emit(
                "RBAC-004",
                Severity::Critical,
                format!("{label} can impersonate identities"),
                "The `impersonate` verb lets a subject act as other users, groups or service accounts.",
                "The subject inherits the permissions of whoever it impersonates.",
                "Remove `impersonate`, or restrict it with `resourceNames` to a single, low-privilege identity.",
            );
        }
        if rule.any_resource(&WORKLOADS) && rule.verb("create") {
            emit(
                "RBAC-005",
                Severity::High,
                format!("{label} can create workloads ({scope})"),
                "Creating pods (directly or via controllers) allows mounting any service account and its token in the same namespace, and hostPath volumes unless admission policies block them.",
                "Privilege escalation to every service account in scope and possibly to the node.",
                "Grant workload creation only to deployment pipelines, and enforce Pod Security Admission (`restricted`) in the namespace.",
            );
        }
        if rule.any_resource(&["pods/exec", "pods/attach"]) && rule.any_verb(&["create", "get"]) {
            emit(
                "RBAC-006",
                Severity::High,
                format!("{label} can exec into pods"),
                "`pods/exec` and `pods/attach` give an interactive shell in running containers.",
                "Access to the container's filesystem, environment variables, mounted secrets and service-account token.",
                "Restrict exec to break-glass roles with audit logging.",
            );
        }
        if (rule.resource("serviceaccounts/token") && rule.verb("create"))
            || (rule.resource("nodes/proxy") && rule.any_verb(&["get", "create"]))
        {
            emit(
                "RBAC-007",
                Severity::High,
                format!("{label} can mint tokens or proxy to kubelets"),
                "`serviceaccounts/token` create mints tokens for any service account; `nodes/proxy` reaches the kubelet API directly.",
                "Identity theft or command execution on nodes.",
                "Remove these permissions from non-system roles.",
            );
        }
        if rule.any_resource(&["rolebindings", "clusterrolebindings"])
            && rule.any_verb(&WRITE_VERBS)
        {
            emit(
                "RBAC-008",
                Severity::High,
                format!("{label} can modify role bindings"),
                "Writing bindings lets a subject attach existing roles to itself (bounded by RBAC escalation checks unless it also has `bind`).",
                "Escalation to any role the subject already holds permissions for, in other namespaces too when cluster-scoped.",
                "Limit binding management to administrators or GitOps controllers.",
            );
        }
        if rule.any_resource(&[
            "mutatingwebhookconfigurations",
            "validatingwebhookconfigurations",
        ]) && rule.any_verb(&WRITE_VERBS)
        {
            emit(
                "RBAC-009",
                Severity::High,
                format!("{label} can change admission webhooks"),
                "Admission webhooks see and can mutate every object created in the cluster.",
                "Interception of secrets and injection of malicious containers cluster-wide.",
                "Restrict webhook configuration to cluster administrators.",
            );
        }
    }
}

fn subject_id(s: &Subject, default_ns: Option<&str>) -> (String, NodeKind, String) {
    match s.kind.as_str() {
        "ServiceAccount" => {
            let ns = s.namespace.as_deref().or(default_ns).unwrap_or("default");
            (
                format!("k8s:sa:{ns}/{}", s.name),
                NodeKind::ServiceAccount,
                format!("sa {ns}/{}", s.name),
            )
        }
        "Group" => (
            format!("k8s:group:{}", s.name),
            NodeKind::Group,
            format!("group {}", s.name),
        ),
        _ => (
            format!("k8s:user:{}", s.name),
            NodeKind::User,
            format!("user {}", s.name),
        ),
    }
}

fn role_node_id(cluster: bool, ns: Option<&str>, name: &str, binding_ns: Option<&str>) -> String {
    match (cluster, binding_ns) {
        (true, Some(bns)) => format!("k8s:clusterrole:{name}@{bns}"),
        (true, None) => format!("k8s:clusterrole:{name}"),
        (false, _) => format!("k8s:role:{}/{name}", ns.or(binding_ns).unwrap_or("default")),
    }
}

pub fn analyze(docs: &[Value], source: &str) -> Partial {
    let mut flat = Vec::new();
    flatten(docs, &mut flat);

    let mut roles: HashMap<String, RoleDef> = HashMap::new();
    let mut bindings = Vec::new();
    for d in flat {
        let kind = d.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = meta(d, "name").unwrap_or("<unnamed>").to_string();
        let namespace = meta(d, "namespace").map(str::to_string);
        match kind {
            "Role" | "ClusterRole" => {
                let r = RoleDef {
                    cluster: kind == "ClusterRole",
                    name: name.clone(),
                    namespace: if kind == "Role" {
                        Some(namespace.unwrap_or_else(|| "default".into()))
                    } else {
                        None
                    },
                    rules: parse_rules(d),
                    builtin: false,
                };
                roles.insert(role_key(r.cluster, r.namespace.as_deref(), &r.name), r);
            }
            "RoleBinding" | "ClusterRoleBinding" => {
                let role_kind = d
                    .pointer("/roleRef/kind")
                    .and_then(Value::as_str)
                    .unwrap_or("ClusterRole");
                let role_name = d
                    .pointer("/roleRef/name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let subjects = d
                    .get("subjects")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|s| Subject {
                                kind: s
                                    .get("kind")
                                    .and_then(Value::as_str)
                                    .unwrap_or("User")
                                    .to_string(),
                                name: s
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                namespace: s
                                    .get("namespace")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                bindings.push(Binding {
                    cluster: kind == "ClusterRoleBinding",
                    name,
                    namespace: if kind == "RoleBinding" {
                        Some(namespace.unwrap_or_else(|| "default".into()))
                    } else {
                        None
                    },
                    role_cluster: role_kind == "ClusterRole",
                    role_name,
                    subjects,
                });
            }
            _ => {}
        }
    }

    let mut f = Finder {
        source,
        findings: Vec::new(),
    };
    let mut graph = Graph::default();

    // Which subjects each role definition is bound to.
    let mut bound: HashMap<String, Vec<String>> = HashMap::new();
    for b in &bindings {
        let key = role_key(b.role_cluster, b.namespace.as_deref(), &b.role_name);
        let entry = bound.entry(key).or_default();
        for s in &b.subjects {
            entry.push(format!("{} {}", s.kind, s.name));
        }
    }

    let mut sorted_roles: Vec<_> = roles.values().collect();
    sorted_roles.sort_by_key(|r| role_label(r));
    for r in &sorted_roles {
        audit_role(
            r,
            bound
                .get(&role_key(r.cluster, r.namespace.as_deref(), &r.name))
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            &mut f,
        );
    }

    // Binding-level checks.
    for b in &bindings {
        let bkind = if b.cluster {
            "ClusterRoleBinding"
        } else {
            "RoleBinding"
        };
        let blabel = match &b.namespace {
            Some(ns) => format!("{bkind}/{ns}/{}", b.name),
            None => format!("{bkind}/{}", b.name),
        };
        let role_id = role_node_id(
            b.role_cluster,
            b.namespace.as_deref(),
            &b.role_name,
            if b.cluster {
                None
            } else {
                b.namespace.as_deref()
            },
        );
        for s in &b.subjects {
            let (sid, _, slabel) = subject_id(s, b.namespace.as_deref());
            if b.role_cluster
                && b.role_name == "cluster-admin"
                && !(s.kind == "Group" && s.name == "system:masters")
            {
                f.push(
                    FindingBuilder::new("RBAC-020", if b.cluster { Severity::Critical } else { Severity::High }, Category::Rbac, format!("{slabel} is bound to cluster-admin"))
                        .key(format!("{blabel}:{}", sid))
                        .description("cluster-admin grants unrestricted access. Through a ClusterRoleBinding it applies to every namespace; through a RoleBinding to the whole namespace.")
                        .impact("Full control of the cluster (or namespace), including all secrets and workloads.")
                        .recommendation("Bind a purpose-built role with only the permissions this subject needs. Reserve cluster-admin for break-glass accounts.")
                        .evidence(Evidence::new("Binding", blabel.clone()))
                        .evidence(Evidence::new("Subject", format!("{} {}", s.kind, s.name)))
                        .node(sid.clone())
                        .node(role_id.clone()),
                );
            }
            if matches!(
                s.name.as_str(),
                "system:anonymous" | "system:unauthenticated" | "system:authenticated"
            ) {
                f.push(
                    FindingBuilder::new("RBAC-021", Severity::Critical, Category::Rbac, format!("{blabel} grants access to {}", s.name))
                        .key(format!("{blabel}:{}", s.name))
                        .description("Binding to anonymous, unauthenticated or all-authenticated subjects exposes the role to anyone who can reach the API server (or any account at all).")
                        .impact("Unauthenticated or trivially obtained access to the role's permissions.")
                        .recommendation("Bind to specific users, groups or service accounts instead.")
                        .evidence(Evidence::new("Binding", blabel.clone()))
                        .evidence(Evidence::new("Role", b.role_name.clone()))
                        .node(sid.clone()),
                );
            }
            if s.kind == "ServiceAccount" && s.name == "default" {
                f.push(
                    FindingBuilder::new("RBAC-022", Severity::Medium, Category::Rbac, format!("default service account is granted {}", b.role_name))
                        .key(format!("{blabel}:{sid}"))
                        .description("Every pod that does not set `serviceAccountName` runs as the namespace's `default` service account, so this permission is silently shared by all of them.")
                        .impact("Any compromised pod in the namespace inherits the role.")
                        .recommendation("Create a dedicated service account for the workload that needs the role, and set `automountServiceAccountToken: false` on `default`.")
                        .evidence(Evidence::new("Binding", blabel.clone()))
                        .node(sid.clone()),
                );
            }
        }
        let key = role_key(b.role_cluster, b.namespace.as_deref(), &b.role_name);
        if !roles.contains_key(&key) && !(b.role_cluster && builtin(&b.role_name).is_some()) {
            f.push(
                FindingBuilder::new("RBAC-023", Severity::Info, Category::Rbac, format!("{blabel} references {} which is not in the input", key))
                    .key(blabel.clone())
                    .description("The referenced role was not included in the analysed manifests, so its permissions cannot be assessed.")
                    .impact("Coverage gap: effective permissions of the bound subjects are unknown.")
                    .recommendation("Include the role definition (e.g. `kubectl get clusterroles,roles -A -o yaml`) in the project.")
                    .evidence(Evidence::new("Binding", blabel.clone())),
            );
        }
    }

    // ---- Graph construction ----
    let mut service_accounts: Vec<(String, String)> = Vec::new(); // (ns, node id)
    for b in &bindings {
        for s in &b.subjects {
            if s.kind == "ServiceAccount" {
                let (sid, _, _) = subject_id(s, b.namespace.as_deref());
                let ns = s
                    .namespace
                    .clone()
                    .or(b.namespace.clone())
                    .unwrap_or_else(|| "default".into());
                if !service_accounts.iter().any(|(_, id)| id == &sid) {
                    service_accounts.push((ns, sid));
                }
            }
        }
    }

    let add_role_edges = |graph: &mut Graph,
                          role: &RoleDef,
                          node_id: &str,
                          scope: Option<&str>,
                          node_label: String| {
        let mut role_node = Node::new(node_id, NodeKind::Role, node_label)
            .with_attr("scope", scope.unwrap_or("cluster"))
            .with_attr("builtin", role.builtin);
        if role.builtin && role.name == "cluster-admin" {
            role_node = role_node.with_attr("sensitivity", "critical");
        }
        graph.upsert_node(role_node);
        let scope_s = scope.unwrap_or("*");
        let scope_label = scope
            .map(|s| format!("ns {s}"))
            .unwrap_or_else(|| "all namespaces".into());
        for rule in &role.rules {
            for res in &rule.resources {
                let rid = format!("k8s:res:{scope_s}/{res}");
                let (kind, label) = if res == "*" {
                    (NodeKind::Resource, format!("all resources ({scope_label})"))
                } else if res == "secrets" {
                    (NodeKind::Secret, format!("secrets ({scope_label})"))
                } else {
                    (NodeKind::Resource, format!("{res} ({scope_label})"))
                };
                let mut n = Node::new(&rid, kind, label);
                if res == "*" {
                    n = n.with_attr("sensitivity", "critical");
                }
                graph.upsert_node(n);
                graph.upsert_edge(
                    Edge::new(node_id, &rid, "grants").with_permissions(rule.verbs.clone()),
                );
            }
            // Derived escalation edges.
            if rule.any_resource(&WORKLOADS) && rule.verb("create") {
                for (ns, sa) in &service_accounts {
                    if scope.is_none() || scope == Some(ns.as_str()) {
                        graph.upsert_edge(Edge::new(node_id, sa, "can_run_as").with_attr(
                            "derived",
                            "create pods mounting the service account token",
                        ));
                    }
                }
            }
            if rule.any_resource(&["serviceaccounts"]) && rule.verb("impersonate") {
                for (ns, sa) in &service_accounts {
                    if scope.is_none() || scope == Some(ns.as_str()) {
                        graph.upsert_edge(
                            Edge::new(node_id, sa, "can_impersonate")
                                .with_attr("derived", "impersonate verb"),
                        );
                    }
                }
            }
            if rule.any_resource(&["roles", "clusterroles"])
                && rule.any_verb(&["escalate", "bind"])
                && !node_id.starts_with("k8s:clusterrole:cluster-admin")
            {
                let ca = "k8s:clusterrole:cluster-admin";
                graph.upsert_node(
                    Node::new(ca, NodeKind::Role, "ClusterRole/cluster-admin")
                        .with_attr("sensitivity", "critical")
                        .with_attr("builtin", true),
                );
                graph.upsert_edge(
                    Edge::new(node_id, ca, "can_escalate_to")
                        .with_attr("derived", "escalate/bind verbs"),
                );
            }
        }
    };

    for b in &bindings {
        let binding_ns = if b.cluster {
            None
        } else {
            b.namespace.as_deref()
        };
        let role = roles
            .get(&role_key(
                b.role_cluster,
                b.namespace.as_deref(),
                &b.role_name,
            ))
            .cloned()
            .or_else(|| {
                if b.role_cluster {
                    builtin(&b.role_name)
                } else {
                    None
                }
            });
        let role_id = role_node_id(
            b.role_cluster,
            b.namespace.as_deref(),
            &b.role_name,
            binding_ns,
        );
        let label = match (b.role_cluster, binding_ns) {
            (true, Some(ns)) => format!("ClusterRole/{} in {ns}", b.role_name),
            (true, None) => format!("ClusterRole/{}", b.role_name),
            (false, _) => format!(
                "Role/{}/{}",
                b.namespace.as_deref().unwrap_or("default"),
                b.role_name
            ),
        };
        let scope = if b.role_cluster {
            binding_ns
        } else {
            b.namespace.as_deref()
        };
        match &role {
            Some(r) => add_role_edges(&mut graph, r, &role_id, scope, label),
            None => graph.upsert_node(
                Node::new(&role_id, NodeKind::Role, label).with_attr("unresolved", true),
            ),
        }
        for s in &b.subjects {
            let (sid, kind, slabel) = subject_id(s, b.namespace.as_deref());
            let mut n = Node::new(&sid, kind, slabel);
            if matches!(
                s.name.as_str(),
                "system:anonymous" | "system:unauthenticated"
            ) {
                n = n.with_attr("public", true);
            }
            graph.upsert_node(n);
            graph.upsert_edge(
                Edge::new(&sid, &role_id, "bound_to").with_attr("binding", b.name.clone()),
            );
        }
    }
    for r in &sorted_roles {
        let id = role_node_id(r.cluster, r.namespace.as_deref(), &r.name, None);
        if !graph.has_node(&id) {
            add_role_edges(&mut graph, r, &id, r.namespace.as_deref(), role_label(r));
        }
    }
    for n in &mut graph.nodes {
        n.attributes
            .entry("platform".into())
            .or_insert("kubernetes".into());
    }

    Partial {
        graph,
        findings: f.findings,
        policies: Vec::new(),
        mcp_servers: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::parse_documents;

    fn run(yaml: &str) -> Partial {
        analyze(&parse_documents(yaml).unwrap(), "rbac.yaml")
    }

    fn rules(p: &Partial) -> Vec<&str> {
        p.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    const WILDCARD: &str = r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: god-mode }
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ci-god }
roleRef: { kind: ClusterRole, name: god-mode, apiGroup: rbac.authorization.k8s.io }
subjects:
  - { kind: ServiceAccount, name: ci, namespace: build }
"#;

    #[test]
    fn wildcard_cluster_role_is_critical() {
        let p = run(WILDCARD);
        let f = p.findings.iter().find(|f| f.rule_id == "RBAC-001").unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(p.graph.has_node("k8s:sa:build/ci"));
        assert!(p
            .graph
            .edges
            .iter()
            .any(|e| e.from == "k8s:sa:build/ci" && e.to == "k8s:clusterrole:god-mode"));
    }

    #[test]
    fn unbound_role_is_downgraded() {
        let p = run("kind: ClusterRole\napiVersion: rbac.authorization.k8s.io/v1\nmetadata: {name: x}\nrules:\n  - {resources: ['*'], verbs: ['*']}\n");
        assert_eq!(p.findings[0].severity, Severity::High);
    }

    #[test]
    fn secrets_and_workloads() {
        let p = run(r#"
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: deployer, namespace: prod }
rules:
  - { apiGroups: [""], resources: ["secrets"], verbs: ["get", "list"] }
  - { apiGroups: [""], resources: ["pods"], verbs: ["create"] }
  - { apiGroups: [""], resources: ["pods/exec"], verbs: ["create"] }
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: deployer, namespace: prod }
roleRef: { kind: Role, name: deployer }
subjects:
  - { kind: ServiceAccount, name: default }
  - { kind: ServiceAccount, name: payments }
"#);
        let r = rules(&p);
        assert!(r.contains(&"RBAC-002"));
        assert!(r.contains(&"RBAC-005"));
        assert!(r.contains(&"RBAC-006"));
        assert!(r.contains(&"RBAC-022"));
        // create pods => can run as every SA in the namespace
        assert!(p
            .graph
            .edges
            .iter()
            .any(|e| e.relation == "can_run_as" && e.to == "k8s:sa:prod/payments"));
        let secret = p.graph.node("k8s:res:prod/secrets").unwrap();
        assert_eq!(secret.kind, NodeKind::Secret);
    }

    #[test]
    fn escalation_verbs_and_anonymous() {
        let p = run(r#"
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: binder }
rules:
  - { resources: ["clusterroles"], verbs: ["bind", "escalate"] }
  - { resources: ["users"], verbs: ["impersonate"] }
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: oops }
roleRef: { kind: ClusterRole, name: cluster-admin }
subjects:
  - { kind: Group, name: system:unauthenticated }
"#);
        let r = rules(&p);
        assert!(r.contains(&"RBAC-003"));
        assert!(r.contains(&"RBAC-004"));
        assert!(r.contains(&"RBAC-020"));
        assert!(r.contains(&"RBAC-021"));
        assert!(p
            .graph
            .node("k8s:group:system:unauthenticated")
            .unwrap()
            .attributes
            .contains_key("public"));
    }

    #[test]
    fn view_role_is_clean_and_missing_role_reported() {
        let p = run(r#"
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: readers, namespace: dev }
roleRef: { kind: ClusterRole, name: view }
subjects: [{ kind: Group, name: devs }]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: { name: mystery, namespace: dev }
roleRef: { kind: Role, name: not-here }
subjects: [{ kind: User, name: bob }]
"#);
        assert_eq!(rules(&p), vec!["RBAC-023"]);
    }

    #[test]
    fn list_kind_is_flattened() {
        let p = run(
            r#"{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"a"},"rules":[{"resources":["*"],"verbs":["*"]}]}]}"#,
        );
        assert_eq!(rules(&p), vec!["RBAC-001"]);
    }

    #[test]
    fn fingerprints_are_stable() {
        let a = run(WILDCARD);
        let b = run(WILDCARD);
        assert_eq!(a.findings[0].id, b.findings[0].id);
    }
}
