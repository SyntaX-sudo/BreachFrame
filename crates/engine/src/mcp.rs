//! MCP (Model Context Protocol) configuration analyzer.
//!
//! Supports the `mcpServers` format (Claude Desktop, Claude Code `.mcp.json`,
//! Cursor, Windsurf), VS Code `servers` / `mcp.servers`, and per-project
//! `projects.<path>.mcpServers` blocks in `~/.claude.json`.
//!
//! **Nothing found in these files is ever executed.** Commands, arguments and
//! URLs are inspected as strings only.

use crate::model::{
    Category, Edge, Evidence, FindingBuilder, Graph, McpServerSummary, Node, NodeKind, Partial,
    Severity,
};
use crate::secrets;
use crate::util::{clip, str_list};
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;

static PIPE_TO_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|iex|invoke-expression|python3?|node)\b").unwrap()
});
static DANGEROUS_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^--?(dangerously[-\w]*|allow-all[-\w]*|no-sandbox|unsafe[-\w]*|disable-security[-\w]*|yolo|skip-permissions[-\w]*|trust-all[-\w]*)(=.*)?$").unwrap()
});
static DANGEROUS_TOOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(exec|shell|command|run|bash|terminal|write|delete|remove|rm|move|edit|eval|kill|deploy|push|merge|sql|query)").unwrap()
});

const SHELLS: [&str; 10] = [
    "bash",
    "sh",
    "zsh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];
const RUNNERS: [&str; 6] = ["npx", "bunx", "pnpx", "uvx", "pipx", "dlx"];

fn basename(cmd: &str) -> String {
    cmd.rsplit(['/', '\\'])
        .next()
        .unwrap_or(cmd)
        .to_ascii_lowercase()
}

/// Collect `(name, definition)` pairs from all supported layouts.
fn collect_servers(doc: &Value) -> Vec<(String, &Map<String, Value>)> {
    let mut blocks: Vec<(String, Option<&Value>)> = vec![
        (String::new(), doc.get("mcpServers")),
        (String::new(), doc.get("servers")),
        (String::new(), doc.pointer("/mcp/servers")),
    ];
    if let Some(Value::Object(projects)) = doc.get("projects") {
        for (path, p) in projects {
            blocks.push((format!("{} › ", clip(path, 60)), p.get("mcpServers")));
        }
    }
    let mut out = Vec::new();
    for (prefix, block) in blocks {
        if let Some(Value::Object(m)) = block {
            for (name, def) in m {
                if let Value::Object(def) = def {
                    out.push((format!("{prefix}{name}"), def));
                }
            }
        }
    }
    out
}

/// Package spec without version pin? Returns the spec when unpinned.
fn unpinned_package(runner: &str, args: &[String]) -> Option<String> {
    let spec = args
        .iter()
        .find(|a| !a.starts_with('-') && *a != "run" && *a != "exec" && *a != "dlx")?;
    let pinned = match runner {
        "uvx" | "pipx" => {
            spec.contains("==")
                || spec.contains('@')
                || args
                    .iter()
                    .any(|a| a.starts_with("--from") && a.contains("=="))
        }
        _ => {
            // npm: @scope/name@1.2.3 or name@1.2.3 (not @latest)
            let body = spec.strip_prefix('@').unwrap_or(spec);
            match body.split_once('@') {
                Some((_, v)) => {
                    !v.is_empty()
                        && v != "latest"
                        && v != "next"
                        && v.chars()
                            .next()
                            .map(|c| c.is_ascii_digit())
                            .unwrap_or(false)
                }
                None => spec.starts_with('.') || spec.starts_with('/') || spec.contains(".tgz"),
            }
        }
    };
    if pinned {
        None
    } else {
        Some(spec.clone())
    }
}

fn infer_capabilities(name: &str, command: &str, args: &[String]) -> Vec<&'static str> {
    let hay = format!("{} {} {}", name, command, args.join(" ")).to_ascii_lowercase();
    let mut caps = Vec::new();
    let has = |s: &str| hay.contains(s);
    if has("filesystem") || has("server-fs") || has("file-system") {
        caps.push("filesystem");
    }
    if has("shell")
        || has("terminal")
        || has("desktop-commander")
        || has("command")
        || SHELLS.contains(&basename(command).as_str())
    {
        caps.push("shell");
    }
    if has("puppeteer") || has("playwright") || has("browser") || has("fetch") || has("http") {
        caps.push("network");
    }
    if has("github") || has("gitlab") || has("git") {
        caps.push("source-control");
    }
    if has("postgres")
        || has("mysql")
        || has("sqlite")
        || has("mongo")
        || has("redis")
        || has("database")
        || has("supabase")
    {
        caps.push("database");
    }
    if has("docker")
        || has("kubernetes")
        || has("kubectl")
        || has("aws")
        || has("gcloud")
        || has("azure")
    {
        caps.push("infrastructure");
    }
    if has("slack") || has("gmail") || has("email") || has("discord") {
        caps.push("messaging");
    }
    caps.dedup();
    caps
}

static HOME_DIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(/home/[^/]+|/users/[^/]+|[a-z]:\\users\\[^\\]+)$").unwrap());

/// Paths that expose a whole disk, system directory or home directory.
fn broad_path(p: &str) -> bool {
    let lower = p.trim().to_ascii_lowercase();
    let trimmed = lower.trim_end_matches(['/', '\\']);
    matches!(
        trimmed,
        "" | "~"
            | "$home"
            | "${home}"
            | "${userhome}"
            | "%userprofile%"
            | "/etc"
            | "/var"
            | "/usr"
            | "/root"
            | "/home"
            | "/users"
            | "c:\\users"
    ) || (trimmed.len() == 2 && trimmed.ends_with(':'))
        || HOME_DIR.is_match(trimmed)
}

pub fn analyze(doc: &Value, source: &str) -> Partial {
    let mut graph = Graph::default();
    let mut findings = Vec::new();
    let mut summaries = Vec::new();

    let client_id = format!("mcp:client:{source}");
    graph.upsert_node(
        Node::new(
            &client_id,
            NodeKind::Agent,
            format!("MCP client ({source})"),
        )
        .with_attr("platform", "mcp"),
    );

    for (name, def) in collect_servers(doc) {
        let server_id = format!("mcp:server:{source}:{name}");
        let command = def
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let args = str_list(def.get("args"));
        let url = def
            .get("url")
            .or_else(|| def.get("serverUrl"))
            .or_else(|| def.get("httpUrl"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let transport = def
            .get("type")
            .or_else(|| def.get("transport"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                if url.is_some() {
                    "http".into()
                } else {
                    "stdio".into()
                }
            });
        let disabled = def
            .get("disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let env: Vec<(String, String)> = def
            .get("env")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            v.as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| v.to_string()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let headers: Vec<(String, String)> = def
            .get("headers")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let mut auto_approved: Vec<String> = str_list(def.get("alwaysAllow"));
        auto_approved.extend(str_list(def.get("autoApprove")));
        let trust_all = def.get("trust").and_then(Value::as_bool) == Some(true);
        if trust_all {
            auto_approved.push("* (trust: true)".into());
        }

        let loc = format!("{source} › {name}");
        let before = findings.len();
        let mut push =
            |b: FindingBuilder| findings.push(b.source(source).node(server_id.clone()).build());
        let base = |rule: &str, sev: Severity, title: String, key: &str| {
            FindingBuilder::new(rule, sev, Category::Mcp, title).key(format!("{name}:{key}"))
        };

        // MCP-001 hardcoded secrets in env / headers / args / url
        let mut secret_nodes = Vec::new();
        for (section, k, v) in env
            .iter()
            .map(|(k, v)| ("env", k, v))
            .chain(headers.iter().map(|(k, v)| ("headers", k, v)))
        {
            if let Some(m) = secrets::scan_pair(k, v) {
                secret_nodes.push(k.clone());
                push(
                    base("MCP-001", Severity::High, format!("Hardcoded credential in `{name}` {section}.{k}"), &format!("{section}:{k}"))
                        .description(format!("A {} is stored in plain text in the MCP configuration.", m.kind))
                        .impact("Anyone who can read this file (backups, dotfile repos, screen shares, other local processes) obtains the credential. MCP configs are frequently committed to git by accident.")
                        .recommendation("Move the value to the OS keychain or an environment variable and reference it (`${env:NAME}`, `${input:name}`). Rotate the exposed credential.")
                        .evidence(Evidence::new(format!("{section}.{k}"), m.redacted).at(loc.clone())),
                );
            }
        }
        for (i, a) in args.iter().enumerate() {
            if let Some(m) = secrets::scan_value(a) {
                secret_nodes.push(format!("arg{i}"));
                push(
                    base("MCP-001", Severity::High, format!("Credential passed as a command-line argument to `{name}`"), &format!("arg:{i}"))
                        .description(format!("A {} appears in the server's arguments.", m.kind))
                        .impact("Command-line arguments are visible to every local user via the process list, and end up in shell history and logs.")
                        .recommendation("Pass credentials through environment variables or a secrets manager instead of arguments, and rotate this one.")
                        .evidence(Evidence::new(format!("args[{i}]"), m.redacted).at(loc.clone())),
                );
            }
        }
        if let Some(u) = &url {
            if let Some(m) = secrets::scan_value(u) {
                push(
                    base(
                        "MCP-001",
                        Severity::High,
                        format!("Credential embedded in the URL of `{name}`"),
                        "url",
                    )
                    .description(format!("A {} is embedded in the server URL.", m.kind))
                    .impact("URLs are logged by proxies and servers and shown in UIs.")
                    .recommendation(
                        "Send credentials in an Authorization header sourced from a secret store.",
                    )
                    .evidence(Evidence::new("url", m.redacted).at(loc.clone())),
                );
            }
            // MCP-002 plaintext HTTP to non-local host
            let lower = u.to_ascii_lowercase();
            if lower.starts_with("http://") {
                let host = lower
                    .trim_start_matches("http://")
                    .split(['/', ':', '?'])
                    .next()
                    .unwrap_or("");
                if !matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1") {
                    push(
                        base("MCP-002", Severity::High, format!("`{name}` connects over unencrypted HTTP"), "http")
                            .description("The remote MCP server is reached over plain HTTP.")
                            .impact("Tool calls, results and any credentials can be read or modified by anyone on the network path (prompt-injection and data-theft vector).")
                            .recommendation("Use HTTPS with a valid certificate.")
                            .evidence(Evidence::new("url", redact_url(u)).at(loc.clone())),
                    );
                }
            }
        }

        let cmd_base = basename(&command);
        let joined = args.join(" ");

        // MCP-003 unpinned package runners / docker images
        if RUNNERS.contains(&cmd_base.trim_end_matches(".cmd").trim_end_matches(".exe")) {
            if let Some(spec) = unpinned_package(
                cmd_base.trim_end_matches(".cmd").trim_end_matches(".exe"),
                &args,
            ) {
                push(
                    base("MCP-003", Severity::Medium, format!("`{name}` runs an unpinned package ({spec})"), "unpinned")
                        .description(format!("`{cmd_base}` downloads and executes the latest published version of `{spec}` every time the client starts."))
                        .impact("A compromised or typosquatted package release runs immediately with the user's privileges (supply-chain attack).")
                        .recommendation("Pin an exact version (e.g. `package@1.4.2` or `package==1.4.2`) and review updates before bumping it.")
                        .evidence(Evidence::new("command", clip(&format!("{command} {joined}"), 300)).at(loc.clone())),
                );
            }
        }
        if cmd_base.starts_with("docker") || cmd_base.starts_with("podman") {
            let run_idx = args.iter().position(|a| a == "run");
            if let Some(ri) = run_idx {
                let mut i = ri + 1;
                let mut image = None;
                while i < args.len() {
                    let a = &args[i];
                    if a.starts_with('-') {
                        if matches!(
                            a.as_str(),
                            "-v" | "--volume"
                                | "-e"
                                | "--env"
                                | "--network"
                                | "--name"
                                | "-p"
                                | "--mount"
                                | "-u"
                                | "--user"
                                | "-w"
                                | "--env-file"
                        ) {
                            i += 1;
                        }
                    } else {
                        image = Some(a.clone());
                        break;
                    }
                    i += 1;
                }
                if let Some(img) = image {
                    let last = img.rsplit('/').next().unwrap_or(&img);
                    if !img.contains("@sha256:")
                        && (!last.contains(':') || last.ends_with(":latest"))
                    {
                        push(
                            base("MCP-003", Severity::Medium, format!("`{name}` runs an unpinned container image ({img})"), "image")
                                .description("The container image is referenced without a fixed tag or digest.")
                                .impact("A new, possibly malicious image version is pulled and executed without review.")
                                .recommendation("Pin the image by digest (`image@sha256:…`) or at least an immutable version tag.")
                                .evidence(Evidence::new("image", img.clone()).at(loc.clone())),
                        );
                    }
                }
                // MCP-006 dangerous docker options
                let mut issues = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    let next = args.get(i + 1).map(String::as_str).unwrap_or("");
                    if a == "--privileged" {
                        issues.push("--privileged".to_string());
                    }
                    if (a == "--network" && next == "host")
                        || a == "--network=host"
                        || a == "--net=host"
                    {
                        issues.push("--network host".into());
                    }
                    if a == "--pid=host" || (a == "--pid" && next == "host") {
                        issues.push("--pid host".into());
                    }
                    let vol = if a == "-v" || a == "--volume" {
                        Some(next)
                    } else {
                        a.strip_prefix("--volume=")
                            .or_else(|| a.strip_prefix("-v="))
                    };
                    if let Some(v) = vol {
                        let host = v.split(':').next().unwrap_or("");
                        if v.contains("docker.sock") {
                            issues.push(format!("Docker socket mount ({v})"));
                        } else if host == "/" || broad_path(host) {
                            issues.push(format!("broad host mount ({v})"));
                        }
                    }
                    if a.starts_with("--cap-add") {
                        issues.push(
                            format!("{a} {}", if a.contains('=') { "" } else { next })
                                .trim()
                                .to_string(),
                        );
                    }
                }
                if !issues.is_empty() {
                    let critical = issues
                        .iter()
                        .any(|i| i.contains("privileged") || i.contains("docker.sock"));
                    push(
                        base("MCP-006", if critical { Severity::Critical } else { Severity::High }, format!("`{name}` container weakens isolation"), "docker")
                            .description("The MCP server's container is started with options that break container isolation.")
                            .impact("A compromised or prompt-injected server can take over the host (privileged mode and the Docker socket are root-equivalent).")
                            .recommendation("Drop `--privileged`, never mount the Docker socket, avoid host networking/PID, and mount only the specific directories the server needs (read-only where possible).")
                            .evidence(Evidence::new("Options", issues.join("; ")).at(loc.clone())),
                    );
                }
            }
        }

        // MCP-004 shell interpreter with inline script
        if SHELLS.contains(&cmd_base.as_str()) {
            let inline = args.iter().any(|a| {
                let l = a.to_ascii_lowercase();
                matches!(
                    l.as_str(),
                    "-c" | "/c"
                        | "/k"
                        | "-command"
                        | "-c:"
                        | "-encodedcommand"
                        | "-enc"
                        | "-e"
                        | "-ec"
                )
            });
            if inline {
                let encoded = args.iter().any(|a| {
                    matches!(
                        a.to_ascii_lowercase().as_str(),
                        "-encodedcommand" | "-enc" | "-e" | "-ec"
                    )
                });
                push(
                    base("MCP-004", Severity::High, format!("`{name}` launches a shell with an inline script"), "shell")
                        .description(if encoded { "The server is started through PowerShell with a Base64-encoded command, which hides what actually runs." } else { "The server is started through a shell interpreter with an inline command string." })
                        .impact("Arbitrary shell logic runs every time the MCP client starts; it is easy to hide malicious commands in config files shared between users.")
                        .recommendation("Invoke the server binary directly with explicit arguments. Never run encoded or inline scripts from MCP configs.")
                        .evidence(Evidence::new("command", clip(&format!("{command} {joined}"), 300)).at(loc.clone())),
                );
            }
        }

        // MCP-005 remote script piped to an interpreter
        if PIPE_TO_SHELL.is_match(&joined) || PIPE_TO_SHELL.is_match(&command) {
            push(
                base("MCP-005", Severity::Critical, format!("`{name}` pipes a downloaded script into an interpreter"), "pipe")
                    .description("The startup command downloads content from the network and executes it directly.")
                    .impact("Whoever controls the URL (or the network path) gets code execution on this machine on every client start.")
                    .recommendation("Install a reviewed, pinned release instead of piping remote scripts into a shell.")
                    .evidence(Evidence::new("command", clip(&format!("{command} {joined}"), 300)).at(loc.clone())),
            );
        }

        // MCP-007 overly broad filesystem roots
        let caps = infer_capabilities(&name, &command, &args);
        if caps.contains(&"filesystem") {
            let broad: Vec<_> = args
                .iter()
                .filter(|a| !a.starts_with('-') && (a.as_str() == "/" || broad_path(a)))
                .cloned()
                .collect();
            if !broad.is_empty() {
                push(
                    base("MCP-007", Severity::High, format!("`{name}` exposes a very broad filesystem root"), "fsroot")
                        .description("The filesystem server is granted access to the root of the disk or an entire home directory.")
                        .impact("The model (and any prompt injection reaching it) can read SSH keys, cloud credentials, browser profiles and other secrets, and modify files outside the project.")
                        .recommendation("Grant only the specific project directories the agent needs; prefer read-only access where the server supports it.")
                        .evidence(Evidence::new("Allowed paths", broad.join(", ")).at(loc.clone())),
                );
            }
        }

        // MCP-008 auto-approved tools
        if !auto_approved.is_empty() {
            let dangerous: Vec<_> = auto_approved
                .iter()
                .filter(|t| t.starts_with('*') || DANGEROUS_TOOL.is_match(t))
                .cloned()
                .collect();
            push(
                base(
                    "MCP-008",
                    if dangerous.is_empty() { Severity::Medium } else { Severity::High },
                    format!("`{name}` auto-approves {} tool(s) without confirmation", auto_approved.len()),
                    "autoapprove",
                )
                .description("Tools listed in `alwaysAllow` / `autoApprove` (or `trust: true`) run without asking the user.")
                .impact(if dangerous.is_empty() { "Removes the human checkpoint that limits prompt-injection damage." } else { "Side-effecting tools (exec/write/delete/deploy) can be triggered by prompt injection with no confirmation." })
                .recommendation("Keep confirmation enabled for any tool that writes, executes, deletes or sends data. Auto-approve only read-only tools.")
                .evidence(Evidence::new("Auto-approved", clip(&auto_approved.join(", "), 300)).at(loc.clone())),
            );
        }

        // MCP-009 dangerous flags
        let flags: Vec<_> = args
            .iter()
            .filter(|a| DANGEROUS_FLAG.is_match(a))
            .cloned()
            .collect();
        if !flags.is_empty() {
            push(
                base("MCP-009", Severity::Medium, format!("`{name}` disables safety controls"), "flags")
                    .description("The server is started with flags that disable sandboxing or permission checks.")
                    .impact("Removes defence-in-depth protections the server would otherwise apply.")
                    .recommendation("Remove the flags unless strictly needed in an isolated environment.")
                    .evidence(Evidence::new("Flags", flags.join(" ")).at(loc.clone())),
            );
        }

        // MCP-010 executable from temp directory
        let lc = command.to_ascii_lowercase().replace('\\', "/");
        if lc.starts_with("/tmp/")
            || lc.contains("/appdata/local/temp/")
            || lc.starts_with("/var/tmp/")
            || lc.contains("%temp%")
        {
            push(
                base("MCP-010", Severity::Medium, format!("`{name}` runs an executable from a temporary directory"), "tmp")
                    .description("The server binary lives in a world- or user-writable temporary directory.")
                    .impact("Any local process can replace the binary and gain code execution when the MCP client starts.")
                    .recommendation("Install the server to a protected location (package manager or program directory).")
                    .evidence(Evidence::new("command", command.clone()).at(loc.clone())),
            );
        }

        let own: Vec<_> = findings[before..].iter().collect();
        let max_severity = own.iter().map(|f| f.severity).max();
        let n_findings = own.len();

        // Graph
        let mut node = Node::new(&server_id, NodeKind::McpServer, name.clone())
            .with_attr("transport", transport.clone())
            .with_attr("platform", "mcp");
        if disabled {
            node = node.with_attr("disabled", true);
        }
        graph.upsert_node(node);
        if !disabled {
            let mut e = Edge::new(&client_id, &server_id, "invokes");
            if !auto_approved.is_empty() {
                e = e
                    .with_attr("auto_approve", true)
                    .with_permissions(auto_approved.iter().take(20).cloned());
            }
            graph.upsert_edge(e);
        }
        for cap in &caps {
            let cid = format!("mcp:capability:{cap}");
            let (kind, sens) = match *cap {
                "shell" => (NodeKind::Resource, "critical"),
                "filesystem" => (NodeKind::Resource, "high"),
                "database" => (NodeKind::Resource, "high"),
                "infrastructure" => (NodeKind::Resource, "critical"),
                _ => (NodeKind::Resource, "medium"),
            };
            graph.upsert_node(
                Node::new(&cid, kind, format!("{cap} access"))
                    .with_attr("sensitivity", sens)
                    .with_attr("inferred", true),
            );
            graph
                .upsert_edge(Edge::new(&server_id, &cid, "capability").with_attr("inferred", true));
        }
        for k in &secret_nodes {
            let sid = format!("mcp:secret:{source}:{name}:{k}");
            graph.upsert_node(Node::new(
                &sid,
                NodeKind::Secret,
                format!("{k} (plaintext)"),
            ));
            graph.upsert_edge(Edge::new(&server_id, &sid, "holds_secret"));
        }
        if let Some(u) = &url {
            let host = u
                .split("://")
                .nth(1)
                .unwrap_or(u)
                .split(['/', '?'])
                .next()
                .unwrap_or("")
                .to_string();
            let hid = format!("net:host:{host}");
            graph.upsert_node(Node::new(&hid, NodeKind::External, host.clone()).with_attr(
                "public",
                !host.starts_with("localhost") && !host.starts_with("127."),
            ));
            graph.upsert_edge(Edge::new(&server_id, &hid, "connects_to"));
        }

        summaries.push(McpServerSummary {
            name: name.clone(),
            transport,
            command: if command.is_empty() {
                None
            } else {
                Some(command.clone())
            },
            args: args
                .iter()
                .map(|a| {
                    secrets::scan_value(a)
                        .map(|m| m.redacted)
                        .unwrap_or_else(|| clip(a, 200))
                })
                .collect(),
            url: url.as_deref().map(redact_url),
            env_keys: env.iter().map(|(k, _)| k.clone()).collect(),
            auto_approved,
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            disabled,
            findings: n_findings,
            max_severity,
            source: source.to_string(),
        });
    }

    Partial {
        graph,
        findings,
        policies: Vec::new(),
        mcp_servers: summaries,
    }
}

/// Remove userinfo and query strings from a URL before display.
fn redact_url(u: &str) -> String {
    let (scheme, rest) = u.split_once("://").unwrap_or(("", u));
    let rest = match rest.split_once('@') {
        Some((userinfo, after)) if !userinfo.contains('/') => format!("••••@{after}"),
        _ => rest.to_string(),
    };
    let rest = match rest.split_once('?') {
        Some((p, _)) => format!("{p}?••••"),
        None => rest,
    };
    if scheme.is_empty() {
        rest
    } else {
        format!("{scheme}://{rest}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::parse_documents;

    fn run(json: &str) -> Partial {
        analyze(
            &parse_documents(json).unwrap()[0],
            "claude_desktop_config.json",
        )
    }
    fn rules(p: &Partial) -> Vec<&str> {
        p.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn clean_config_has_no_findings() {
        let p = run(
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2025.8.21","/Users/me/projects/app"]}}}"#,
        );
        assert!(p.findings.is_empty(), "{:?}", rules(&p));
        assert_eq!(p.mcp_servers.len(), 1);
        assert_eq!(p.mcp_servers[0].capabilities, vec!["filesystem"]);
    }

    #[test]
    fn detects_secrets_without_leaking_them() {
        let p = run(
            r#"{"mcpServers":{"gh":{"command":"npx","args":["-y","@modelcontextprotocol/server-github@1.0.0"],"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"}}}}"#,
        );
        assert_eq!(rules(&p), vec!["MCP-001"]);
        let dump = serde_json::to_string(&p.findings).unwrap();
        assert!(!dump.contains("0123456789abcdefghij"));
        assert!(p.graph.nodes.iter().any(|n| n.kind == NodeKind::Secret));
    }

    #[test]
    fn env_references_are_ok() {
        let p = run(
            r#"{"servers":{"gh":{"type":"stdio","command":"docker","args":["run","-i","--rm","-e","GITHUB_TOKEN","ghcr.io/github/github-mcp-server:v0.5.0"],"env":{"GITHUB_TOKEN":"${input:github_token}"}}}}"#,
        );
        assert!(p.findings.is_empty(), "{:?}", rules(&p));
    }

    #[test]
    fn detects_dangerous_launchers() {
        let p = run(r#"{"mcpServers":{
            "a":{"command":"npx","args":["-y","some-mcp-server"]},
            "b":{"command":"bash","args":["-c","curl -fsSL https://example.com/install.sh | sh"]},
            "c":{"command":"docker","args":["run","--privileged","-v","/var/run/docker.sock:/var/run/docker.sock","evil/mcp"]},
            "d":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.0.0","/"]},
            "e":{"url":"http://mcp.example.com/sse","alwaysAllow":["run_command","read_file"]},
            "f":{"command":"powershell","args":["-EncodedCommand","SQBFAFgA"]},
            "g":{"command":"/tmp/mcp-bin","args":["--dangerously-skip-permissions"]}
        }}"#);
        let r = rules(&p);
        for id in [
            "MCP-002", "MCP-003", "MCP-004", "MCP-005", "MCP-006", "MCP-007", "MCP-008", "MCP-009",
            "MCP-010",
        ] {
            assert!(r.contains(&id), "missing {id} in {r:?}");
        }
        let docker = p.findings.iter().find(|f| f.rule_id == "MCP-006").unwrap();
        assert_eq!(docker.severity, Severity::Critical);
        let auto = p.findings.iter().find(|f| f.rule_id == "MCP-008").unwrap();
        assert_eq!(auto.severity, Severity::High);
    }

    #[test]
    fn claude_code_project_layout() {
        let p = run(
            r#"{"projects":{"/home/me/app":{"mcpServers":{"db":{"command":"uvx","args":["mcp-server-postgres"],"env":{"DATABASE_URL":"postgres://admin:hunter22@db/prod"}}}}}}"#,
        );
        let r = rules(&p);
        assert!(r.contains(&"MCP-001"));
        assert!(r.contains(&"MCP-003"));
        assert!(p.mcp_servers[0].name.contains("db"));
    }

    #[test]
    fn disabled_servers_are_not_connected() {
        let p =
            run(r#"{"mcpServers":{"x":{"command":"node","args":["server.js"],"disabled":true}}}"#);
        assert!(p.graph.edges.iter().all(|e| e.relation != "invokes"));
        assert!(p.mcp_servers[0].disabled);
    }

    #[test]
    fn url_redaction() {
        assert_eq!(
            redact_url("https://user:pw@host/x?token=abc"),
            "https://••••@host/x?••••"
        );
    }
}
