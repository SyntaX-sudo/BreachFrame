//! `breachframe` — headless BreachFrame analysis for terminals and CI.

use breachframe_engine::report::{self, ReportMeta};
use breachframe_engine::{analyze, labs, AnalysisResult, ArtifactInput, Severity, ENGINE_VERSION};
use std::collections::HashMap;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "\
BreachFrame — visualize the risk, understand the breach.

USAGE:
    breachframe analyze <FILE>... [--format summary|json|html] [--output FILE]
                                  [--fail-on critical|high|medium|low] [--project NAME]
    breachframe labs
    breachframe lab <LAB_ID> [--format summary|json|html] [--fixed] [--output FILE]
    breachframe version

Supported inputs: BreachFrame environment files (YAML/JSON), Kubernetes RBAC
manifests, AWS IAM policies / authorization details, MCP configurations.
Files are parsed as data only; nothing in them is executed.

EXIT CODES:
    0  success          1  usage or I/O error
    2  findings at or above --fail-on severity were found";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Default)]
struct Opts {
    positional: Vec<String>,
    format: String,
    output: Option<String>,
    fail_on: Option<Severity>,
    project: Option<String>,
    fixed: bool,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        format: "summary".into(),
        ..Default::default()
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match a.as_str() {
            "--format" | "-f" => o.format = value("--format")?,
            "--output" | "-o" => o.output = Some(value("--output")?),
            "--project" => o.project = Some(value("--project")?),
            "--fixed" => o.fixed = true,
            "--fail-on" => {
                o.fail_on = Some(match value("--fail-on")?.as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    other => return Err(format!("unknown severity `{other}`")),
                })
            }
            s if s.starts_with('-') => return Err(format!("unknown option `{s}`")),
            _ => o.positional.push(a.clone()),
        }
    }
    if !matches!(o.format.as_str(), "summary" | "json" | "html") {
        return Err(format!("unknown format `{}`", o.format));
    }
    Ok(o)
}

fn summary(r: &AnalysisResult) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Risk score: {}/100   nodes: {}   edges: {}   policy violations: {}\n",
        r.risk_score, r.stats.nodes, r.stats.edges, r.stats.policy_violations
    ));
    for sev in Severity::ALL {
        s.push_str(&format!(
            "  {:<9}{}\n",
            sev.as_str(),
            r.stats.by_severity.get(&sev).unwrap_or(&0)
        ));
    }
    s.push_str("\nArtifacts:\n");
    for a in &r.artifacts {
        match &a.error {
            Some(e) => s.push_str(&format!("  ✗ {} — {e}\n", a.name)),
            None => s.push_str(&format!(
                "  ✓ {} ({}, {} findings)\n",
                a.name,
                a.kind.label(),
                a.findings
            )),
        }
    }
    if !r.findings.is_empty() {
        s.push_str("\nFindings:\n");
        for f in &r.findings {
            s.push_str(&format!(
                "  [{:<8}] {:<16} {}\n",
                f.severity.as_str().to_uppercase(),
                f.rule_id,
                f.title
            ));
        }
    }
    s
}

fn render(r: &AnalysisResult, format: &str, project: &str) -> String {
    let meta = ReportMeta {
        tool: "BreachFrame CLI".into(),
        tool_version: ENGINE_VERSION.into(),
        project: project.into(),
        generated_at: now_ms(),
        statuses: HashMap::new(),
        notes: HashMap::new(),
    };
    match format {
        "json" => report::to_json(meta, r),
        "html" => report::to_html(meta, r),
        _ => summary(r),
    }
}

fn emit(text: &str, output: &Option<String>) -> Result<(), String> {
    match output {
        Some(path) => std::fs::write(path, text).map_err(|e| format!("cannot write {path}: {e}")),
        None => {
            println!("{text}");
            Ok(())
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let Some(cmd) = args.first() else {
        println!("{USAGE}");
        return Ok(ExitCode::from(1));
    };
    let opts = parse(&args[1..])?;
    match cmd.as_str() {
        "analyze" => {
            if opts.positional.is_empty() {
                return Err("analyze needs at least one file".into());
            }
            let mut inputs = Vec::new();
            for path in &opts.positional {
                let meta = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
                if meta.len() as usize > breachframe_engine::input::limits::MAX_ARTIFACT_BYTES {
                    return Err(format!("{path}: file exceeds the 5 MiB limit"));
                }
                let content = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
                let name = std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                inputs.push(ArtifactInput::new(name, content));
            }
            let r = analyze(&inputs, now_ms());
            let project = opts
                .project
                .clone()
                .unwrap_or_else(|| "CLI analysis".into());
            emit(&render(&r, &opts.format, &project), &opts.output)?;
            if let Some(threshold) = opts.fail_on {
                if r.findings.iter().any(|f| f.severity >= threshold) {
                    return Ok(ExitCode::from(2));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        "labs" => {
            for l in labs::all() {
                println!("{:<28} {:<18} {}", l.id, l.category, l.title);
            }
            Ok(ExitCode::SUCCESS)
        }
        "lab" => {
            let id = opts
                .positional
                .first()
                .ok_or("lab needs a lab id (see `breachframe labs`)")?;
            let run = labs::run(id, now_ms()).ok_or_else(|| format!("unknown lab `{id}`"))?;
            let (r, variant) = if opts.fixed {
                (&run.fixed, "fixed")
            } else {
                (&run.vulnerable, "vulnerable")
            };
            emit(
                &render(
                    r,
                    &opts.format,
                    &format!("Lab: {} ({variant})", run.lab.title),
                ),
                &opts.output,
            )?;
            Ok(ExitCode::SUCCESS)
        }
        "version" | "--version" | "-V" => {
            println!("breachframe {ENGINE_VERSION}");
            Ok(ExitCode::SUCCESS)
        }
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options() {
        let o = parse(&[
            "a.json".into(),
            "--format".into(),
            "json".into(),
            "--fail-on".into(),
            "high".into(),
        ])
        .unwrap();
        assert_eq!(o.positional, vec!["a.json"]);
        assert_eq!(o.format, "json");
        assert_eq!(o.fail_on, Some(Severity::High));
        assert!(parse(&["--format".into(), "pdf".into()]).is_err());
        assert!(parse(&["--wat".into()]).is_err());
    }

    #[test]
    fn lab_command_runs() {
        assert_eq!(
            run(vec![
                "lab".into(),
                "api-bola".into(),
                "--format".into(),
                "json".into(),
                "--output".into(),
                std::env::temp_dir()
                    .join("bf-cli-test.json")
                    .to_string_lossy()
                    .into()
            ])
            .unwrap(),
            ExitCode::SUCCESS
        );
        assert!(run(vec!["lab".into(), "nope".into()]).is_err());
    }
}
