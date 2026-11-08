//! HTML and JSON report generation.
//!
//! HTML reports are fully self-contained (inline CSS, no scripts, no external
//! requests) and every value coming from analysed files is HTML-escaped.

use crate::model::{AnalysisResult, Finding, Severity};
use crate::util::html_escape as esc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ReportMeta {
    pub tool: String,
    pub tool_version: String,
    pub project: String,
    pub generated_at: i64,
    /// Optional per-finding workflow status (from the Findings Manager).
    #[serde(default)]
    pub statuses: HashMap<String, String>,
    #[serde(default)]
    pub notes: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema: String,
    pub meta: ReportMeta,
    pub analysis: AnalysisResult,
}

pub fn to_json(meta: ReportMeta, analysis: &AnalysisResult) -> String {
    let report = Report {
        schema: "https://breachframe.dev/schemas/report-v1.json".into(),
        meta,
        analysis: analysis.clone(),
    };
    serde_json::to_string_pretty(&report).expect("report serializes")
}

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#ff3b5c",
        Severity::High => "#ff8a3d",
        Severity::Medium => "#f5c542",
        Severity::Low => "#4fb3ff",
        Severity::Info => "#8b95a7",
    }
}

fn format_ts(ms: i64) -> String {
    // UTC ISO-8601 without external crates (civil-from-days, H. Hinnant).
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn finding_html(f: &Finding, meta: &ReportMeta, labels: &HashMap<&str, &str>) -> String {
    let status = meta
        .statuses
        .get(&f.id)
        .map(String::as_str)
        .unwrap_or("open");
    let mut h = String::new();
    h.push_str(&format!(
        "<article class=\"finding\" id=\"f-{id}\"><header><span class=\"sev\" style=\"background:{c}\">{sev}</span><h3>{title}</h3><span class=\"meta\">{rule} · {cat:?} · status: {status}</span></header>",
        id = esc(&f.id),
        c = sev_color(f.severity),
        sev = f.severity.as_str().to_uppercase(),
        title = esc(&f.title),
        rule = esc(&f.rule_id),
        cat = f.category,
        status = esc(status),
    ));
    h.push_str(&format!("<p>{}</p>", esc(&f.description)));
    h.push_str(&format!(
        "<p><strong>Impact.</strong> {}</p>",
        esc(&f.impact)
    ));
    h.push_str(&format!(
        "<p><strong>Recommendation.</strong> {}</p>",
        esc(&f.recommendation)
    ));
    if !f.path.is_empty() {
        let chain: Vec<String> = f
            .path
            .iter()
            .map(|id| {
                format!(
                    "<code>{}</code>",
                    esc(labels.get(id.as_str()).copied().unwrap_or(id))
                )
            })
            .collect();
        h.push_str(&format!(
            "<p class=\"path\"><strong>Attack path.</strong> {}</p>",
            chain.join(" <span>→</span> ")
        ));
    }
    if !f.evidence.is_empty() {
        h.push_str("<table class=\"ev\"><tbody>");
        for e in &f.evidence {
            h.push_str(&format!(
                "<tr><th>{}</th><td><code>{}</code>{}</td></tr>",
                esc(&e.label),
                esc(&e.value),
                e.location
                    .as_ref()
                    .map(|l| format!("<div class=\"loc\">{}</div>", esc(l)))
                    .unwrap_or_default()
            ));
        }
        h.push_str("</tbody></table>");
    }
    if let Some(n) = meta.notes.get(&f.id).filter(|n| !n.trim().is_empty()) {
        h.push_str(&format!(
            "<p class=\"note\"><strong>Analyst note.</strong> {}</p>",
            esc(n)
        ));
    }
    h.push_str("</article>");
    h
}

pub fn to_html(meta: ReportMeta, a: &AnalysisResult) -> String {
    let labels: HashMap<&str, &str> = a
        .graph
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.label.as_str()))
        .collect();
    let mut sev_rows = String::new();
    for s in Severity::ALL {
        let n = a.stats.by_severity.get(&s).copied().unwrap_or(0);
        sev_rows.push_str(&format!(
            "<div class=\"tile\"><div class=\"n\" style=\"color:{}\">{n}</div><div class=\"l\">{}</div></div>",
            sev_color(s),
            s.as_str()
        ));
    }
    let mut artifacts = String::new();
    for art in &a.artifacts {
        artifacts.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code class=\"hash\">{}</code></td><td>{}</td></tr>",
            esc(&art.name),
            esc(art.kind.label()),
            art.size,
            art.findings,
            esc(&art.sha256),
            art.error.as_ref().map(|e| format!("<span class=\"err\">{}</span>", esc(e))).unwrap_or_else(|| "ok".into())
        ));
    }
    let findings: String = a
        .findings
        .iter()
        .map(|f| finding_html(f, &meta, &labels))
        .collect();
    let mut toc = String::new();
    for f in &a.findings {
        toc.push_str(&format!(
            "<tr><td><span class=\"dot\" style=\"background:{}\"></span>{}</td><td><a href=\"#f-{}\">{}</a></td><td>{}</td><td>{}</td></tr>",
            sev_color(f.severity),
            f.severity.as_str(),
            esc(&f.id),
            esc(&f.title),
            esc(&f.rule_id),
            esc(meta.statuses.get(&f.id).map(String::as_str).unwrap_or("open"))
        ));
    }
    let mut mcp = String::new();
    if !a.mcp_servers.is_empty() {
        mcp.push_str("<h2>MCP servers</h2><table><thead><tr><th>Server</th><th>Transport</th><th>Launch</th><th>Capabilities</th><th>Findings</th></tr></thead><tbody>");
        for s in &a.mcp_servers {
            let launch = s.url.clone().unwrap_or_else(|| {
                format!(
                    "{} {}",
                    s.command.clone().unwrap_or_default(),
                    s.args.join(" ")
                )
            });
            mcp.push_str(&format!(
                "<tr><td>{}{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                esc(&s.name),
                if s.disabled {
                    " <em>(disabled)</em>"
                } else {
                    ""
                },
                esc(&s.transport),
                esc(&crate::util::clip(&launch, 160)),
                esc(&s.capabilities.join(", ")),
                s.findings
            ));
        }
        mcp.push_str("</tbody></table>");
    }
    let mut policies = String::new();
    if !a.policies.is_empty() {
        policies.push_str("<h2>Policies evaluated</h2><table><thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Violations</th></tr></thead><tbody>");
        for p in &a.policies {
            let n = a
                .findings
                .iter()
                .filter(|f| f.rule_id == format!("POLICY:{}", p.id))
                .count();
            policies.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&p.id),
                esc(&p.name),
                p.severity.as_str(),
                if n == 0 {
                    "<span class=\"ok\">0 — compliant</span>".to_string()
                } else {
                    format!("<span class=\"err\">{n}</span>")
                }
            ));
        }
        policies.push_str("</tbody></table>");
    }

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>BreachFrame report — {project}</title>
<style>
:root{{--bg:#0b0e14;--panel:#121722;--line:#232b3b;--text:#d7dde8;--muted:#8b95a7;--accent:#3df5c8}}
@media (prefers-color-scheme: light){{:root{{--bg:#f6f7f9;--panel:#fff;--line:#dde1e8;--text:#1b2230;--muted:#5b6577;--accent:#0a8f72}}}}
@media print{{:root{{--bg:#fff;--panel:#fff;--line:#ccc;--text:#000;--muted:#444}} .finding{{break-inside:avoid}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:1040px;margin:0 auto;padding:32px 20px 64px}}
h1{{font-size:26px;margin:0}} h2{{font-size:18px;margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}} h3{{font-size:15px;margin:0;flex:1}}
.brand{{color:var(--accent);font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:12px}}
.muted,.meta{{color:var(--muted);font-size:12px}}
.score{{display:flex;gap:24px;align-items:center;margin-top:20px;padding:20px;background:var(--panel);border:1px solid var(--line);border-radius:10px;flex-wrap:wrap}}
.score .big{{font-size:44px;font-weight:700}} .tiles{{display:flex;gap:10px;flex-wrap:wrap}}
.tile{{min-width:84px;padding:8px 12px;border:1px solid var(--line);border-radius:8px;text-align:center}} .tile .n{{font-size:22px;font-weight:700}} .tile .l{{font-size:11px;color:var(--muted);text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}} th{{color:var(--muted);font-weight:600}}
code{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;word-break:break-all}} .hash{{font-size:10px}}
.finding{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0}}
.finding header{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px}}
.sev{{color:#000;font-size:10px;font-weight:800;padding:2px 8px;border-radius:999px;letter-spacing:.05em}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}}
.ev th{{width:160px}} .loc{{color:var(--muted);font-size:11px}} .path code{{background:rgba(127,127,127,.12);padding:1px 6px;border-radius:4px}}
.err{{color:#ff3b5c}} .ok{{color:#2fbf71}} .note{{border-left:3px solid var(--accent);padding-left:10px}}
a{{color:var(--accent)}}
</style></head><body><main>
<div class="brand">BreachFrame · Security Analysis Report</div>
<h1>{project}</h1>
<div class="muted">Generated {generated} · engine {version} · analysis of {nart} artifact(s) taken {analysed}</div>
<section class="score"><div><div class="muted">Risk score</div><div class="big">{score}<span class="muted">/100</span></div></div><div class="tiles">{sev_rows}</div>
<div class="muted">{nodes} nodes · {edges} edges · {pv} policy violation(s)</div></section>
<h2>Summary of findings</h2>
{toc_block}
<h2>Artifacts</h2>
<table><thead><tr><th>File</th><th>Type</th><th>Bytes</th><th>Findings</th><th>SHA-256</th><th>Status</th></tr></thead><tbody>{artifacts}</tbody></table>
{policies}
{mcp}
<h2>Findings</h2>
{findings}
<h2>Methodology</h2>
<p class="muted">BreachFrame parses configuration files as data only — no command, URL or script found in an artifact is executed or contacted. Attack paths are shortest paths in the merged permission graph; policy violations are paths forbidden by explicitly declared policies. Risk score = 100 × (1 − Π(1 − wᵢ)) with weights critical 0.35, high 0.20, medium 0.08, low 0.03, info 0. Credentials are shown redacted.</p>
</main></body></html>"#,
        project = esc(&meta.project),
        generated = format_ts(meta.generated_at),
        analysed = format_ts(a.generated_at),
        version = esc(&a.engine_version),
        nart = a.artifacts.len(),
        score = a.risk_score,
        nodes = a.stats.nodes,
        edges = a.stats.edges,
        pv = a.stats.policy_violations,
        toc_block = if a.findings.is_empty() {
            "<p class=\"ok\">No findings.</p>".to_string()
        } else {
            format!("<table><thead><tr><th>Severity</th><th>Finding</th><th>Rule</th><th>Status</th></tr></thead><tbody>{toc}</tbody></table>")
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{analyze, ArtifactInput};

    fn meta() -> ReportMeta {
        ReportMeta {
            tool: "BreachFrame".into(),
            tool_version: "test".into(),
            project: "<script>alert(1)</script>".into(),
            generated_at: 1_700_000_000_000,
            statuses: HashMap::new(),
            notes: HashMap::new(),
        }
    }

    #[test]
    fn html_escapes_untrusted_values() {
        let a = analyze(
            &[ArtifactInput::new(
                "<img src=x onerror=alert(1)>.json",
                r#"{"Statement":[{"Sid":"<b>x</b>","Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            )],
            0,
        );
        let html = to_html(meta(), &a);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("<b>x</b>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script"), "report must not contain scripts");
        assert!(html.contains("IAM-001"));
    }

    #[test]
    fn json_round_trips() {
        let a = analyze(
            &[ArtifactInput::new(
                "p.json",
                r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            )],
            5,
        );
        let s = to_json(meta(), &a);
        let r: Report = serde_json::from_str(&s).unwrap();
        assert_eq!(r.analysis, a);
    }

    #[test]
    fn timestamps_format() {
        assert_eq!(format_ts(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_ts(1_700_000_000_000), "2023-11-14 22:13:20 UTC");
    }
}
