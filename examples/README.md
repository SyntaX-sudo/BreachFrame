# Examples

Deliberately insecure sample inputs, one per supported format. All credentials
are fake. They are covered by `crates/engine/tests/examples.rs`, so the findings
listed here are verified on every CI run.

| File | Format | Demonstrates |
|------|--------|--------------|
| [`environment/support-agent-platform.yaml`](environment/support-agent-platform.yaml) | BreachFrame environment | Two policy violations: a public AI agent reaching the billing DB through an MCP tool, and anonymous users reaching a payment key |
| [`kubernetes/rbac.yaml`](kubernetes/rbac.yaml) | Kubernetes RBAC | Cluster-wide secret reads, workload creation, `pods/exec`, `edit` granted to `system:authenticated` |
| [`aws/iam-policy.json`](aws/iam-policy.json) | AWS IAM policy | `iam:PassRole` escalation, `s3:*` on `*`, secret reads on `*` |
| [`mcp/claude_desktop_config.json`](mcp/claude_desktop_config.json) | MCP client config (JSONC) | Hardcoded token (redacted in output), plaintext HTTP, `curl \| sh`, broad filesystem root, unpinned package |

Try them:

```bash
# desktop app: Projects → New project → Import files → select these files → Run analysis
# CLI:
breachframe analyze examples/*/* --format html --output report.html
breachframe analyze examples/kubernetes/rbac.yaml --fail-on high   # exit code 2
```
