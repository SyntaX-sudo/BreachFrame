# Rules reference

Every finding has a rule id, a severity, evidence, impact and a recommendation.
Finding ids are stable fingerprints (`sha256(rule, source, key)`). That is how
BreachFrame keeps a finding's workflow status and notes across re-analyses.

Severities shown below are the defaults. Some rules adjust severity based on
scope, as noted.

## Policy violations

| Rule | Severity | Meaning |
|------|----------|---------|
| `POLICY:<id>` | from the policy | A path exists that a `deny` policy forbids. Evidence: the full path and the relation used at each hop. See [environment-format.md](environment-format.md). |

## Kubernetes RBAC

Input: YAML/JSON manifests with `Role`, `ClusterRole`, `RoleBinding`,
`ClusterRoleBinding`, `ServiceAccount` objects (multi-document YAML and `List`
objects are supported). Built-in `cluster-admin`, `admin`, `edit` and `view` are
known. Roles that are not bound to any subject are reported one severity level
lower.

| Rule | Severity | Check |
|------|----------|-------|
| RBAC-001 | critical (cluster) / high | `*` verbs on `*` resources |
| RBAC-002 | high | Read access (get/list/watch) to Secrets |
| RBAC-003 | critical | `escalate` / `bind` verbs on roles |
| RBAC-004 | critical | `impersonate` |
| RBAC-005 | high | Create pods or pod controllers |
| RBAC-006 | high | `pods/exec` / `pods/attach` |
| RBAC-007 | high | `serviceaccounts/token` create, `nodes/proxy` |
| RBAC-008 | high | Write role bindings |
| RBAC-009 | high | Modify admission webhook configurations |
| RBAC-010 | medium | Wildcard verbs or resources |
| RBAC-020 | critical (cluster) / high | Subject bound to `cluster-admin` |
| RBAC-021 | critical | Binding to `system:anonymous`, `system:unauthenticated` or `system:authenticated` |
| RBAC-022 | medium | `default` service account granted a role |
| RBAC-023 | info | Binding references a role that is not in the input |

Derived graph edges: `can_run_as` (pod creators → service accounts in scope),
`can_impersonate`, `can_escalate_to`.

## AWS IAM

Input: a single policy document (`{"Version", "Statement"}`) or the output of
`aws iam get-account-authorization-details` (users, groups, roles, inline and
managed policies, trust policies; URL-encoded documents are decoded).
Findings are per statement, and the statement's `Sid` (or `Statement[n]`) is
part of the title.

| Rule | Severity | Check |
|------|----------|-------|
| IAM-001 | critical (high with a Condition) | `Action: "*"` on `Resource: "*"`, or `AdministratorAccess` attached |
| IAM-002 | high (critical for iam/sts/organizations) | Service wildcards (`s3:*`) on `Resource: "*"` |
| IAM-003 | high | Privilege-escalation actions (17 tracked, e.g. `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `lambda:UpdateFunctionCode`) on `*` |
| IAM-004 | high | `Allow` combined with `NotAction` |
| IAM-005 | critical | Trust policy allows `Principal: "*"` without a Condition |
| IAM-006 | medium | Secret-reading actions (Secrets Manager, SSM parameters, KMS decrypt, S3 GetObject) on `*` |

Derived graph edges: `can_pass_role` from principals that may pass any role.

## MCP configurations

Input: MCP client configuration files: Claude Desktop
(`claude_desktop_config.json`), Claude Code (`~/.claude.json`, `.mcp.json`),
VS Code (`mcp.json`, `settings.json` → `mcp.servers`), Cursor, Windsurf, Gemini
CLI. JSON with comments and trailing commas (JSONC) is accepted.

**BreachFrame never runs, installs or connects to anything found in these
files.** Commands, URLs and scripts are only parsed as text.

| Rule | Severity | Check |
|------|----------|-------|
| MCP-001 | high | Hardcoded credentials in `env`, `headers`, `args` or URL (values are redacted; `${env:VAR}`-style references are not flagged) |
| MCP-002 | high | Remote server over plaintext `http://` (localhost excluded) |
| MCP-003 | medium | Unpinned `npx` / `uvx` package or untagged container image |
| MCP-004 | high | Shell interpreter with an inline or encoded script |
| MCP-005 | critical | Remote script piped into an interpreter (`curl … \| sh`) |
| MCP-006 | high / critical | Privileged container, Docker socket, host network/PID, broad host mounts, added capabilities |
| MCP-007 | high | Filesystem server exposing `/`, a drive root or a whole home directory |
| MCP-008 | high | Auto-approved tools (`alwaysAllow`, `autoApprove`, `trust: true`) |
| MCP-009 | medium | Flags that disable sandboxing or permission checks |
| MCP-010 | medium | Executable launched from a temporary directory |

## Secret detection

Secrets are detected (and always redacted) in MCP configurations: `env`,
`headers`, `args` and URLs. Environment files are not scanned for secrets, so
don't put real credentials in them. Patterns: AWS access keys, GitHub / GitLab / Slack / Stripe / Google
tokens, Anthropic and OpenAI-style API keys, private key blocks, JWTs,
credentials embedded in URLs, and bearer tokens.

## Graph node ids

Use these ids in environment-file policies to reference nodes generated from
other artifacts:

| Source | Node ids |
|--------|----------|
| Kubernetes | `k8s:sa:<ns>/<name>`, `k8s:user:<name>`, `k8s:group:<name>`, `k8s:role:<ns>/<name>`, `k8s:clusterrole:<name>`, `k8s:res:<scope>/<resource>` |
| AWS IAM | `aws:user:<name>`, `aws:group:<name>`, `aws:role:<name>`, `aws:policy:<file>` (standalone policy documents), `aws:service:<svc>` / `aws:principal:<p>` / `aws:federated:<p>` (trust principals), `aws:res:<arn>`, `aws:res:<service>:*`, `aws:res:*` |
| MCP | `mcp:client:<file>`, `mcp:server:<file>:<name>`, `mcp:capability:<cap>`, `net:host:<host>` |
