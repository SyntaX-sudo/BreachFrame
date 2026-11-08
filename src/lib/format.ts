import type { ArtifactKind, Category, FindingStatus, NodeKind, Severity } from './types';

export function timeAgo(ms: number, now = Date.now()): string {
  const s = Math.round((now - ms) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(ms).toLocaleDateString();
}

export function dateTime(ms: number): string {
  return new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

/** CSS variable for each severity (defined in index.css). */
export const SEVERITY_VAR: Record<Severity, string> = {
  critical: 'var(--color-sev-critical)',
  high: 'var(--color-sev-high)',
  medium: 'var(--color-sev-medium)',
  low: 'var(--color-sev-low)',
  info: 'var(--color-sev-info)',
};

export const STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Open',
  in_progress: 'In progress',
  resolved: 'Resolved',
  accepted_risk: 'Accepted risk',
  false_positive: 'False positive',
};

export const CATEGORY_LABEL: Record<Category, string> = {
  policy: 'Policy',
  rbac: 'Kubernetes RBAC',
  iam: 'AWS IAM',
  mcp: 'MCP',
  secrets: 'Secrets',
};

export const ARTIFACT_LABEL: Record<ArtifactKind, string> = {
  environment: 'Environment',
  k8s_rbac: 'Kubernetes RBAC',
  aws_iam: 'AWS IAM',
  mcp_config: 'MCP config',
  unknown: 'Unknown',
};

export const KIND_LABEL: Record<NodeKind, string> = {
  user: 'User',
  group: 'Group',
  role: 'Role',
  service_account: 'Service account',
  service: 'Service',
  api: 'API',
  agent: 'Agent',
  mcp_server: 'MCP server',
  tool: 'Tool',
  resource: 'Resource',
  secret: 'Secret',
  external: 'External',
  other: 'Other',
};

export function riskBand(score: number): { label: string; color: string } {
  if (score >= 70) return { label: 'Critical', color: SEVERITY_VAR.critical };
  if (score >= 40) return { label: 'High', color: SEVERITY_VAR.high };
  if (score >= 15) return { label: 'Elevated', color: SEVERITY_VAR.medium };
  if (score > 0) return { label: 'Low', color: SEVERITY_VAR.low };
  return { label: 'Clear', color: 'var(--color-ok)' };
}

export function pluralize(n: number, word: string, plural = `${word}s`): string {
  return `${n} ${n === 1 ? word : plural}`;
}
