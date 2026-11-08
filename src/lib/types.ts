// Mirrors the serde (camelCase) types of crates/engine and src-tauri/src/service.rs.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export type Category = 'policy' | 'rbac' | 'iam' | 'mcp' | 'secrets';
export const CATEGORIES: Category[] = ['policy', 'rbac', 'iam', 'mcp', 'secrets'];

export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'accepted_risk' | 'false_positive';
export const STATUSES: FindingStatus[] = ['open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive'];

export type NodeKind =
  | 'user'
  | 'group'
  | 'role'
  | 'service_account'
  | 'service'
  | 'api'
  | 'agent'
  | 'mcp_server'
  | 'tool'
  | 'resource'
  | 'secret'
  | 'external'
  | 'other';

export type ArtifactKind = 'environment' | 'k8s_rbac' | 'aws_iam' | 'mcp_config' | 'unknown';

export type Json = string | number | boolean | null | Json[] | { [k: string]: Json };

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  attributes?: Record<string, Json>;
  source?: string;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  relation: string;
  permissions?: string[];
  attributes?: Record<string, Json>;
  source?: string;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Evidence {
  label: string;
  value: string;
  location?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  category: Category;
  description: string;
  impact: string;
  recommendation: string;
  evidence: Evidence[];
  path?: string[];
  edgePath?: string[];
  nodes?: string[];
  source?: string;
}

export interface Selector {
  ids: string[];
  kinds: NodeKind[];
  attributes: Record<string, Json>;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  deny: { from: Selector; to: Selector; via: string[]; maxDepth?: number | null };
  recommendation: string;
  source?: string;
}

export interface ArtifactSummary {
  name: string;
  kind: ArtifactKind;
  sha256: string;
  size: number;
  nodes: number;
  edges: number;
  findings: number;
  error?: string;
}

export interface PrincipalSummary {
  id: string;
  label: string;
  kind: NodeKind;
  reachable: number;
  reachableSensitive: number;
  permissions: number;
  wildcard: boolean;
  maxSeverity?: Severity;
}

export interface McpServerSummary {
  name: string;
  transport: string;
  command?: string;
  args: string[];
  url?: string;
  envKeys: string[];
  autoApproved: string[];
  capabilities: string[];
  disabled: boolean;
  findings: number;
  maxSeverity?: Severity;
  source: string;
}

export interface Stats {
  bySeverity: Partial<Record<Severity, number>>;
  byCategory: Partial<Record<Category, number>>;
  nodes: number;
  edges: number;
  policyViolations: number;
}

export interface AnalysisResult {
  engineVersion: string;
  generatedAt: number;
  artifacts: ArtifactSummary[];
  graph: Graph;
  policies: Policy[];
  findings: Finding[];
  principals: PrincipalSummary[];
  mcpServers: McpServerSummary[];
  stats: Stats;
  riskScore: number;
}

export interface ProjectSummary {
  id: number;
  name: string;
  description: string;
  createdAt: number;
  updatedAt: number;
  artifactCount: number;
  analysisCount: number;
  latestAnalysisId: number | null;
  latestRisk: number | null;
  openFindings: number;
}

export interface ArtifactRow {
  id: number;
  projectId: number;
  name: string;
  kind: ArtifactKind;
  sha256: string;
  size: number;
  origin: string;
  importedAt: number;
}

export interface ImportResult {
  name: string;
  artifact: ArtifactRow | null;
  error: string | null;
}

export interface AnalysisRow {
  id: number;
  projectId: number;
  createdAt: number;
  label: string;
  riskScore: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  nodes: number;
  edges: number;
}

export interface AnalysisDetail {
  row: AnalysisRow;
  result: AnalysisResult;
}

export interface RunOutcome {
  analysis: AnalysisRow;
  newFindings: number;
  resolvedFindings: number;
  reopenedFindings: number;
  artifactErrors: string[];
}

export interface StoredFinding {
  id: number;
  projectId: number;
  projectName: string;
  status: FindingStatus;
  notes: string;
  present: boolean;
  firstSeen: number;
  lastSeen: number;
  lastAnalysisId: number;
  finding: Finding;
}

export interface FindingFilter {
  projectId?: number | null;
  severities?: Severity[];
  statuses?: FindingStatus[];
  categories?: Category[];
  search?: string;
  includeAbsent?: boolean;
}

export interface ActivityRow {
  id: number;
  projectId: number | null;
  projectName: string | null;
  ts: number;
  kind: string;
  message: string;
}

export interface RecentAnalysis {
  id: number;
  projectId: number;
  projectName: string;
  createdAt: number;
  riskScore: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Dashboard {
  projects: number;
  artifacts: number;
  analyses: number;
  openBySeverity: Record<Severity, number>;
  byStatus: Record<FindingStatus, number>;
  byCategory: Partial<Record<Category, number>>;
  topRules: [string, number][];
  recentAnalyses: RecentAnalysis[];
  activity: ActivityRow[];
}

export interface FindingRef {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
}

export interface Comparison {
  riskBefore: number;
  riskAfter: number;
  resolved: FindingRef[];
  introduced: FindingRef[];
  persisting: FindingRef[];
  nodesAdded: string[];
  nodesRemoved: string[];
  edgesAdded: string[];
  edgesRemoved: string[];
  severityDelta: Partial<Record<Severity, number>>;
}

export interface SimulationStep {
  depth: number;
  nodes: string[];
  edges: string[];
}

export interface Simulation {
  start: string;
  steps: SimulationStep[];
  reached: number;
  reachedSensitive: string[];
  totalNodes: number;
  note: string;
}

export interface LabArtifact {
  name: string;
  content: string;
}

export interface Lab {
  id: string;
  title: string;
  category: string;
  difficulty: string;
  summary: string;
  objectives: string[];
  attacker: string;
  walkthrough: string[];
  vulnerable: LabArtifact[];
  fixed: LabArtifact[];
}

export interface LabRun {
  lab: Lab;
  vulnerable: AnalysisResult;
  fixed: AnalysisResult;
  comparison: Comparison;
}

export interface DiscoveredConfig {
  client: string;
  path: string;
  size: number;
}

export interface AppInfo {
  version: string;
  engineVersion: string;
  dataDir: string;
  dbPath: string;
  os: string;
  arch: string;
}
