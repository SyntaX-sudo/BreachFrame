// Typed wrappers around the Tauri IPC commands defined in src-tauri/src/commands.rs.
import { invoke } from '@tauri-apps/api/core';
import type {
  ActivityRow,
  AnalysisDetail,
  AnalysisRow,
  AppInfo,
  ArtifactRow,
  Comparison,
  Dashboard,
  DiscoveredConfig,
  FindingFilter,
  FindingStatus,
  Graph,
  ImportResult,
  Lab,
  LabRun,
  ProjectSummary,
  RunOutcome,
  Simulation,
  StoredFinding,
} from './types';

/** True when running inside the Tauri desktop shell. */
export function hasBackend(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

export class ApiError extends Error {
  readonly command: string;
  constructor(command: string, message: string) {
    super(message);
    this.command = command;
    this.name = 'ApiError';
  }
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (e) {
    const message = typeof e === 'string' ? e : e instanceof Error ? e.message : JSON.stringify(e);
    throw new ApiError(command, message);
  }
}

export const api = {
  appInfo: () => call<AppInfo>('app_info'),
  dashboard: () => call<Dashboard>('get_dashboard'),
  activity: (projectId?: number | null, limit = 100) => call<ActivityRow[]>('list_activity', { projectId: projectId ?? null, limit }),

  listProjects: () => call<ProjectSummary[]>('list_projects'),
  getProject: (id: number) => call<ProjectSummary>('get_project', { id }),
  createProject: (name: string, description = '') => call<ProjectSummary>('create_project', { name, description }),
  updateProject: (id: number, name: string, description = '') => call<ProjectSummary>('update_project', { id, name, description }),
  deleteProject: (id: number) => call<void>('delete_project', { id }),

  listArtifacts: (projectId: number) => call<ArtifactRow[]>('list_artifacts', { projectId }),
  importFiles: (projectId: number, paths: string[]) => call<ImportResult[]>('import_files', { projectId, paths }),
  importText: (projectId: number, name: string, content: string) => call<ArtifactRow>('import_text', { projectId, name, content }),
  artifactContent: (id: number) => call<string>('artifact_content', { id }),
  removeArtifact: (id: number) => call<void>('remove_artifact', { id }),

  runAnalysis: (projectId: number, label = '') => call<RunOutcome>('run_analysis', { projectId, label }),
  listAnalyses: (projectId: number) => call<AnalysisRow[]>('list_analyses', { projectId }),
  getAnalysis: (id: number) => call<AnalysisDetail>('get_analysis', { id }),
  deleteAnalysis: (id: number) => call<void>('delete_analysis', { id }),
  compareAnalyses: (beforeId: number, afterId: number) => call<Comparison>('compare_analyses', { beforeId, afterId }),
  simulate: (graph: Graph, start: string, maxSteps?: number) => call<Simulation>('simulate', { graph, start, maxSteps: maxSteps ?? null }),

  listFindings: (filter: FindingFilter) => call<StoredFinding[]>('list_findings', { filter }),
  updateFinding: (id: number, patch: { status?: FindingStatus; notes?: string }) =>
    call<StoredFinding>('update_finding', { id, status: patch.status ?? null, notes: patch.notes ?? null }),

  renderReport: (analysisId: number, format: 'html' | 'json') => call<string>('render_report', { analysisId, format }),
  exportReport: (analysisId: number, format: 'html' | 'json', path: string) => call<void>('export_report', { analysisId, format, path }),

  listLabs: () => call<Lab[]>('list_labs'),
  runLab: (id: string) => call<LabRun>('run_lab', { id }),
  importLab: (id: string) => call<ProjectSummary>('import_lab', { id }),
  discoverMcpConfigs: () => call<DiscoveredConfig[]>('discover_mcp_configs'),
};

export type Api = typeof api;
