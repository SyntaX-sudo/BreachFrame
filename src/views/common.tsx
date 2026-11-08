import { useCallback } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { FolderOpen, Play } from 'lucide-react';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useUi } from '../lib/store';
import { dateTime } from '../lib/format';
import type { AnalysisRow } from '../lib/types';
import { EmptyState } from '../components/ui';

export const IMPORT_FILTERS = [
  { name: 'Configuration files', extensions: ['json', 'jsonc', 'yaml', 'yml'] },
  { name: 'All files', extensions: ['*'] },
];

/** Native file picker → backend import, with a summary toast. */
export function useImportFiles() {
  const toast = useUi((s) => s.toast);
  const bump = useUi((s) => s.bump);
  return useCallback(
    async (projectId: number, paths?: string[]) => {
      let selected = paths;
      if (!selected) {
        const r = await open({ multiple: true, directory: false, filters: IMPORT_FILTERS, title: 'Import configuration files' });
        if (!r) return;
        selected = Array.isArray(r) ? r : [r];
      }
      if (selected.length === 0) return;
      try {
        const results = await api.importFiles(projectId, selected);
        const ok = results.filter((r) => r.artifact);
        const bad = results.filter((r) => r.error);
        if (ok.length) toast({ kind: 'success', title: `Imported ${ok.length} file${ok.length > 1 ? 's' : ''}`, detail: ok.map((r) => r.name).join(', ') });
        for (const b of bad) toast({ kind: 'error', title: `Rejected ${b.name}`, detail: b.error ?? undefined });
        bump();
      } catch (e) {
        toast({ kind: 'error', title: 'Import failed', detail: e instanceof Error ? e.message : String(e) });
      }
    },
    [toast, bump],
  );
}

export function useRunAnalysis() {
  const toast = useUi((s) => s.toast);
  const bump = useUi((s) => s.bump);
  const select = useUi((s) => s.selectAnalysis);
  return useCallback(
    async (projectId: number) => {
      try {
        const r = await api.runAnalysis(projectId);
        select(projectId, null);
        toast({
          kind: 'success',
          title: `Analysis #${r.analysis.id} complete — risk ${r.analysis.riskScore}`,
          detail: `${r.newFindings} new · ${r.resolvedFindings} resolved · ${r.reopenedFindings} reopened`,
        });
        for (const e of r.artifactErrors) toast({ kind: 'error', title: 'Artifact skipped', detail: e });
        bump();
        return r;
      } catch (e) {
        toast({ kind: 'error', title: 'Analysis failed', detail: e instanceof Error ? e.message : String(e) });
      }
    },
    [toast, bump, select],
  );
}

export function NeedProject({ what }: { what: string }) {
  const setView = useUi((s) => s.setView);
  return (
    <EmptyState icon={<FolderOpen size={36} />} title="No project selected" action={<button className="btn btn-primary" onClick={() => setView('projects')}>Open a project</button>}>
      Open a project tab to see its {what}. Projects hold the configuration files you import and every analysis you run.
    </EmptyState>
  );
}

export function NeedAnalysis({ projectId, hasArtifacts }: { projectId: number; hasArtifacts: boolean }) {
  const importFiles = useImportFiles();
  const run = useRunAnalysis();
  return (
    <EmptyState
      icon={<Play size={36} />}
      title={hasArtifacts ? 'Not analysed yet' : 'This project is empty'}
      action={
        hasArtifacts ? (
          <button className="btn btn-primary" onClick={() => run(projectId)}>
            <Play size={14} /> Run analysis
          </button>
        ) : (
          <button className="btn btn-primary" onClick={() => importFiles(projectId)}>
            <FolderOpen size={14} /> Import files
          </button>
        )
      }
    >
      {hasArtifacts
        ? 'Run an analysis to build the security graph and findings.'
        : 'Import BreachFrame environment files, Kubernetes RBAC manifests, AWS IAM policies or MCP configurations.'}
    </EmptyState>
  );
}

export function AnalysisPicker({ projectId, analyses, value }: { projectId: number; analyses: AnalysisRow[]; value: number | null }) {
  const select = useUi((s) => s.selectAnalysis);
  if (analyses.length === 0) return null;
  return (
    <select
      className="input max-w-[280px]"
      aria-label="Analysis"
      value={value ?? ''}
      onChange={(e) => select(projectId, e.target.value === String(analyses[0].id) ? null : Number(e.target.value))}
    >
      {analyses.map((a, i) => (
        <option key={a.id} value={a.id}>
          #{a.id} {a.label ? `· ${a.label} ` : ''}· {dateTime(a.createdAt)} · risk {a.riskScore}
          {i === 0 ? ' (latest)' : ''}
        </option>
      ))}
    </select>
  );
}

export function useProjects() {
  return useAsync(() => api.listProjects(), []);
}
