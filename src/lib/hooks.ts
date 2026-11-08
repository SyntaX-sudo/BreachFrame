import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';
import { useUi } from './store';
import type { AnalysisDetail, AnalysisRow, ProjectSummary } from './types';

export interface AsyncState<T> {
  data: T | undefined;
  error: string | undefined;
  loading: boolean;
  reload: () => void;
}

/** Run an async loader whenever deps or the global data revision change. */
export function useAsync<T>(loader: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const revision = useUi((s) => s.revision);
  const [state, setState] = useState<{ data?: T; error?: string; loading: boolean }>({ loading: true });
  const [tick, setTick] = useState(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: undefined }));
    loaderRef
      .current()
      .then((data) => !cancelled && setState({ data, loading: false }))
      .catch((e: unknown) => !cancelled && setState((s) => ({ data: s.data, error: e instanceof Error ? e.message : String(e), loading: false })));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, revision, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data: state.data, error: state.error, loading: state.loading, reload };
}

export interface ProjectAnalysis {
  project?: ProjectSummary;
  analyses: AnalysisRow[];
  detail?: AnalysisDetail;
  analysisId: number | null;
  loading: boolean;
  error?: string;
}

/** Active project + its selected (or latest) analysis. */
export function useProjectAnalysis(): ProjectAnalysis {
  const projectId = useUi((s) => s.activeProjectId);
  const pinned = useUi((s) => (projectId != null ? (s.selectedAnalysis[projectId] ?? null) : null));
  const project = useAsync(() => (projectId != null ? api.getProject(projectId) : Promise.resolve(undefined)), [projectId]);
  const analyses = useAsync(() => (projectId != null ? api.listAnalyses(projectId) : Promise.resolve([])), [projectId]);
  const list = analyses.data ?? [];
  const analysisId = pinned != null && list.some((a) => a.id === pinned) ? pinned : (list[0]?.id ?? null);
  const detail = useAsync(() => (analysisId != null ? api.getAnalysis(analysisId) : Promise.resolve(undefined)), [analysisId]);
  return {
    project: project.data,
    analyses: list,
    detail: analysisId != null ? detail.data : undefined,
    analysisId,
    loading: project.loading || analyses.loading || detail.loading,
    error: project.error ?? analyses.error ?? detail.error,
  };
}

/** Wrap a mutating backend action: toast on error, bump revision on success. */
export function useAction() {
  const toast = useUi((s) => s.toast);
  const bump = useUi((s) => s.bump);
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async <T,>(fn: () => Promise<T>, success?: string | ((r: T) => string | undefined)): Promise<T | undefined> => {
      setBusy(true);
      try {
        const r = await fn();
        bump();
        const msg = typeof success === 'function' ? success(r) : success;
        if (msg) toast({ kind: 'success', title: msg });
        return r;
      } catch (e) {
        toast({ kind: 'error', title: 'Action failed', detail: e instanceof Error ? e.message : String(e) });
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [toast, bump],
  );
  return { run, busy };
}
