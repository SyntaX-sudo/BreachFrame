import { useState } from 'react';
import { save } from '@tauri-apps/plugin-dialog';
import { Braces, Download, FileText } from 'lucide-react';
import { api } from '../lib/api';
import { useAsync, useProjectAnalysis } from '../lib/hooks';
import { useUi } from '../lib/store';
import { ErrorNote, PageHeader, Segmented, Skeleton, Spinner } from '../components/ui';
import { AnalysisPicker, NeedAnalysis, NeedProject } from './common';

function safeName(s: string) {
  return s.replace(/[^\w.-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'report';
}

export function ReportsView() {
  const active = useUi((s) => s.activeProjectId);
  const toast = useUi((s) => s.toast);
  const bump = useUi((s) => s.bump);
  const pa = useProjectAnalysis();
  const [format, setFormat] = useState<'html' | 'json'>('html');
  const [busy, setBusy] = useState(false);
  const preview = useAsync(() => (pa.analysisId != null ? api.renderReport(pa.analysisId, format) : Promise.resolve('')), [pa.analysisId, format]);

  if (active == null) return <NeedProject what="reports" />;

  const exportIt = async () => {
    if (pa.analysisId == null || !pa.project) return;
    const path = await save({
      title: 'Export report',
      defaultPath: `breachframe-${safeName(pa.project.name)}-analysis-${pa.analysisId}.${format}`,
      filters: [{ name: format === 'html' ? 'HTML report' : 'JSON report', extensions: [format] }],
    });
    if (!path) return;
    setBusy(true);
    try {
      const target = path.toLowerCase().endsWith(`.${format}`) ? path : `${path}.${format}`;
      await api.exportReport(pa.analysisId, format, target);
      toast({ kind: 'success', title: 'Report exported', detail: target });
      bump();
    } catch (e) {
      toast({ kind: 'error', title: 'Export failed', detail: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        icon={<FileText size={18} className="text-[var(--color-accent)]" />}
        title="Report Generator"
        subtitle="Self-contained HTML (no scripts, no external requests) or machine-readable JSON, with evidence, recommendations, workflow status and analyst notes."
        actions={
          <>
            <AnalysisPicker projectId={active} analyses={pa.analyses} value={pa.analysisId} />
            <Segmented
              value={format}
              onChange={setFormat}
              options={[
                { value: 'html', label: <span className="flex items-center gap-1.5"><FileText size={13} /> HTML</span> },
                { value: 'json', label: <span className="flex items-center gap-1.5"><Braces size={13} /> JSON</span> },
              ]}
            />
            <button className="btn btn-primary" disabled={busy || pa.analysisId == null} onClick={exportIt}>
              {busy ? <Spinner size={13} className="text-[#04221b]" /> : <Download size={13} />} Export…
            </button>
          </>
        }
      />
      <ErrorNote error={pa.error ?? preview.error} />
      {!pa.loading && pa.analysisId == null && pa.project && <NeedAnalysis projectId={active} hasArtifacts={pa.project.artifactCount > 0} />}
      {pa.analysisId != null && (
        <div className="min-h-0 flex-1 p-6">
          {preview.loading && !preview.data && <Skeleton className="h-full" />}
          {preview.data &&
            (format === 'html' ? (
              // Sandboxed preview: no scripts, no same-origin access.
              <iframe title="Report preview" sandbox="" srcDoc={preview.data} className="h-full w-full rounded-lg border border-[var(--color-line)] bg-white" />
            ) : (
              <pre className="h-full overflow-auto rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-4 font-mono text-[11px] leading-relaxed">{preview.data}</pre>
            ))}
        </div>
      )}
    </div>
  );
}
