import { useState } from 'react';
import { Play, Route } from 'lucide-react';
import { useProjectAnalysis } from '../lib/hooks';
import { useUi } from '../lib/store';
import { GraphExplorer } from '../components/GraphExplorer';
import { RiskGauge } from '../components/charts';
import { ErrorNote, PageHeader, Skeleton, Spinner } from '../components/ui';
import { AnalysisPicker, NeedAnalysis, NeedProject, useRunAnalysis } from './common';

export function AttackPathsView() {
  const active = useUi((s) => s.activeProjectId);
  const pa = useProjectAnalysis();
  const run = useRunAnalysis();
  const [busy, setBusy] = useState(false);
  if (active == null) return <NeedProject what="attack paths" />;
  const r = pa.detail?.result;
  return (
    <div className="flex h-full flex-col">
      <PageHeader
        icon={<Route size={18} className="text-[var(--color-accent)]" />}
        title="Attack Path Visualizer"
        subtitle={
          r ? (
            <>
              {pa.project?.name} · {r.stats.nodes} nodes · {r.stats.edges} edges · <span className="text-[var(--color-sev-critical)]">{r.stats.policyViolations} policy violations</span> across {r.policies.length} policies
            </>
          ) : (
            pa.project?.name
          )
        }
        actions={
          <>
            {r && <RiskGauge score={r.riskScore} size={96} />}
            <AnalysisPicker projectId={active} analyses={pa.analyses} value={pa.analysisId} />
            <button
              className="btn btn-primary"
              disabled={busy || !pa.project?.artifactCount}
              onClick={async () => {
                setBusy(true);
                await run(active);
                setBusy(false);
              }}
            >
              {busy ? <Spinner size={13} className="text-[#04221b]" /> : <Play size={13} />} Re-run
            </button>
          </>
        }
      />
      <ErrorNote error={pa.error} />
      {pa.loading && !r && <Skeleton className="m-6 flex-1" />}
      {!pa.loading && !r && pa.project && <NeedAnalysis projectId={active} hasArtifacts={pa.project.artifactCount > 0} />}
      {r && (
        <div className="min-h-0 flex-1">
          <GraphExplorer graph={r.graph} findings={r.findings} />
        </div>
      )}
    </div>
  );
}
