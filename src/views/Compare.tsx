import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowRight, GitCompareArrows, Minus, Plus } from 'lucide-react';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useUi } from '../lib/store';
import { dateTime, SEVERITY_LABEL, SEVERITY_VAR } from '../lib/format';
import { SEVERITIES, type AnalysisResult, type Comparison, type FindingRef } from '../lib/types';
import { GraphView, type NodeState } from '../components/GraphView';
import { RiskGauge } from '../components/charts';
import { Card, EmptyState, ErrorNote, PageHeader, Segmented, SeverityBadge, Skeleton } from '../components/ui';

function RefList({ items, empty, tone }: { items: FindingRef[]; empty: string; tone: 'ok' | 'bad' | 'neutral' }) {
  if (items.length === 0) return <div className="py-4 text-center text-[12px] text-[var(--color-faint)]">{empty}</div>;
  return (
    <ul className="space-y-1">
      {items.map((f) => (
        <li key={f.id} className="flex items-center gap-2 text-[12px]">
          {tone === 'ok' ? <Minus size={12} className="shrink-0 text-[var(--color-ok)]" /> : tone === 'bad' ? <Plus size={12} className="shrink-0 text-[var(--color-sev-critical)]" /> : <span className="w-3" />}
          <SeverityBadge severity={f.severity} compact />
          <span className={tone === 'ok' ? 'truncate text-[var(--color-muted)] line-through decoration-[var(--color-ok)]/60' : 'truncate'}>{f.title}</span>
        </li>
      ))}
    </ul>
  );
}

export function ComparisonSummary({ comparison: c, beforeLabel, afterLabel }: { comparison: Comparison; beforeLabel: string; afterLabel: string }) {
  const delta = c.riskAfter - c.riskBefore;
  return (
    <div className="grid grid-cols-12 gap-4">
      <div className="panel col-span-12 flex flex-wrap items-center justify-center gap-8 px-6 py-4 lg:col-span-5">
        <div className="text-center">
          <div className="label mb-1">{beforeLabel}</div>
          <RiskGauge score={c.riskBefore} />
        </div>
        <ArrowRight className="text-[var(--color-faint)]" />
        <div className="text-center">
          <div className="label mb-1">{afterLabel}</div>
          <RiskGauge score={c.riskAfter} />
        </div>
        <div className="text-center">
          <div className="label mb-1">Change</div>
          <div className="text-[28px] font-semibold tabular-nums" style={{ color: delta < 0 ? 'var(--color-ok)' : delta > 0 ? 'var(--color-sev-critical)' : undefined }}>
            {delta > 0 ? '+' : ''}
            {delta}
          </div>
        </div>
      </div>
      <div className="panel col-span-12 px-5 py-4 lg:col-span-7">
        <div className="label mb-2">Findings by severity ({afterLabel.toLowerCase()} − {beforeLabel.toLowerCase()})</div>
        <div className="grid grid-cols-5 gap-2">
          {SEVERITIES.map((s) => {
            const d = c.severityDelta[s] ?? 0;
            return (
              <div key={s} className="rounded-md border border-[var(--color-line)] px-3 py-2 text-center">
                <div className="text-[18px] font-semibold tabular-nums" style={{ color: d < 0 ? 'var(--color-ok)' : d > 0 ? SEVERITY_VAR[s] : 'var(--color-faint)' }}>
                  {d > 0 ? '+' : ''}
                  {d}
                </div>
                <div className="text-[10.5px] uppercase tracking-wider text-[var(--color-muted)]">{SEVERITY_LABEL[s]}</div>
              </div>
            );
          })}
        </div>
        <div className="mt-3 flex gap-6 text-[11.5px] text-[var(--color-muted)]">
          <span>
            <span className="text-[var(--color-ok)]">−{c.edgesRemoved.length}</span> / <span className="text-[var(--color-sev-high)]">+{c.edgesAdded.length}</span> edges
          </span>
          <span>
            <span className="text-[var(--color-ok)]">−{c.nodesRemoved.length}</span> / <span className="text-[var(--color-sev-high)]">+{c.nodesAdded.length}</span> nodes
          </span>
        </div>
      </div>
      <Card className="col-span-12 md:col-span-4" title={`Resolved (${c.resolved.length})`}>
        <RefList items={c.resolved} empty="Nothing resolved" tone="ok" />
      </Card>
      <Card className="col-span-12 md:col-span-4" title={`Introduced (${c.introduced.length})`}>
        <RefList items={c.introduced} empty="No new findings" tone="bad" />
      </Card>
      <Card className="col-span-12 md:col-span-4" title={`Still present (${c.persisting.length})`}>
        <RefList items={c.persisting} empty="None" tone="neutral" />
      </Card>
    </div>
  );
}

function DiffGraphs({ before, after, comparison }: { before: AnalysisResult; after: AnalysisResult; comparison: Comparison }) {
  const removed = useMemo(() => new Set(comparison.edgesRemoved), [comparison]);
  const added = useMemo(() => new Set(comparison.edgesAdded), [comparison]);
  const nodesRemoved = useMemo(() => new Set(comparison.nodesRemoved), [comparison]);
  const nodesAdded = useMemo(() => new Set(comparison.nodesAdded), [comparison]);
  const bEdge = useCallback((id: string) => (removed.has(id) ? 'edge-removed' : undefined), [removed]);
  const aEdge = useCallback((id: string) => (added.has(id) ? 'edge-added' : undefined), [added]);
  const bNode = useCallback((id: string): NodeState => (nodesRemoved.has(id) ? 'removed' : undefined), [nodesRemoved]);
  const aNode = useCallback((id: string): NodeState => (nodesAdded.has(id) ? 'added' : undefined), [nodesAdded]);
  return (
    <div className="grid grid-cols-2 gap-4">
      {[
        { label: 'Before', g: before.graph, e: bEdge, n: bNode, legend: 'dashed red = removed in after' },
        { label: 'After', g: after.graph, e: aEdge, n: aNode, legend: 'green = added in after' },
      ].map((x) => (
        <div key={x.label} className="panel flex h-[420px] flex-col overflow-hidden">
          <div className="flex items-center justify-between border-b border-[var(--color-line)] px-4 py-2">
            <span className="label">{x.label}</span>
            <span className="text-[10.5px] text-[var(--color-faint)]">{x.legend}</span>
          </div>
          <div className="min-h-0 flex-1 grid-bg">
            <GraphView graph={x.g} edgeClass={x.e} nodeState={x.n} showLabels={false} minimap={false} />
          </div>
        </div>
      ))}
    </div>
  );
}

function ProjectCompare() {
  const active = useUi((s) => s.activeProjectId);
  const analyses = useAsync(() => (active != null ? api.listAnalyses(active) : Promise.resolve([])), [active]);
  const list = useMemo(() => analyses.data ?? [], [analyses.data]);
  const [beforeId, setBefore] = useState<number | null>(null);
  const [afterId, setAfter] = useState<number | null>(null);
  useEffect(() => {
    if (list.length >= 2) {
      setAfter(list[0].id);
      setBefore(list[list.length - 1].id);
    } else {
      setAfter(null);
      setBefore(null);
    }
  }, [list]);
  const cmp = useAsync(() => (beforeId != null && afterId != null ? api.compareAnalyses(beforeId, afterId) : Promise.resolve(undefined)), [beforeId, afterId]);
  const b = useAsync(() => (beforeId != null ? api.getAnalysis(beforeId) : Promise.resolve(undefined)), [beforeId]);
  const a = useAsync(() => (afterId != null ? api.getAnalysis(afterId) : Promise.resolve(undefined)), [afterId]);

  if (active == null)
    return (
      <EmptyState icon={<GitCompareArrows size={36} />} title="Open a project to compare its analyses">
        Or switch to “Training lab” to compare a lab's vulnerable and fixed configurations.
      </EmptyState>
    );
  if (!analyses.loading && list.length < 2)
    return (
      <EmptyState icon={<GitCompareArrows size={36} />} title="At least two analyses are needed">
        Run an analysis, change the configuration (for example replace a file with its fixed version), then run again. Importing a lab as a project creates both analyses automatically.
      </EmptyState>
    );
  const opt = (x: (typeof list)[number]) => `#${x.id}${x.label ? ` · ${x.label}` : ''} · ${dateTime(x.createdAt)} · risk ${x.riskScore}`;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select className="input" value={beforeId ?? ''} onChange={(e) => setBefore(Number(e.target.value))} aria-label="Before analysis">
          {list.map((x) => (
            <option key={x.id} value={x.id}>
              Before: {opt(x)}
            </option>
          ))}
        </select>
        <ArrowRight size={14} className="text-[var(--color-faint)]" />
        <select className="input" value={afterId ?? ''} onChange={(e) => setAfter(Number(e.target.value))} aria-label="After analysis">
          {list.map((x) => (
            <option key={x.id} value={x.id}>
              After: {opt(x)}
            </option>
          ))}
        </select>
      </div>
      <ErrorNote error={cmp.error} />
      {cmp.loading && !cmp.data && <Skeleton className="h-48" />}
      {cmp.data && <ComparisonSummary comparison={cmp.data} beforeLabel="Before" afterLabel="After" />}
      {cmp.data && a.data && b.data && <DiffGraphs before={b.data.result} after={a.data.result} comparison={cmp.data} />}
    </div>
  );
}

function LabCompare() {
  const labs = useAsync(() => api.listLabs(), []);
  const [id, setId] = useState<string | null>(null);
  useEffect(() => {
    if (!id && labs.data?.length) setId(labs.data[0].id);
  }, [labs.data, id]);
  const run = useAsync(() => (id ? api.runLab(id) : Promise.resolve(undefined)), [id]);
  return (
    <div className="space-y-4">
      <select className="input" value={id ?? ''} onChange={(e) => setId(e.target.value)} aria-label="Lab">
        {(labs.data ?? []).map((l) => (
          <option key={l.id} value={l.id}>
            {l.title}
          </option>
        ))}
      </select>
      <ErrorNote error={run.error} />
      {run.loading && !run.data && <Skeleton className="h-48" />}
      {run.data && (
        <>
          <ComparisonSummary comparison={run.data.comparison} beforeLabel="Vulnerable" afterLabel="Fixed" />
          <DiffGraphs before={run.data.vulnerable} after={run.data.fixed} comparison={run.data.comparison} />
        </>
      )}
    </div>
  );
}

export function CompareView() {
  const active = useUi((s) => s.activeProjectId);
  const [mode, setMode] = useState<'project' | 'lab'>(active != null ? 'project' : 'lab');
  return (
    <div className="flex h-full flex-col overflow-auto">
      <PageHeader
        icon={<GitCompareArrows size={18} className="text-[var(--color-accent)]" />}
        title="Before & After"
        subtitle="Compare two analyses: risk score, findings resolved or introduced, and graph edges removed or added."
        actions={
          <Segmented
            value={mode}
            onChange={setMode}
            options={[
              { value: 'project', label: 'Project analyses' },
              { value: 'lab', label: 'Training lab' },
            ]}
          />
        }
      />
      <div className="p-6">{mode === 'project' ? <ProjectCompare /> : <LabCompare />}</div>
    </div>
  );
}
