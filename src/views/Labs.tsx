import { useState } from 'react';
import { ArrowLeft, Code2, FlaskConical, FolderInput, ShieldCheck, ShieldX, Target } from 'lucide-react';
import { api } from '../lib/api';
import { useAction, useAsync } from '../lib/hooks';
import { useUi } from '../lib/store';
import type { Lab, LabRun } from '../lib/types';
import { GraphExplorer } from '../components/GraphExplorer';
import { RiskGauge } from '../components/charts';
import { cx, ErrorNote, Modal, PageHeader, Segmented, SeverityBadge, Skeleton, Spinner } from '../components/ui';
import { ComparisonSummary } from './Compare';

function LabSource({ run, variant, open, onClose }: { run: LabRun; variant: 'vulnerable' | 'fixed'; open: boolean; onClose: () => void }) {
  const files = run.lab[variant];
  const [i, setI] = useState(0);
  return (
    <Modal open={open} onClose={onClose} wide title={`${run.lab.title} — ${variant} artifacts`}>
      <div className="mb-2 flex gap-1">
        {files.map((f, idx) => (
          <button key={f.name} className={cx('btn h-7', idx === i && 'border-[var(--color-accent)]')} onClick={() => setI(idx)}>
            {f.name}
          </button>
        ))}
      </div>
      <pre className="max-h-[60vh] overflow-auto rounded-md border border-[var(--color-line)] bg-[var(--color-bg)] p-3 font-mono text-[11px] leading-relaxed">{files[i]?.content}</pre>
    </Modal>
  );
}

function LabDetail({ lab, onBack }: { lab: Lab; onBack: () => void }) {
  const run = useAsync(() => api.runLab(lab.id), [lab.id]);
  const [variant, setVariant] = useState<'vulnerable' | 'fixed'>('vulnerable');
  const [tab, setTab] = useState<'graph' | 'brief' | 'diff'>('brief');
  const [source, setSource] = useState(false);
  const { run: act, busy } = useAction();
  const openProject = useUi((s) => s.openProject);
  const r = run.data?.[variant];
  return (
    <div className="flex h-full flex-col">
      <PageHeader
        icon={
          <button className="btn btn-ghost h-7 px-1.5" onClick={onBack} aria-label="Back to labs">
            <ArrowLeft size={15} />
          </button>
        }
        title={lab.title}
        subtitle={`${lab.category} · ${lab.difficulty} · runs locally on built-in artifacts`}
        actions={
          <>
            {r && <RiskGauge score={r.riskScore} size={96} />}
            <Segmented
              value={variant}
              onChange={setVariant}
              options={[
                { value: 'vulnerable', label: <span className="flex items-center gap-1.5"><ShieldX size={13} className="text-[var(--color-sev-critical)]" /> Vulnerable</span> },
                { value: 'fixed', label: <span className="flex items-center gap-1.5"><ShieldCheck size={13} className="text-[var(--color-ok)]" /> Fixed</span> },
              ]}
            />
            <button className="btn" onClick={() => setSource(true)} disabled={!run.data}>
              <Code2 size={13} /> Source
            </button>
            <button
              className="btn btn-primary"
              disabled={busy}
              onClick={async () => {
                const p = await act(() => api.importLab(lab.id), 'Lab imported as a project with two analyses (vulnerable → fixed)');
                if (p) openProject(p.id, 'compare');
              }}
            >
              {busy ? <Spinner size={13} className="text-[#04221b]" /> : <FolderInput size={13} />} Import as project
            </button>
          </>
        }
      />
      <div className="border-b border-[var(--color-line)] px-6 py-2">
        <Segmented
          size="sm"
          value={tab}
          onChange={setTab}
          options={[
            { value: 'brief', label: 'Briefing' },
            { value: 'graph', label: 'Attack graph' },
            { value: 'diff', label: 'Before & After' },
          ]}
        />
      </div>
      <ErrorNote error={run.error} />
      {run.loading && !run.data && <Skeleton className="m-6 flex-1" />}
      {run.data && r && tab === 'graph' && (
        <div className="min-h-0 flex-1">
          <GraphExplorer graph={r.graph} findings={r.findings} attacker={r.graph.nodes.some((n) => n.id === lab.attacker) ? lab.attacker : undefined} />
        </div>
      )}
      {run.data && r && tab === 'brief' && (
        <div className="grid min-h-0 flex-1 grid-cols-12 gap-5 overflow-auto p-6">
          <div className="col-span-12 space-y-5 lg:col-span-7">
            <p className="text-[13.5px] leading-relaxed">{lab.summary}</p>
            <section>
              <div className="label mb-2">Learning objectives</div>
              <ul className="list-disc space-y-1 pl-5 text-[12.5px] text-[var(--color-muted)]">
                {lab.objectives.map((o) => (
                  <li key={o}>{o}</li>
                ))}
              </ul>
            </section>
            <section>
              <div className="label mb-2 flex items-center gap-2">
                <Target size={12} /> Attack walkthrough
              </div>
              <ol className="space-y-2">
                {lab.walkthrough.map((w, i) => (
                  <li key={i} className="flex gap-3 text-[12.5px]">
                    <span className="grid size-5 shrink-0 place-items-center rounded-full bg-[var(--color-panel-3)] text-[10.5px] font-semibold">{i + 1}</span>
                    <span className="leading-relaxed">{w}</span>
                  </li>
                ))}
              </ol>
            </section>
            <div className="rounded-lg border border-[var(--color-line-strong)] bg-[var(--color-panel)] px-4 py-3 text-[11.5px] text-[var(--color-muted)]">
              How this lab works: the vulnerable and fixed artifacts below are analysed by the same engine you use on your own files. The attack graph and blast-radius simulation are computed over that model — no system, network or cloud account is touched.
            </div>
          </div>
          <div className="col-span-12 space-y-2 lg:col-span-5">
            <div className="label mb-1">
              {variant} findings ({r.findings.length})
            </div>
            {r.findings.map((f) => (
              <div key={f.id} className="panel px-3 py-2.5">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={f.severity} compact />
                  <span className="font-mono text-[10.5px] text-[var(--color-faint)]">{f.ruleId}</span>
                </div>
                <div className="mt-1 text-[12px]">{f.title}</div>
              </div>
            ))}
            {r.findings.length === 0 && <div className="text-[12px] text-[var(--color-ok)]">No findings — this configuration passes every check.</div>}
          </div>
        </div>
      )}
      {run.data && tab === 'diff' && (
        <div className="min-h-0 flex-1 overflow-auto p-6">
          <ComparisonSummary comparison={run.data.comparison} beforeLabel="Vulnerable" afterLabel="Fixed" />
        </div>
      )}
      {run.data && <LabSource run={run.data} variant={variant} open={source} onClose={() => setSource(false)} />}
    </div>
  );
}

export function LabsView() {
  const labs = useAsync(() => api.listLabs(), []);
  const [selected, setSelected] = useState<Lab | null>(null);
  if (selected) return <LabDetail lab={selected} onBack={() => setSelected(null)} />;
  return (
    <div className="flex h-full flex-col overflow-auto">
      <PageHeader
        icon={<FlaskConical size={18} className="text-[var(--color-accent)]" />}
        title="Security Simulation Labs"
        subtitle="Self-contained training scenarios. Each lab ships a vulnerable and a fixed configuration, analysed locally by the real engine."
      />
      <ErrorNote error={labs.error} />
      <div className="grid grid-cols-1 gap-4 p-6 md:grid-cols-2">
        {labs.loading && !labs.data && Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-40" />)}
        {(labs.data ?? []).map((l) => (
          <button key={l.id} onClick={() => setSelected(l)} className="panel group flex flex-col gap-2 p-5 text-left transition-colors hover:border-[var(--color-accent-dim)]" data-testid={`lab-${l.id}`}>
            <div className="flex items-center gap-2 text-[11px]">
              <span className="rounded-full border border-[var(--color-line-strong)] px-2 py-[1px] text-[var(--color-muted)]">{l.category}</span>
              <span className="text-[var(--color-faint)]">{l.difficulty}</span>
            </div>
            <div className="text-[15px] font-semibold group-hover:text-[var(--color-accent)]">{l.title}</div>
            <p className="line-clamp-3 text-[12.5px] leading-relaxed text-[var(--color-muted)]">{l.summary}</p>
            <div className="mt-auto pt-2 text-[11px] text-[var(--color-faint)]">
              {l.vulnerable.length} artifacts · {l.objectives.length} objectives
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
