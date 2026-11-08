import { FlaskConical, FolderPlus, LayoutDashboard } from 'lucide-react';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useUi } from '../lib/store';
import { CATEGORY_LABEL, SEVERITY_VAR, STATUS_LABEL, timeAgo } from '../lib/format';
import { STATUSES, type Category } from '../lib/types';
import { HBars, RiskBars, SeverityDonut } from '../components/charts';
import { Card, EmptyState, ErrorNote, PageHeader, Skeleton, Stat } from '../components/ui';

export function DashboardView() {
  const d = useAsync(() => api.dashboard(), []);
  const projects = useAsync(() => api.listProjects(), []);
  const setView = useUi((s) => s.setView);
  const openProject = useUi((s) => s.openProject);

  const data = d.data;
  const openTotal = data ? Object.values(data.openBySeverity).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="flex h-full flex-col overflow-auto">
      <PageHeader
        icon={<LayoutDashboard size={18} className="text-[var(--color-accent)]" />}
        title="Security Dashboard"
        subtitle="Live totals from every project and analysis stored on this machine."
        actions={
          <>
            <button className="btn" onClick={() => setView('labs')}>
              <FlaskConical size={14} /> Labs
            </button>
            <button className="btn btn-primary" onClick={() => setView('projects')}>
              <FolderPlus size={14} /> New project
            </button>
          </>
        }
      />
      <ErrorNote error={d.error} />
      {!data && d.loading && (
        <div className="grid grid-cols-4 gap-4 p-6">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      )}
      {data && data.projects === 0 && (
        <EmptyState
          icon={<LayoutDashboard size={40} />}
          title="Nothing analysed yet"
          action={
            <div className="flex gap-2">
              <button className="btn btn-primary" onClick={() => setView('projects')}>
                <FolderPlus size={14} /> Create a project
              </button>
              <button className="btn" onClick={() => setView('labs')}>
                <FlaskConical size={14} /> Explore a lab
              </button>
            </div>
          }
        >
          The dashboard summarises real analyses only. Create a project and import your configuration files, or load one of the built-in training labs.
        </EmptyState>
      )}
      {data && data.projects > 0 && (
        <div className="grid grid-cols-12 gap-4 p-6">
          <div className="col-span-12 grid grid-cols-2 gap-4 lg:grid-cols-5">
            <Stat label="Open findings" value={openTotal} hint={`${data.openBySeverity.critical} critical · ${data.openBySeverity.high} high`} color={openTotal ? SEVERITY_VAR.high : undefined} />
            <Stat label="Projects" value={data.projects} hint={`${data.artifacts} artifacts`} />
            <Stat label="Analyses" value={data.analyses} hint={data.recentAnalyses.length ? `last ${timeAgo(data.recentAnalyses[data.recentAnalyses.length - 1].createdAt)}` : '—'} />
            <Stat label="Resolved" value={data.byStatus.resolved ?? 0} hint="automatically or manually" color="var(--color-ok)" />
            <Stat label="Accepted risk" value={data.byStatus.accepted_risk ?? 0} hint={`${data.byStatus.false_positive ?? 0} false positive`} />
          </div>

          <Card title="Open findings by severity" className="col-span-12 lg:col-span-4">
            <SeverityDonut counts={data.openBySeverity} />
          </Card>
          <Card title="Risk score per analysis" className="col-span-12 lg:col-span-5">
            <RiskBars
              points={data.recentAnalyses.map((a) => ({ id: a.id, value: a.riskScore, label: `#${a.id} · ${timeAgo(a.createdAt)}`, sub: a.projectName }))}
              onSelect={(p) => {
                const a = data.recentAnalyses.find((x) => x.id === p.id);
                if (a) openProject(a.projectId, 'attack-paths');
              }}
            />
          </Card>
          <Card title="Workflow status" className="col-span-12 lg:col-span-3">
            <HBars
              rows={STATUSES.map((s) => ({
                label: STATUS_LABEL[s],
                value: data.byStatus[s] ?? 0,
                color: s === 'resolved' ? 'var(--color-ok)' : s === 'open' ? 'var(--color-sev-high)' : s === 'in_progress' ? 'var(--color-sev-low)' : 'var(--color-muted)',
              }))}
            />
          </Card>

          <Card title="Most frequent open issues" className="col-span-12 lg:col-span-4">
            <HBars rows={data.topRules.map(([r, n]) => ({ label: r, value: n }))} />
          </Card>
          <Card title="Open findings by area" className="col-span-12 lg:col-span-3">
            <HBars rows={Object.entries(data.byCategory).map(([c, n]) => ({ label: CATEGORY_LABEL[c as Category] ?? c, value: n ?? 0 }))} color="#c58bff" />
          </Card>
          <Card title="Projects" className="col-span-12 lg:col-span-5" bodyClass="p-0">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="text-left text-[11px] text-[var(--color-muted)]">
                  <th className="px-4 py-2 font-medium">Project</th>
                  <th className="px-2 py-2 font-medium">Risk</th>
                  <th className="px-2 py-2 font-medium">Open</th>
                  <th className="px-4 py-2 text-right font-medium">Updated</th>
                </tr>
              </thead>
              <tbody>
                {(projects.data ?? []).slice(0, 8).map((p) => (
                  <tr key={p.id} className="cursor-pointer border-t border-[var(--color-line)] hover:bg-[var(--color-panel-2)]" onClick={() => openProject(p.id, 'attack-paths')}>
                    <td className="max-w-[220px] truncate px-4 py-2">{p.name}</td>
                    <td className="px-2 py-2 tabular-nums">{p.latestRisk ?? '—'}</td>
                    <td className="px-2 py-2 tabular-nums">{p.openFindings}</td>
                    <td className="px-4 py-2 text-right text-[var(--color-muted)]">{timeAgo(p.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card title="Recent activity" className="col-span-12">
            <ul className="grid grid-cols-1 gap-x-8 gap-y-1.5 md:grid-cols-2">
              {data.activity.map((a) => (
                <li key={a.id} className="flex items-baseline gap-3 text-[12px]">
                  <span className="w-16 shrink-0 text-right text-[11px] text-[var(--color-faint)]">{timeAgo(a.ts)}</span>
                  <span className="truncate">{a.message}</span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}
    </div>
  );
}
