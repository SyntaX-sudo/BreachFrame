import { useMemo, useState } from 'react';
import { ArrowDownUp, KeyRound } from 'lucide-react';
import { useProjectAnalysis } from '../lib/hooks';
import { useUi } from '../lib/store';
import { KIND_LABEL } from '../lib/format';
import type { Finding, PrincipalSummary } from '../lib/types';
import { Card, cx, EmptyState, ErrorNote, KindIcon, PageHeader, SeverityBadge, Segmented, Skeleton } from '../components/ui';
import { AnalysisPicker, NeedAnalysis, NeedProject } from './common';
import { FindingDetail } from './Findings';

type SortKey = 'reachableSensitive' | 'reachable' | 'permissions' | 'label';

export function PermissionsView() {
  const active = useUi((s) => s.activeProjectId);
  const pa = useProjectAnalysis();
  const [scope, setScope] = useState<'all' | 'rbac' | 'iam' | 'policy'>('all');
  const [sort, setSort] = useState<SortKey>('reachableSensitive');
  const [selected, setSelected] = useState<Finding | null>(null);
  const [principal, setPrincipal] = useState<PrincipalSummary | null>(null);
  const r = pa.detail?.result;

  const findings = useMemo(
    () => (r?.findings ?? []).filter((f) => (scope === 'all' ? f.category === 'rbac' || f.category === 'iam' || f.category === 'policy' : f.category === scope)),
    [r, scope],
  );
  const principals = useMemo(() => {
    const list = [...(r?.principals ?? [])];
    list.sort((a, b) => (sort === 'label' ? a.label.localeCompare(b.label) : (b[sort] as number) - (a[sort] as number)));
    return list;
  }, [r, sort]);
  const principalFindings = useMemo(
    () => (principal ? (r?.findings ?? []).filter((f) => f.nodes?.includes(principal.id) || f.path?.[0] === principal.id) : []),
    [principal, r],
  );

  if (active == null) return <NeedProject what="permission audit" />;
  const Th = ({ k, children, className }: { k: SortKey; children: string; className?: string }) => (
    <th className={cx('px-2 py-2 font-medium', className)}>
      <button className={cx('inline-flex items-center gap-1', sort === k && 'text-[var(--color-text)]')} onClick={() => setSort(k)}>
        {children} <ArrowDownUp size={10} />
      </button>
    </th>
  );
  return (
    <div className="flex h-full flex-col overflow-hidden">
      <PageHeader
        icon={<KeyRound size={18} className="text-[var(--color-accent)]" />}
        title="Permission Auditor"
        subtitle="Effective reach of every principal, plus RBAC, IAM and policy findings."
        actions={<AnalysisPicker projectId={active} analyses={pa.analyses} value={pa.analysisId} />}
      />
      <ErrorNote error={pa.error} />
      {pa.loading && !r && <Skeleton className="m-6 h-64" />}
      {!pa.loading && !r && pa.project && <NeedAnalysis projectId={active} hasArtifacts={pa.project.artifactCount > 0} />}
      {r && (
        <div className="grid min-h-0 flex-1 grid-cols-12 gap-4 overflow-auto p-6">
          <Card className="col-span-12 xl:col-span-7" title={`Principals (${principals.length})`} bodyClass="p-0 overflow-auto max-h-[calc(100vh-230px)]">
            {principals.length === 0 ? (
              <EmptyState title="No principals">The graph has no users, groups, service accounts, agents or services.</EmptyState>
            ) : (
              <table className="w-full text-[12.5px]">
                <thead className="sticky top-0 bg-[var(--color-panel)]">
                  <tr className="text-left text-[11px] text-[var(--color-muted)]">
                    <Th k="label" className="pl-4">Principal</Th>
                    <Th k="reachableSensitive">Sensitive</Th>
                    <Th k="reachable">Reachable</Th>
                    <Th k="permissions">Permissions</Th>
                    <th className="px-2 py-2 font-medium">Worst</th>
                  </tr>
                </thead>
                <tbody>
                  {principals.map((p) => (
                    <tr key={p.id} className={cx('cursor-pointer border-t border-[var(--color-line)]', principal?.id === p.id ? 'bg-[var(--color-panel-3)]' : 'hover:bg-[var(--color-panel-2)]')} onClick={() => setPrincipal(p)}>
                      <td className="py-2 pl-4 pr-2">
                        <div className="flex items-center gap-2">
                          <KindIcon kind={p.kind} />
                          <div className="min-w-0">
                            <div className="truncate font-medium">{p.label}</div>
                            <div className="text-[10.5px] text-[var(--color-faint)]">{KIND_LABEL[p.kind]}</div>
                          </div>
                          {p.wildcard && <span className="rounded border border-[var(--color-sev-high)] px-1 text-[9.5px] font-semibold text-[var(--color-sev-high)]">WILDCARD</span>}
                        </div>
                      </td>
                      <td className="px-2 py-2 tabular-nums" style={{ color: p.reachableSensitive ? 'var(--color-sev-critical)' : undefined }}>
                        {p.reachableSensitive}
                      </td>
                      <td className="px-2 py-2 tabular-nums">{p.reachable}</td>
                      <td className="px-2 py-2 tabular-nums">{p.permissions}</td>
                      <td className="px-2 py-2">{p.maxSeverity ? <SeverityBadge severity={p.maxSeverity} compact /> : <span className="text-[var(--color-faint)]">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <div className="col-span-12 flex flex-col gap-4 xl:col-span-5">
            {principal && (
              <Card title={`Findings for ${principal.label}`}>
                {principalFindings.length === 0 ? (
                  <div className="text-[12px] text-[var(--color-faint)]">No findings reference this principal directly.</div>
                ) : (
                  <ul className="space-y-1">
                    {principalFindings.map((f) => (
                      <li key={f.id}>
                        <button className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left hover:bg-[var(--color-panel-2)]" onClick={() => setSelected(f)}>
                          <SeverityBadge severity={f.severity} compact />
                          <span className="truncate text-[12px]">{f.title}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            )}
            <Card
              title={`Permission findings (${findings.length})`}
              bodyClass="p-0"
              actions={
                <Segmented
                  size="sm"
                  value={scope}
                  onChange={setScope}
                  options={[
                    { value: 'all', label: 'All' },
                    { value: 'rbac', label: 'K8s' },
                    { value: 'iam', label: 'IAM' },
                    { value: 'policy', label: 'Policy' },
                  ]}
                />
              }
            >
              {findings.length === 0 && <div className="px-4 py-8 text-center text-[12px] text-[var(--color-faint)]">No permission findings in this scope.</div>}
              <ul>
                {findings.map((f) => (
                  <li key={f.id} className="border-b border-[var(--color-line)] last:border-0">
                    <button className="w-full px-4 py-2.5 text-left hover:bg-[var(--color-panel-2)]" onClick={() => setSelected(f)}>
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} compact />
                        <span className="font-mono text-[10.5px] text-[var(--color-faint)]">{f.ruleId}</span>
                      </div>
                      <div className="mt-1 text-[12.5px]">{f.title}</div>
                    </button>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        </div>
      )}
      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
