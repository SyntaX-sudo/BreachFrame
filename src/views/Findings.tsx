import { useEffect, useMemo, useState } from 'react';
import { History, ListChecks, Search, X } from 'lucide-react';
import { api } from '../lib/api';
import { useAction, useAsync } from '../lib/hooks';
import { useUi } from '../lib/store';
import { CATEGORY_LABEL, dateTime, SEVERITY_VAR, STATUS_LABEL, timeAgo } from '../lib/format';
import { CATEGORIES, SEVERITIES, STATUSES, type Category, type Finding, type FindingFilter, type FindingStatus, type Severity, type StoredFinding } from '../lib/types';
import { Chip, cx, EmptyState, ErrorNote, PageHeader, SeverityBadge, Skeleton, Spinner, StatusBadge } from '../components/ui';

/** Side drawer with full evidence; editable when a stored record exists. */
export function FindingDetail({ finding, stored, onClose }: { finding: Finding; stored?: StoredFinding; onClose: () => void }) {
  const active = useUi((s) => s.activeProjectId);
  const lookup = useAsync(
    () => (stored ? Promise.resolve([stored]) : api.listFindings({ projectId: active, search: finding.id, includeAbsent: true })),
    [finding.id, stored?.id, active],
  );
  // The backend's reply to an update is the freshest copy: keep it, because an
  // updated finding may drop out of the caller's filtered list.
  const [latest, setLatest] = useState<StoredFinding | null>(null);
  const looked = lookup.data?.find((s) => s.finding.id === finding.id);
  const record = latest && latest.id === looked?.id ? latest : looked;
  const [notes, setNotes] = useState(record?.notes ?? '');
  useEffect(() => setNotes(record?.notes ?? ''), [record?.id, record?.notes]);
  const { run, busy } = useAction();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/40 animate-fade-in" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside role="dialog" aria-label={finding.title} className="flex h-full w-[min(620px,92vw)] flex-col border-l border-[var(--color-line-strong)] bg-[var(--color-panel)] shadow-2xl animate-slide-up">
        <div className="flex items-start gap-3 border-b border-[var(--color-line)] px-5 py-4">
          <div className="min-w-0 flex-1">
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="font-mono text-[11px] text-[var(--color-muted)]">{finding.ruleId}</span>
              <span className="text-[11px] text-[var(--color-faint)]">{CATEGORY_LABEL[finding.category]}</span>
              {finding.source && <span className="text-[11px] text-[var(--color-faint)]">· {finding.source}</span>}
            </div>
            <h2 className="text-[15px] font-semibold leading-snug">{finding.title}</h2>
          </div>
          <button className="btn btn-ghost h-7 px-1.5" onClick={onClose} aria-label="Close">
            <X size={15} />
          </button>
        </div>
        <div className="flex-1 space-y-5 overflow-auto px-5 py-4 text-[12.5px] leading-relaxed">
          <section>
            <div className="label mb-1">Description</div>
            <p>{finding.description}</p>
          </section>
          <section>
            <div className="label mb-1">Impact</div>
            <p className="text-[var(--color-muted)]">{finding.impact}</p>
          </section>
          <section className="rounded-lg border border-[var(--color-accent-dim)] bg-[color-mix(in_srgb,var(--color-accent)_5%,transparent)] px-3.5 py-3">
            <div className="label mb-1 text-[var(--color-accent)]">Recommendation</div>
            <p>{finding.recommendation}</p>
          </section>
          {finding.evidence.length > 0 && (
            <section>
              <div className="label mb-1.5">Evidence</div>
              <table className="w-full border-collapse text-[12px]">
                <tbody>
                  {finding.evidence.map((e, i) => (
                    <tr key={i} className="border-t border-[var(--color-line)] align-top">
                      <th className="w-32 py-2 pr-3 text-left font-medium text-[var(--color-muted)]">{e.label}</th>
                      <td className="py-2">
                        <code className="block whitespace-pre-wrap break-all text-[11.5px]">{e.value}</code>
                        {e.location && <div className="mt-0.5 text-[10.5px] text-[var(--color-faint)]">{e.location}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
          <section className="border-t border-[var(--color-line)] pt-4">
            <div className="label mb-2">Workflow</div>
            {lookup.loading && !record && <Spinner />}
            {!lookup.loading && !record && <div className="text-[12px] text-[var(--color-faint)]">This finding comes from a lab run and is not tracked in a project.</div>}
            {record && (
              <div className="space-y-3">
                <div className="flex flex-wrap gap-1.5" role="radiogroup" aria-label="Status">
                  {STATUSES.map((s) => (
                    <button
                      key={s}
                      role="radio"
                      aria-checked={record.status === s}
                      disabled={busy}
                      className={cx('btn h-7', record.status === s && 'border-[var(--color-accent)] text-[var(--color-accent)]')}
                      onClick={async () => {
                        const r = await run(() => api.updateFinding(record.id, { status: s }), `Status → ${STATUS_LABEL[s]}`);
                        if (r) setLatest(r);
                      }}
                    >
                      {STATUS_LABEL[s]}
                    </button>
                  ))}
                </div>
                <textarea className="input w-full" rows={4} maxLength={10000} placeholder="Analyst notes, ticket links, compensating controls…" value={notes} onChange={(e) => setNotes(e.target.value)} aria-label="Notes" />
                <div className="flex items-center justify-between text-[11px] text-[var(--color-faint)]">
                  <span>
                    First seen {dateTime(record.firstSeen)} · last seen {timeAgo(record.lastSeen)} · {record.present ? 'present in latest analysis' : 'not present in latest analysis'}
                  </span>
                  <button className="btn h-7" disabled={busy || notes === record.notes} onClick={async () => {
                      const r = await run(() => api.updateFinding(record.id, { notes }), 'Notes saved');
                      if (r) setLatest(r);
                    }}>
                    Save notes
                  </button>
                </div>
              </div>
            )}
          </section>
        </div>
      </aside>
    </div>
  );
}

function toggle<T>(set: Set<T>, v: T): Set<T> {
  const n = new Set(set);
  if (n.has(v)) n.delete(v);
  else n.add(v);
  return n;
}

export function buildFilter(state: { projectOnly: boolean; projectId: number | null; severities: Set<Severity>; statuses: Set<FindingStatus>; categories: Set<Category>; search: string; history: boolean }): FindingFilter {
  return {
    projectId: state.projectOnly ? state.projectId : null,
    severities: [...state.severities],
    statuses: [...state.statuses],
    categories: [...state.categories],
    search: state.search.trim() || undefined,
    includeAbsent: state.history,
  };
}

export function FindingsView() {
  const active = useUi((s) => s.activeProjectId);
  const focus = useUi((s) => s.focusFinding);
  const setFocus = useUi((s) => s.setFocusFinding);
  const [projectOnly, setProjectOnly] = useState(active != null);
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());
  const [statuses, setStatuses] = useState<Set<FindingStatus>>(new Set(['open', 'in_progress']));
  const [categories, setCategories] = useState<Set<Category>>(new Set());
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');
  const [history, setHistory] = useState(false);
  const [selected, setSelected] = useState<StoredFinding | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 200);
    return () => clearTimeout(t);
  }, [search]);
  useEffect(() => {
    if (active == null) setProjectOnly(false);
  }, [active]);

  const filter = useMemo(
    () => buildFilter({ projectOnly, projectId: active, severities, statuses, categories, search: debounced, history }),
    [projectOnly, active, severities, statuses, categories, debounced, history],
  );
  const list = useAsync(() => api.listFindings(filter), [JSON.stringify(filter)]);

  useEffect(() => {
    if (!focus || !list.data) return;
    const f = list.data.find((x) => x.finding.id === focus);
    if (f) {
      setSelected(f);
      setFocus(null);
    } else {
      setStatuses(new Set());
    }
  }, [focus, list.data, setFocus]);

  const counts = useMemo(() => {
    const c: Partial<Record<Severity, number>> = {};
    for (const f of list.data ?? []) c[f.finding.severity] = (c[f.finding.severity] ?? 0) + 1;
    return c;
  }, [list.data]);

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <PageHeader
        icon={<ListChecks size={18} className="text-[var(--color-accent)]" />}
        title="Findings Manager"
        subtitle="Findings keep their status and notes across analyses. Issues that disappear are marked resolved automatically and reopened if they return."
        actions={
          <div className="flex items-center gap-3 text-[12px]">
            {SEVERITIES.map((s) => (
              <span key={s} className="flex items-center gap-1.5 tabular-nums">
                <span className="size-2 rounded-sm" style={{ background: SEVERITY_VAR[s] }} />
                {counts[s] ?? 0}
              </span>
            ))}
          </div>
        }
      />
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-line)] px-6 py-2.5">
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-2.5 text-[var(--color-faint)]" />
          <input className="input w-64 pl-7" placeholder="Search title, evidence, notes…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search findings" />
        </div>
        <span className="mx-1 h-5 w-px bg-[var(--color-line)]" />
        {SEVERITIES.map((s) => (
          <Chip key={s} active={severities.has(s)} color={SEVERITY_VAR[s]} onClick={() => setSeverities((x) => toggle(x, s))}>
            {s}
          </Chip>
        ))}
        <span className="mx-1 h-5 w-px bg-[var(--color-line)]" />
        {STATUSES.map((s) => (
          <Chip key={s} active={statuses.has(s)} onClick={() => setStatuses((x) => toggle(x, s))}>
            {STATUS_LABEL[s]}
          </Chip>
        ))}
        <span className="mx-1 h-5 w-px bg-[var(--color-line)]" />
        {CATEGORIES.map((c) => (
          <Chip key={c} active={categories.has(c)} onClick={() => setCategories((x) => toggle(x, c))}>
            {CATEGORY_LABEL[c]}
          </Chip>
        ))}
        <div className="ml-auto flex items-center gap-3 text-[12px]">
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={projectOnly} disabled={active == null} onChange={(e) => setProjectOnly(e.target.checked)} /> Active project only
          </label>
          <label className="flex items-center gap-1.5" title="Include findings no longer present in the latest analysis">
            <input type="checkbox" checked={history} onChange={(e) => setHistory(e.target.checked)} /> <History size={12} /> History
          </label>
        </div>
      </div>
      <ErrorNote error={list.error} />
      <div className="min-h-0 flex-1 overflow-auto">
        {list.loading && !list.data && (
          <div className="space-y-2 p-6">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10" />
            ))}
          </div>
        )}
        {list.data?.length === 0 && (
          <EmptyState icon={<ListChecks size={36} />} title="No findings match">
            Adjust the filters, or run an analysis on a project.
          </EmptyState>
        )}
        {!!list.data?.length && (
          <table className="w-full text-[12.5px]" data-testid="findings-table">
            <thead className="sticky top-0 z-10 bg-[var(--color-bg)]">
              <tr className="text-left text-[11px] text-[var(--color-muted)]">
                <th className="px-6 py-2 font-medium">Severity</th>
                <th className="px-2 py-2 font-medium">Finding</th>
                <th className="px-2 py-2 font-medium">Rule</th>
                <th className="px-2 py-2 font-medium">Project</th>
                <th className="px-2 py-2 font-medium">Status</th>
                <th className="px-6 py-2 text-right font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((f) => (
                <tr key={f.id} className={cx('cursor-pointer border-t border-[var(--color-line)] hover:bg-[var(--color-panel)]', !f.present && 'opacity-55')} onClick={() => setSelected(f)}>
                  <td className="px-6 py-2.5">
                    <SeverityBadge severity={f.finding.severity} />
                  </td>
                  <td className="max-w-[520px] px-2 py-2.5">
                    <div className="truncate font-medium">{f.finding.title}</div>
                    {f.notes && <div className="truncate text-[11px] text-[var(--color-faint)]">📝 {f.notes}</div>}
                  </td>
                  <td className="px-2 py-2.5 font-mono text-[11px] text-[var(--color-muted)]">{f.finding.ruleId}</td>
                  <td className="max-w-[160px] truncate px-2 py-2.5 text-[var(--color-muted)]">{f.projectName}</td>
                  <td className="px-2 py-2.5">
                    <StatusBadge status={f.status} />
                  </td>
                  <td className="px-6 py-2.5 text-right text-[11.5px] text-[var(--color-faint)]">{timeAgo(f.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {selected && <FindingDetail finding={selected.finding} stored={list.data?.find((x) => x.id === selected.id) ?? selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
