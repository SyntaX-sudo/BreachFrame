import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  BarChart3,
  CheckCircle2,
  FileText,
  FlaskConical,
  FolderKanban,
  GitCompareArrows,
  Info,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  Plug,
  Plus,
  Route,
  Search,
  Settings,
  X,
  XCircle,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useUi, type View } from '../lib/store';
import { timeAgo } from '../lib/format';
import { cx, Modal } from './ui';

export const NAV: { view: View; label: string; icon: typeof LayoutDashboard; key: string; needsProject?: boolean }[] = [
  { view: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, key: '1' },
  { view: 'projects', label: 'Projects', icon: FolderKanban, key: '2' },
  { view: 'attack-paths', label: 'Attack Paths', icon: Route, key: '3', needsProject: true },
  { view: 'permissions', label: 'Permissions', icon: KeyRound, key: '4', needsProject: true },
  { view: 'mcp', label: 'MCP Analyzer', icon: Plug, key: '5', needsProject: true },
  { view: 'labs', label: 'Simulation Labs', icon: FlaskConical, key: '6' },
  { view: 'compare', label: 'Before & After', icon: GitCompareArrows, key: '7' },
  { view: 'findings', label: 'Findings', icon: ListChecks, key: '8' },
  { view: 'reports', label: 'Reports', icon: FileText, key: '9', needsProject: true },
];

export function Logo({ size = 26 }: { size?: number }) {
  return <img src="/logo.svg" width={size} height={size} alt="" aria-hidden className="shrink-0" />;
}

export function Sidebar() {
  const view = useUi((s) => s.view);
  const setView = useUi((s) => s.setView);
  const mod = navigator.platform.toLowerCase().includes('mac') ? '⌘' : 'Ctrl';
  return (
    <nav aria-label="Main" className="flex w-[212px] shrink-0 flex-col border-r border-[var(--color-line)] bg-[var(--color-panel)]">
      <div className="flex h-[52px] items-center gap-2.5 border-b border-[var(--color-line)] px-4">
        <Logo />
        <div className="leading-tight">
          <div className="text-[13.5px] font-semibold tracking-tight">BreachFrame</div>
          <div className="text-[10px] uppercase tracking-[0.14em] text-[var(--color-faint)]">Security analysis</div>
        </div>
      </div>
      <ul className="flex-1 space-y-0.5 overflow-auto p-2">
        {NAV.map((n) => (
          <li key={n.view}>
            <button
              onClick={() => setView(n.view)}
              aria-current={view === n.view ? 'page' : undefined}
              className={cx(
                'group flex h-8 w-full items-center gap-2.5 rounded-md px-2.5 text-[12.5px] transition-colors',
                view === n.view ? 'bg-[var(--color-panel-3)] text-[var(--color-text)]' : 'text-[var(--color-muted)] hover:bg-[var(--color-panel-2)] hover:text-[var(--color-text)]',
              )}
            >
              <n.icon size={15} className={view === n.view ? 'text-[var(--color-accent)]' : ''} />
              <span className="flex-1 text-left">{n.label}</span>
              <span className="kbd opacity-0 transition-opacity group-hover:opacity-100">
                {mod}
                {n.key}
              </span>
            </button>
          </li>
        ))}
      </ul>
      <div className="border-t border-[var(--color-line)] p-2">
        <button
          onClick={() => setView('settings')}
          className={cx(
            'flex h-8 w-full items-center gap-2.5 rounded-md px-2.5 text-[12.5px]',
            view === 'settings' ? 'bg-[var(--color-panel-3)]' : 'text-[var(--color-muted)] hover:bg-[var(--color-panel-2)] hover:text-[var(--color-text)]',
          )}
        >
          <Settings size={15} /> Settings & About
        </button>
      </div>
    </nav>
  );
}

export function TopBar() {
  const open = useUi((s) => s.openProjects);
  const active = useUi((s) => s.activeProjectId);
  const setActive = useUi((s) => s.setActiveProject);
  const close = useUi((s) => s.closeProject);
  const setView = useUi((s) => s.setView);
  const setPalette = useUi((s) => s.setPalette);
  const toggleActivity = useUi((s) => s.toggleActivity);
  const activityOpen = useUi((s) => s.activityOpen);
  const projects = useAsync(() => api.listProjects(), []);
  const byId = useMemo(() => new Map((projects.data ?? []).map((p) => [p.id, p])), [projects.data]);

  // Drop tabs whose project was deleted. The list can be stale right after a
  // project is created (the tab opens before the refetch lands), so a tab is
  // only closed once the backend confirms the project no longer exists.
  const loadingProjects = projects.loading;
  useEffect(() => {
    if (!projects.data || loadingProjects) return;
    let cancelled = false;
    for (const id of open) {
      if (byId.has(id)) continue;
      api.getProject(id).then(
        () => undefined,
        () => !cancelled && close(id),
      );
    }
    return () => {
      cancelled = true;
    };
  }, [projects.data, loadingProjects, byId, open, close]);

  const mod = navigator.platform.toLowerCase().includes('mac') ? '⌘' : 'Ctrl';
  return (
    <div className="flex h-[52px] shrink-0 items-center gap-3 border-b border-[var(--color-line)] bg-[var(--color-panel)] pl-2 pr-3">
      <div role="tablist" aria-label="Open projects" className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto">
        {open.map((id) => {
          const p = byId.get(id);
          if (!p) return null;
          const isActive = id === active;
          return (
            <div
              key={id}
              role="tab"
              aria-selected={isActive}
              className={cx(
                'group flex h-8 max-w-[220px] shrink-0 items-center gap-2 rounded-md border pl-2.5 pr-1 text-[12px] transition-colors',
                isActive ? 'border-[var(--color-line-strong)] bg-[var(--color-panel-3)]' : 'border-transparent text-[var(--color-muted)] hover:bg-[var(--color-panel-2)]',
              )}
            >
              <button className="flex min-w-0 items-center gap-2" onClick={() => setActive(id)} title={p.name}>
                <span
                  className="size-1.5 shrink-0 rounded-full"
                  style={{ background: p.latestRisk == null ? 'var(--color-faint)' : p.latestRisk >= 70 ? 'var(--color-sev-critical)' : p.latestRisk >= 40 ? 'var(--color-sev-high)' : p.latestRisk > 0 ? 'var(--color-sev-medium)' : 'var(--color-ok)' }}
                />
                <span className="truncate">{p.name}</span>
              </button>
              <button className="rounded p-0.5 opacity-50 hover:bg-[var(--color-line)] hover:opacity-100" onClick={() => close(id)} aria-label={`Close ${p.name}`}>
                <X size={12} />
              </button>
            </div>
          );
        })}
        <button className="btn btn-ghost h-8 shrink-0 px-2 text-[var(--color-muted)]" onClick={() => setView('projects')} title="Open or create a project">
          <Plus size={14} /> {open.length === 0 && <span>Open project</span>}
        </button>
      </div>
      <button onClick={() => setPalette(true)} className="flex h-8 w-[260px] shrink-0 items-center gap-2 rounded-md border border-[var(--color-line-strong)] bg-[var(--color-bg)] px-2.5 text-[12px] text-[var(--color-faint)] hover:border-[#3a4866]" aria-label="Search">
        <Search size={13} />
        <span className="flex-1 text-left">Search projects, findings, views…</span>
        <span className="kbd">{mod} K</span>
      </button>
      <button className={cx('btn h-8 px-2', activityOpen && 'border-[var(--color-accent-dim)]')} onClick={toggleActivity} aria-pressed={activityOpen} title="Activity panel">
        <Activity size={14} />
      </button>
    </div>
  );
}

const KIND_DOT: Record<string, string> = {
  analysis: 'var(--color-accent)',
  import: 'var(--color-sev-low)',
  finding: 'var(--color-sev-medium)',
  report: '#c58bff',
  project: 'var(--color-muted)',
};

export function ActivityPanel() {
  const open = useUi((s) => s.activityOpen);
  const toggle = useUi((s) => s.toggleActivity);
  const active = useUi((s) => s.activeProjectId);
  const [scope, setScope] = useState<'all' | 'project'>('all');
  const rows = useAsync(() => (open ? api.activity(scope === 'project' ? active : null, 150) : Promise.resolve([])), [open, scope, active]);
  if (!open) return null;
  return (
    <aside aria-label="Activity" className="flex w-[300px] shrink-0 flex-col border-l border-[var(--color-line)] bg-[var(--color-panel)] animate-fade-in">
      <div className="flex h-11 items-center justify-between border-b border-[var(--color-line)] px-3">
        <div className="label flex items-center gap-2">
          <Activity size={13} /> Activity
        </div>
        <div className="flex items-center gap-1">
          <select className="input h-7 text-[11.5px]" value={scope} onChange={(e) => setScope(e.target.value as 'all' | 'project')} aria-label="Activity scope">
            <option value="all">All projects</option>
            <option value="project" disabled={active == null}>
              Active project
            </option>
          </select>
          <button className="btn btn-ghost h-7 px-1.5" onClick={toggle} aria-label="Close activity">
            <X size={14} />
          </button>
        </div>
      </div>
      <ol className="flex-1 overflow-auto px-3 py-2">
        {(rows.data ?? []).map((r) => (
          <li key={r.id} className="relative border-l border-[var(--color-line)] py-2 pl-4">
            <span className="absolute -left-[4px] top-3 size-[7px] rounded-full" style={{ background: KIND_DOT[r.kind] ?? 'var(--color-muted)' }} />
            <div className="text-[12px] leading-snug">{r.message}</div>
            <div className="mt-0.5 text-[10.5px] text-[var(--color-faint)]">
              {timeAgo(r.ts)}
              {r.projectName ? ` · ${r.projectName}` : ''}
            </div>
          </li>
        ))}
        {rows.data?.length === 0 && <li className="py-8 text-center text-[12px] text-[var(--color-faint)]">No activity yet</li>}
      </ol>
    </aside>
  );
}

export function Toasts() {
  const toasts = useUi((s) => s.toasts);
  const dismiss = useUi((s) => s.dismissToast);
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[360px] flex-col gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} role={t.kind === 'error' ? 'alert' : 'status'} className="panel pointer-events-auto flex gap-3 px-3.5 py-3 shadow-2xl animate-slide-up">
          {t.kind === 'success' ? (
            <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-[var(--color-ok)]" />
          ) : t.kind === 'error' ? (
            <XCircle size={16} className="mt-0.5 shrink-0 text-[var(--color-sev-critical)]" />
          ) : (
            <Info size={16} className="mt-0.5 shrink-0 text-[var(--color-sev-low)]" />
          )}
          <div className="min-w-0 flex-1">
            <div className="text-[12.5px] font-medium">{t.title}</div>
            {t.detail && <div className="mt-0.5 break-words text-[11.5px] text-[var(--color-muted)]">{t.detail}</div>}
          </div>
          <button className="self-start opacity-50 hover:opacity-100" onClick={() => dismiss(t.id)} aria-label="Dismiss">
            <X size={13} />
          </button>
        </div>
      ))}
    </div>
  );
}

interface PaletteItem {
  id: string;
  group: string;
  label: string;
  hint?: string;
  run: () => void;
}

export function CommandPalette() {
  const open = useUi((s) => s.paletteOpen);
  const setOpen = useUi((s) => s.setPalette);
  const setView = useUi((s) => s.setView);
  const openProject = useUi((s) => s.openProject);
  const setFocusFinding = useUi((s) => s.setFocusFinding);
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const projects = useAsync(() => (open ? api.listProjects() : Promise.resolve([])), [open]);
  const findings = useAsync(() => (open && q.trim().length >= 2 ? api.listFindings({ search: q.trim() }) : Promise.resolve([])), [open, q]);

  useEffect(() => {
    if (open) {
      setQ('');
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const items: PaletteItem[] = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const match = (s: string) => !needle || s.toLowerCase().includes(needle);
    const out: PaletteItem[] = [];
    for (const n of NAV) if (match(n.label)) out.push({ id: `v-${n.view}`, group: 'Go to', label: n.label, run: () => setView(n.view) });
    if (match('Settings')) out.push({ id: 'v-settings', group: 'Go to', label: 'Settings & About', run: () => setView('settings') });
    for (const p of projects.data ?? [])
      if (match(p.name)) out.push({ id: `p-${p.id}`, group: 'Projects', label: p.name, hint: p.latestRisk != null ? `risk ${p.latestRisk}` : 'not analysed', run: () => openProject(p.id, 'attack-paths') });
    for (const f of (findings.data ?? []).slice(0, 20))
      out.push({
        id: `f-${f.id}`,
        group: 'Findings',
        label: f.finding.title,
        hint: `${f.finding.severity} · ${f.projectName}`,
        run: () => {
          openProject(f.projectId, 'findings');
          setFocusFinding(f.finding.id);
        },
      });
    return out;
  }, [q, projects.data, findings.data, setView, openProject, setFocusFinding]);

  useEffect(() => setIdx(0), [q]);

  if (!open) return null;
  const choose = (i: number) => {
    const it = items[i];
    if (!it) return;
    setOpen(false);
    it.run();
  };
  let lastGroup = '';
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/55 pt-[12vh] animate-fade-in" onMouseDown={(e) => e.target === e.currentTarget && setOpen(false)}>
      <div role="dialog" aria-label="Command palette" className="panel w-full max-w-xl overflow-hidden shadow-2xl animate-slide-up">
        <div className="flex items-center gap-2 border-b border-[var(--color-line)] px-3">
          <Search size={15} className="text-[var(--color-faint)]" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Type a view, project or finding…"
            className="h-11 flex-1 bg-transparent text-[13.5px] outline-none"
            aria-label="Search"
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setIdx((i) => Math.min(i + 1, items.length - 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setIdx((i) => Math.max(i - 1, 0));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                choose(idx);
              } else if (e.key === 'Escape') {
                setOpen(false);
              }
            }}
          />
          <span className="kbd">Esc</span>
        </div>
        <ul className="max-h-[50vh] overflow-auto py-1.5" role="listbox">
          {items.map((it, i) => {
            const header = it.group !== lastGroup ? it.group : null;
            lastGroup = it.group;
            return (
              <li key={it.id}>
                {header && <div className="label px-3.5 pb-1 pt-2.5 text-[10px]">{header}</div>}
                <button
                  role="option"
                  aria-selected={i === idx}
                  onMouseEnter={() => setIdx(i)}
                  onClick={() => choose(i)}
                  className={cx('flex w-full items-center gap-3 px-3.5 py-2 text-left text-[12.5px]', i === idx && 'bg-[var(--color-panel-3)]')}
                >
                  <span className="flex-1 truncate">{it.label}</span>
                  {it.hint && <span className="shrink-0 text-[11px] text-[var(--color-faint)]">{it.hint}</span>}
                </button>
              </li>
            );
          })}
          {items.length === 0 && <li className="px-4 py-8 text-center text-[12.5px] text-[var(--color-faint)]">No matches</li>}
        </ul>
      </div>
    </div>
  );
}

export const SHORTCUTS: [string, string][] = [
  ['Mod K', 'Command palette / search'],
  ['Mod 1 … 9', 'Switch view'],
  ['Mod N', 'New project'],
  ['Mod I', 'Import files into active project'],
  ['Mod Enter', 'Run analysis on active project'],
  ['Mod W', 'Close active project tab'],
  ['Mod Shift ]  /  [', 'Next / previous project tab'],
  ['Mod .', 'Toggle activity panel'],
  ['?', 'Show keyboard shortcuts'],
  ['Esc', 'Close dialogs'],
];

export function ShortcutsHelp() {
  const open = useUi((s) => s.shortcutsOpen);
  const setOpen = useUi((s) => s.setShortcuts);
  const mod = navigator.platform.toLowerCase().includes('mac') ? '⌘' : 'Ctrl';
  return (
    <Modal open={open} onClose={() => setOpen(false)} title="Keyboard shortcuts">
      <table className="w-full text-[12.5px]">
        <tbody>
          {SHORTCUTS.map(([k, d]) => (
            <tr key={k} className="border-b border-[var(--color-line)] last:border-0">
              <td className="py-2 pr-4">
                {k
                  .replace('Mod', mod)
                  .split(' ')
                  .filter(Boolean)
                  .map((p, i) => (
                    <span key={i} className="kbd mr-1">
                      {p}
                    </span>
                  ))}
              </td>
              <td className="py-2 text-[var(--color-muted)]">{d}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Modal>
  );
}

export function BackendMissing() {
  return (
    <div className="grid h-full place-items-center grid-bg">
      <div className="panel max-w-lg p-8 text-center">
        <div className="mx-auto mb-4 w-fit">
          <Logo size={48} />
        </div>
        <h1 className="text-[18px] font-semibold">BreachFrame desktop backend not detected</h1>
        <p className="mt-2 text-[13px] text-[var(--color-muted)]">
          This interface talks to the BreachFrame engine through the Tauri desktop shell. You are viewing it in a plain browser, so no analysis can run and no data is shown.
        </p>
        <p className="mt-4 text-[12.5px] text-[var(--color-muted)]">
          Run <code className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5">npm run tauri dev</code> or install a release build. For headless use, try the CLI:{' '}
          <code className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5">breachframe analyze file.yaml</code>.
        </p>
        <div className="mt-5 flex items-center justify-center gap-2 text-[11px] text-[var(--color-faint)]">
          <BarChart3 size={12} /> No simulated data is ever displayed.
        </div>
      </div>
    </div>
  );
}
