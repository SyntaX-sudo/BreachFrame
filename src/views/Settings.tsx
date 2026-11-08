import { ExternalLink, Keyboard, Settings, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useUi } from '../lib/store';
import { Card, PageHeader } from '../components/ui';
import { Logo } from '../components/Shell';

export function SettingsView() {
  const info = useAsync(() => api.appInfo(), []);
  const setShortcuts = useUi((s) => s.setShortcuts);
  const i = info.data;
  return (
    <div className="flex h-full flex-col overflow-auto">
      <PageHeader icon={<Settings size={18} className="text-[var(--color-accent)]" />} title="Settings & About" />
      <div className="grid grid-cols-12 gap-4 p-6">
        <Card className="col-span-12 lg:col-span-6" title="About">
          <div className="flex items-center gap-4">
            <Logo size={56} />
            <div>
              <div className="text-[18px] font-semibold">BreachFrame</div>
              <div className="text-[12.5px] text-[var(--color-muted)]">Visualize the risk. Understand the breach.</div>
              <div className="mt-1 text-[11.5px] text-[var(--color-faint)]">
                App {i?.version ?? '…'} · engine {i?.engineVersion ?? '…'} · {i?.os}/{i?.arch} · MIT License
              </div>
            </div>
          </div>
        </Card>
        <Card className="col-span-12 lg:col-span-6" title="Local data">
          <dl className="grid grid-cols-[110px_1fr] gap-y-2 text-[12px]">
            <dt className="text-[var(--color-muted)]">Data directory</dt>
            <dd>
              <code className="break-all text-[11.5px]">{i?.dataDir}</code>
            </dd>
            <dt className="text-[var(--color-muted)]">Database</dt>
            <dd>
              <code className="break-all text-[11.5px]">{i?.dbPath}</code>
            </dd>
          </dl>
          <p className="mt-3 text-[11.5px] text-[var(--color-faint)]">
            All projects, artifacts and analyses are stored in this SQLite file only. BreachFrame makes no network requests. Delete the file to reset the application.
          </p>
        </Card>
        <Card className="col-span-12 lg:col-span-6" title="Safety model">
          <ul className="space-y-2 text-[12px] text-[var(--color-muted)]">
            {[
              'Artifacts are parsed as data (JSON/YAML). Commands, scripts and URLs inside them are never executed or contacted.',
              'Input limits: 5 MiB per file, 64 nesting levels, 5 000 YAML documents, 20 000 nodes, 100 000 edges; YAML alias bombs are rejected.',
              'Credentials found in files are shown redacted in the UI, reports and database findings.',
              'Simulations are graph computations over the analysed model — no real system is accessed.',
              'HTML reports contain no scripts and declare a restrictive Content-Security-Policy.',
            ].map((t) => (
              <li key={t} className="flex gap-2">
                <ShieldCheck size={14} className="mt-0.5 shrink-0 text-[var(--color-ok)]" />
                {t}
              </li>
            ))}
          </ul>
        </Card>
        <Card className="col-span-12 lg:col-span-6" title="Help">
          <div className="flex flex-wrap gap-2">
            <button className="btn" onClick={() => setShortcuts(true)}>
              <Keyboard size={13} /> Keyboard shortcuts
            </button>
            <span className="inline-flex items-center gap-1.5 text-[12px] text-[var(--color-muted)]">
              <ExternalLink size={12} /> Documentation: see <code>docs/</code> in the repository
            </span>
          </div>
        </Card>
      </div>
    </div>
  );
}
