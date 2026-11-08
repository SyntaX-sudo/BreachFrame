import { useMemo, useState } from 'react';
import { Globe, Plug, Radar, ShieldAlert, Terminal, X } from 'lucide-react';
import { api } from '../lib/api';
import { useAsync, useProjectAnalysis } from '../lib/hooks';
import { useUi } from '../lib/store';
import type { Finding, McpServerSummary } from '../lib/types';
import { Card, cx, EmptyState, ErrorNote, PageHeader, SeverityBadge, Skeleton, Stat } from '../components/ui';
import { AnalysisPicker, NeedAnalysis, NeedProject, useImportFiles } from './common';
import { FindingDetail } from './Findings';

function ServerCard({ s, findings, onFinding }: { s: McpServerSummary; findings: Finding[]; onFinding: (f: Finding) => void }) {
  const remote = !!s.url;
  return (
    <div className={cx('panel flex flex-col', s.disabled && 'opacity-60')}>
      <div className="flex items-start gap-3 border-b border-[var(--color-line)] px-4 py-3">
        <div className="grid size-8 place-items-center rounded-md bg-[color-mix(in_srgb,#ff8fd0_14%,transparent)]">{remote ? <Globe size={15} className="text-[#ff8fd0]" /> : <Terminal size={15} className="text-[#ff8fd0]" />}</div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-[13px] font-semibold">{s.name}</span>
            {s.disabled && <span className="text-[10px] uppercase text-[var(--color-faint)]">disabled</span>}
          </div>
          <div className="text-[11px] text-[var(--color-faint)]">
            {s.transport} · {s.source}
          </div>
        </div>
        {s.maxSeverity ? <SeverityBadge severity={s.maxSeverity} /> : <span className="text-[11px] text-[var(--color-ok)]">no issues</span>}
      </div>
      <div className="space-y-2.5 px-4 py-3 text-[12px]">
        <code className="block break-all rounded bg-[var(--color-bg)] px-2 py-1.5 text-[11px] text-[var(--color-muted)]">{s.url ?? [s.command, ...s.args].filter(Boolean).join(' ')}</code>
        <div className="flex flex-wrap gap-1.5">
          {s.capabilities.map((c) => (
            <span key={c} className="rounded-full border border-[var(--color-line-strong)] px-2 py-[1px] text-[10.5px]">
              {c}
            </span>
          ))}
          {s.capabilities.length === 0 && <span className="text-[11px] text-[var(--color-faint)]">no capability inferred</span>}
        </div>
        {s.envKeys.length > 0 && (
          <div className="text-[11px] text-[var(--color-muted)]">
            env: <span className="font-mono">{s.envKeys.join(', ')}</span>
          </div>
        )}
        {s.autoApproved.length > 0 && (
          <div className="text-[11px] text-[var(--color-sev-high)]">
            auto-approved: <span className="font-mono">{s.autoApproved.join(', ')}</span>
          </div>
        )}
      </div>
      {findings.length > 0 && (
        <ul className="border-t border-[var(--color-line)] py-1">
          {findings.map((f) => (
            <li key={f.id}>
              <button className="flex w-full items-center gap-2 px-4 py-1.5 text-left hover:bg-[var(--color-panel-2)]" onClick={() => onFinding(f)}>
                <SeverityBadge severity={f.severity} compact />
                <span className="truncate text-[12px]">{f.title}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function McpView() {
  const active = useUi((s) => s.activeProjectId);
  const pa = useProjectAnalysis();
  const importFiles = useImportFiles();
  const discovered = useAsync(() => api.discoverMcpConfigs(), []);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [hideDiscovered, setHideDiscovered] = useState(false);
  const r = pa.detail?.result;
  const mcpFindings = useMemo(() => (r?.findings ?? []).filter((f) => f.category === 'mcp'), [r]);
  const byServer = (s: McpServerSummary) => {
    const id = `mcp:server:${s.source}:${s.name}`;
    return mcpFindings.filter((f) => f.nodes?.includes(id));
  };

  if (active == null) return <NeedProject what="MCP analysis" />;
  const servers = r?.mcpServers ?? [];
  return (
    <div className="flex h-full flex-col overflow-auto">
      <PageHeader
        icon={<Plug size={18} className="text-[var(--color-accent)]" />}
        title="MCP Security Analyzer"
        subtitle="Static analysis of MCP client configurations. Commands, URLs and scripts are never executed or contacted."
        actions={<AnalysisPicker projectId={active} analyses={pa.analyses} value={pa.analysisId} />}
      />
      <ErrorNote error={pa.error} />
      {!hideDiscovered && discovered.data && discovered.data.length > 0 && (
        <div className="mx-6 mt-4 flex items-center gap-3 rounded-lg border border-[var(--color-line-strong)] bg-[var(--color-panel)] px-4 py-2.5 text-[12px]">
          <Radar size={15} className="text-[var(--color-accent)]" />
          <span className="flex-1">
            Found {discovered.data.length} MCP configuration file(s) on this machine: <span className="text-[var(--color-muted)]">{discovered.data.map((d) => d.client).join(', ')}</span>
          </span>
          <button className="btn h-7" onClick={() => importFiles(active, discovered.data!.map((d) => d.path))}>
            Import all into project
          </button>
          <button className="btn btn-ghost h-7 px-1.5" onClick={() => setHideDiscovered(true)} aria-label="Dismiss discovered configurations">
            <X size={14} />
          </button>
        </div>
      )}
      {pa.loading && !r && <Skeleton className="m-6 h-64" />}
      {!pa.loading && !r && pa.project && <NeedAnalysis projectId={active} hasArtifacts={pa.project.artifactCount > 0} />}
      {r && servers.length === 0 && (
        <EmptyState icon={<Plug size={36} />} title="No MCP configuration in this analysis">
          Import a <code>claude_desktop_config.json</code>, <code>.mcp.json</code>, <code>~/.cursor/mcp.json</code> or VS Code <code>mcp.json</code> and re-run the analysis.
        </EmptyState>
      )}
      {r && servers.length > 0 && (
        <div className="space-y-4 p-6">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            <Stat label="Servers" value={servers.length} hint={`${servers.filter((s) => s.disabled).length} disabled`} />
            <Stat label="MCP findings" value={mcpFindings.length} color={mcpFindings.length ? 'var(--color-sev-high)' : undefined} />
            <Stat label="Hardcoded secrets" value={mcpFindings.filter((f) => f.ruleId === 'MCP-001').length} color="var(--color-sev-critical)" />
            <Stat label="Shell access" value={servers.filter((s) => s.capabilities.includes('shell')).length} hint="servers with inferred shell capability" />
            <Stat label="Auto-approved" value={servers.filter((s) => s.autoApproved.length > 0).length} hint="servers skipping confirmation" />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            {servers.map((s) => (
              <ServerCard key={`${s.source}:${s.name}`} s={s} findings={byServer(s)} onFinding={setSelected} />
            ))}
          </div>
          <Card title="Checks performed">
            <ul className="grid grid-cols-1 gap-x-6 gap-y-1.5 text-[12px] text-[var(--color-muted)] md:grid-cols-2">
              {[
                ['MCP-001', 'Hardcoded credentials in env, headers, args or URL (redacted)'],
                ['MCP-002', 'Remote servers over plaintext HTTP'],
                ['MCP-003', 'Unpinned npx/uvx packages and container images'],
                ['MCP-004', 'Shell interpreters with inline or encoded scripts'],
                ['MCP-005', 'Remote scripts piped into an interpreter'],
                ['MCP-006', 'Privileged containers, Docker socket, host mounts'],
                ['MCP-007', 'Filesystem servers exposing / or a whole home directory'],
                ['MCP-008', 'Auto-approved tools (alwaysAllow / autoApprove / trust)'],
                ['MCP-009', 'Flags that disable sandboxing or permission checks'],
                ['MCP-010', 'Executables launched from temporary directories'],
              ].map(([id, d]) => (
                <li key={id} className="flex gap-2">
                  <ShieldAlert size={13} className="mt-0.5 shrink-0 text-[var(--color-faint)]" />
                  <span className="font-mono text-[11px] text-[var(--color-text)]">{id}</span> {d}
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}
      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
