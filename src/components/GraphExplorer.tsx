import { useCallback, useEffect, useMemo, useState } from 'react';
import { Crosshair, Eye, EyeOff, Pause, Play, Radar, RotateCcw, Route, Search, SkipForward, Tags, X } from 'lucide-react';
import { api } from '../lib/api';
import { filterGraph, kindCounts } from '../lib/graph';
import { KIND_LABEL } from '../lib/format';
import type { Finding, Graph, NodeKind, Simulation } from '../lib/types';
import { GraphView, type NodeState } from './GraphView';
import { Chip, cx, EmptyState, KIND_COLOR, KindIcon, SeverityBadge, Spinner } from './ui';

interface Props {
  graph: Graph;
  findings: Finding[];
  /** Pre-select a start node for simulation (labs). */
  attacker?: string;
  /** Show the side list of path findings. */
  showPathList?: boolean;
  compact?: boolean;
}

export function GraphExplorer({ graph, findings, attacker, showPathList = true, compact = false }: Props) {
  const pathFindings = useMemo(() => findings.filter((f) => (f.path?.length ?? 0) > 1), [findings]);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [kinds, setKinds] = useState<Set<NodeKind>>(new Set());
  const [search, setSearch] = useState('');
  const [focusPath, setFocusPath] = useState(false);
  const [labels, setLabels] = useState(true);
  const [sim, setSim] = useState<Simulation | null>(null);
  const [simStep, setSimStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [simBusy, setSimBusy] = useState(false);
  const [simError, setSimError] = useState<string | null>(null);

  useEffect(() => {
    setSelectedFinding(null);
    setSelectedNode(null);
    setSim(null);
  }, [graph]);

  const finding = pathFindings.find((f) => f.id === selectedFinding) ?? null;
  const pathNodes = useMemo(() => new Set(finding?.path ?? []), [finding]);
  const pathEdges = useMemo(() => new Set(finding?.edgePath ?? []), [finding]);

  const simNodes = useMemo(() => {
    if (!sim) return null;
    const s = new Set<string>();
    sim.steps.slice(0, simStep + 1).forEach((st) => st.nodes.forEach((n) => s.add(n)));
    return s;
  }, [sim, simStep]);
  const simEdges = useMemo(() => {
    if (!sim) return null;
    const s = new Set<string>();
    sim.steps.slice(0, simStep + 1).forEach((st) => st.edges.forEach((e) => s.add(e)));
    return s;
  }, [sim, simStep]);

  const view = useMemo(
    () => filterGraph(graph, { kinds, search, focusNodes: focusPath && finding ? pathNodes : undefined }),
    [graph, kinds, search, focusPath, finding, pathNodes],
  );

  const nodeState = useCallback(
    (id: string): NodeState => {
      if (sim && simNodes) {
        if (id === sim.start) return 'start';
        return simNodes.has(id) ? 'sim' : 'dim';
      }
      if (finding) return pathNodes.has(id) ? 'hot' : 'dim';
      return undefined;
    },
    [sim, simNodes, finding, pathNodes],
  );
  const edgeClass = useCallback(
    (id: string) => {
      if (sim && simEdges) return simEdges.has(id) ? 'edge-sim' : 'edge-dim';
      if (finding) return pathEdges.has(id) ? 'edge-hot' : 'edge-dim';
      return undefined;
    },
    [sim, simEdges, finding, pathEdges],
  );

  useEffect(() => {
    if (!playing || !sim) return;
    if (simStep >= sim.steps.length - 1) {
      setPlaying(false);
      return;
    }
    const t = setTimeout(() => setSimStep((s) => s + 1), 900);
    return () => clearTimeout(t);
  }, [playing, sim, simStep]);

  const startSim = async (start: string) => {
    setSimBusy(true);
    setSimError(null);
    try {
      const s = await api.simulate(graph, start);
      setSelectedFinding(null);
      setSim(s);
      setSimStep(0);
      setPlaying(true);
    } catch (e) {
      setSimError(e instanceof Error ? e.message : String(e));
    } finally {
      setSimBusy(false);
    }
  };

  const node = selectedNode ? graph.nodes.find((n) => n.id === selectedNode) : undefined;
  const outgoing = node ? graph.edges.filter((e) => e.from === node.id) : [];
  const incoming = node ? graph.edges.filter((e) => e.to === node.id) : [];
  const labelOf = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  const counts = useMemo(() => kindCounts(graph), [graph]);

  if (graph.nodes.length === 0) {
    return (
      <EmptyState icon={<Route size={36} />} title="Empty graph">
        The analysed artifacts produced no graph nodes. Import a BreachFrame environment, RBAC, IAM or MCP file.
      </EmptyState>
    );
  }

  return (
    <div className="relative flex h-full min-h-0">
      {showPathList && (
        <aside className="flex w-[300px] shrink-0 flex-col border-r border-[var(--color-line)]" aria-label="Attack paths">
          <div className="label border-b border-[var(--color-line)] px-4 py-2.5">Attack paths ({pathFindings.length})</div>
          <ul className="flex-1 overflow-auto p-2">
            {pathFindings.length === 0 && (
              <li className="px-3 py-8 text-center text-[12px] leading-relaxed text-[var(--color-faint)]">
                No policy violations. Attack paths appear when a path in the graph breaks a policy declared in an environment file.
              </li>
            )}
            {pathFindings.map((f) => (
              <li key={f.id}>
                <button
                  onClick={() => {
                    setSim(null);
                    setSelectedFinding(f.id === selectedFinding ? null : f.id);
                  }}
                  className={cx(
                    'w-full rounded-md border px-3 py-2.5 text-left transition-colors',
                    f.id === selectedFinding ? 'border-[var(--color-sev-critical)] bg-[color-mix(in_srgb,var(--color-sev-critical)_7%,transparent)]' : 'border-transparent hover:bg-[var(--color-panel-2)]',
                  )}
                >
                  <div className="mb-1 flex items-center gap-2">
                    <SeverityBadge severity={f.severity} compact />
                    <span className="font-mono text-[10.5px] text-[var(--color-faint)]">{f.ruleId}</span>
                    <span className="ml-auto text-[10.5px] text-[var(--color-faint)]">{(f.path?.length ?? 1) - 1} hops</span>
                  </div>
                  <div className="text-[12px] leading-snug">{f.title}</div>
                </button>
              </li>
            ))}
          </ul>
        </aside>
      )}

      <div className="relative flex min-w-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-1.5 border-b border-[var(--color-line)] px-3 py-2">
          <div className="relative">
            <Search size={12} className="absolute left-2 top-[9px] text-[var(--color-faint)]" />
            <input className="input h-7 w-44 pl-6 text-[12px]" placeholder="Find node" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Find node" />
          </div>
          {counts.map(([k, n]) => (
            <Chip
              key={k}
              active={kinds.has(k)}
              color={KIND_COLOR[k]}
              onClick={() =>
                setKinds((s) => {
                  const x = new Set(s);
                  if (x.has(k)) x.delete(k);
                  else x.add(k);
                  return x;
                })
              }
            >
              {KIND_LABEL[k]} <span className="text-[var(--color-faint)]">{n}</span>
            </Chip>
          ))}
          <div className="ml-auto flex items-center gap-1.5">
            <button className={cx('btn h-7 px-2', focusPath && 'border-[var(--color-accent-dim)]')} disabled={!finding} onClick={() => setFocusPath((v) => !v)} title="Only show the selected path">
              {focusPath ? <EyeOff size={13} /> : <Eye size={13} />} Path only
            </button>
            <button className={cx('btn h-7 px-2', labels && 'border-[var(--color-accent-dim)]')} onClick={() => setLabels((v) => !v)} title="Edge labels">
              <Tags size={13} />
            </button>
          </div>
        </div>

        {sim && (
          <div className="flex items-center gap-3 border-b border-[var(--color-line)] bg-[color-mix(in_srgb,var(--color-sev-high)_6%,transparent)] px-3 py-2 text-[12px]" role="region" aria-label="Simulation">
            <Radar size={14} className="text-[var(--color-sev-high)]" />
            <span className="font-medium">Blast radius from {labelOf(sim.start)}</span>
            <button className="btn h-6 px-1.5" onClick={() => setPlaying((p) => !p)} aria-label={playing ? 'Pause' : 'Play'}>
              {playing ? <Pause size={12} /> : <Play size={12} />}
            </button>
            <button className="btn h-6 px-1.5" onClick={() => setSimStep((s) => Math.min(s + 1, sim.steps.length - 1))} aria-label="Next step">
              <SkipForward size={12} />
            </button>
            <button className="btn h-6 px-1.5" onClick={() => setSimStep(0)} aria-label="Restart">
              <RotateCcw size={12} />
            </button>
            <input type="range" min={0} max={sim.steps.length - 1} value={simStep} onChange={(e) => setSimStep(Number(e.target.value))} aria-label="Step" className="w-40 accent-[var(--color-sev-high)]" />
            <span className="tabular-nums text-[var(--color-muted)]">
              hop {simStep}/{sim.steps.length - 1} · {simNodes ? simNodes.size - 1 : 0} reached · {sim.reachedSensitive.filter((n) => simNodes?.has(n)).length} sensitive
            </span>
            <span className="ml-auto text-[10.5px] text-[var(--color-faint)]">Model-based simulation — no real system is touched</span>
            <button className="btn btn-ghost h-6 px-1" onClick={() => setSim(null)} aria-label="Stop simulation">
              <X size={13} />
            </button>
          </div>
        )}

        <div className="min-h-0 flex-1 grid-bg" data-testid="graph-canvas">
          <GraphView graph={view} nodeState={nodeState} edgeClass={edgeClass} selected={selectedNode} onSelect={setSelectedNode} showLabels={labels && view.edges.length < 120} fitKey={`${selectedFinding}-${focusPath}`} minimap={!compact} />
        </div>

        {finding && !sim && (
          <div className="absolute bottom-3 left-14 right-3 panel max-h-[34%] overflow-auto px-4 py-3 shadow-2xl animate-slide-up" style={{ right: node ? 312 : 12 }}>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="text-[12.5px] font-medium">{finding.title}</span>
            </div>
            <ol className="mt-2 flex flex-wrap items-center gap-1 text-[11.5px]">
              {finding.path?.map((id, i) => (
                <li key={id} className="flex items-center gap-1">
                  {i > 0 && <span className="text-[var(--color-sev-critical)]">→</span>}
                  <button className="rounded border border-[var(--color-line-strong)] bg-[var(--color-panel-2)] px-1.5 py-0.5 hover:border-[var(--color-accent-dim)]" onClick={() => setSelectedNode(id)}>
                    {labelOf(id)}
                  </button>
                </li>
              ))}
            </ol>
            <p className="mt-2 text-[11.5px] text-[var(--color-muted)]">{finding.recommendation}</p>
          </div>
        )}
      </div>

      {node && (
        <aside className="flex w-[300px] shrink-0 flex-col overflow-auto border-l border-[var(--color-line)] bg-[var(--color-panel)] animate-fade-in" aria-label="Node inspector">
          <div className="flex items-start gap-2.5 border-b border-[var(--color-line)] px-4 py-3">
            <KindIcon kind={node.kind} size={18} />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-semibold leading-tight">{node.label}</div>
              <code className="block break-all text-[10.5px] text-[var(--color-faint)]">{node.id}</code>
            </div>
            <button className="btn btn-ghost h-6 px-1" onClick={() => setSelectedNode(null)} aria-label="Close inspector">
              <X size={13} />
            </button>
          </div>
          <div className="space-y-4 px-4 py-3 text-[12px]">
            <button className="btn w-full justify-center" disabled={simBusy} onClick={() => startSim(node.id)}>
              {simBusy ? <Spinner size={13} /> : <Crosshair size={13} />} Simulate compromise from here
            </button>
            {simError && <div className="text-[11.5px] text-[var(--color-sev-critical)]">{simError}</div>}
            <dl className="grid grid-cols-[90px_1fr] gap-x-2 gap-y-1">
              <dt className="text-[var(--color-muted)]">Kind</dt>
              <dd>{KIND_LABEL[node.kind]}</dd>
              {node.source && (
                <>
                  <dt className="text-[var(--color-muted)]">Source</dt>
                  <dd className="truncate">{node.source}</dd>
                </>
              )}
              {Object.entries(node.attributes ?? {}).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="truncate text-[var(--color-muted)]">{k}</dt>
                  <dd className="break-all font-mono text-[11px]">{typeof v === 'string' ? v : JSON.stringify(v)}</dd>
                </div>
              ))}
            </dl>
            <div>
              <div className="label mb-1.5">Outgoing ({outgoing.length})</div>
              <ul className="space-y-1">
                {outgoing.map((e) => (
                  <li key={e.id}>
                    <button className="w-full rounded px-1.5 py-1 text-left hover:bg-[var(--color-panel-2)]" onClick={() => setSelectedNode(e.to)}>
                      <span className="font-mono text-[10.5px] text-[var(--color-accent)]">{e.relation}</span> → {labelOf(e.to)}
                      {!!e.permissions?.length && <div className="truncate font-mono text-[10px] text-[var(--color-faint)]">{e.permissions.join(', ')}</div>}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="label mb-1.5">Incoming ({incoming.length})</div>
              <ul className="space-y-1">
                {incoming.map((e) => (
                  <li key={e.id}>
                    <button className="w-full rounded px-1.5 py-1 text-left hover:bg-[var(--color-panel-2)]" onClick={() => setSelectedNode(e.from)}>
                      {labelOf(e.from)} <span className="font-mono text-[10.5px] text-[var(--color-accent)]">{e.relation}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </aside>
      )}
      {attacker && !sim && !node && (
        <button className="btn btn-primary absolute right-4 top-[58px] z-10 shadow-xl" onClick={() => startSim(attacker)} disabled={simBusy}>
          <Crosshair size={13} /> Simulate attacker
        </button>
      )}
    </div>
  );
}
