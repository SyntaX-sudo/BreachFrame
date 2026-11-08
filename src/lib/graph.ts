import dagre from '@dagrejs/dagre';
import type { Finding, Graph, GraphEdge, GraphNode, NodeKind } from './types';

export const NODE_W = 196;
export const NODE_H = 52;

export interface Positioned {
  node: GraphNode;
  x: number;
  y: number;
}

export interface GraphFilter {
  kinds?: Set<NodeKind>;
  search?: string;
  /** Only keep nodes on these paths (plus their edges). */
  focusNodes?: Set<string>;
}

/** Filter nodes by kind / search text; edges are kept only between kept nodes. */
export function filterGraph(graph: Graph, f: GraphFilter): Graph {
  const q = f.search?.trim().toLowerCase();
  const keep = new Set<string>();
  for (const n of graph.nodes) {
    if (f.kinds && f.kinds.size > 0 && !f.kinds.has(n.kind)) continue;
    if (f.focusNodes && f.focusNodes.size > 0 && !f.focusNodes.has(n.id)) continue;
    if (q && !n.label.toLowerCase().includes(q) && !n.id.toLowerCase().includes(q)) continue;
    keep.add(n.id);
  }
  return {
    nodes: graph.nodes.filter((n) => keep.has(n.id)),
    edges: graph.edges.filter((e) => keep.has(e.from) && keep.has(e.to)),
  };
}

/** Layered left-to-right layout. Deterministic for a given graph. */
export function layoutGraph(graph: Graph, direction: 'LR' | 'TB' = 'LR'): Map<string, Positioned> {
  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({ rankdir: direction, nodesep: 22, ranksep: 90, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of graph.nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });
  for (const e of graph.edges) {
    if (g.hasNode(e.from) && g.hasNode(e.to)) g.setEdge(e.from, e.to, {}, e.id);
  }
  dagre.layout(g);
  const out = new Map<string, Positioned>();
  for (const n of graph.nodes) {
    const p = g.node(n.id) as { x: number; y: number } | undefined;
    out.set(n.id, { node: n, x: (p?.x ?? 0) - NODE_W / 2, y: (p?.y ?? 0) - NODE_H / 2 });
  }
  return out;
}

/** Nodes and edges touched by a set of findings (for highlighting). */
export function highlightFor(findings: Finding[]): { nodes: Set<string>; edges: Set<string> } {
  const nodes = new Set<string>();
  const edges = new Set<string>();
  for (const f of findings) {
    f.path?.forEach((n) => nodes.add(n));
    f.nodes?.forEach((n) => nodes.add(n));
    f.edgePath?.forEach((e) => edges.add(e));
  }
  return { nodes, edges };
}

export function isSensitive(n: GraphNode): boolean {
  if (n.kind === 'secret') return true;
  const a = n.attributes ?? {};
  return a.crown_jewel === true || a.sensitivity === 'high' || a.sensitivity === 'critical';
}

export function edgeLabel(e: GraphEdge): string {
  if (!e.permissions?.length) return e.relation;
  const perms = e.permissions.slice(0, 3).join(', ');
  return `${e.relation} · ${perms}${e.permissions.length > 3 ? ` +${e.permissions.length - 3}` : ''}`;
}

/** Count nodes by kind, sorted by frequency. */
export function kindCounts(graph: Graph): [NodeKind, number][] {
  const m = new Map<NodeKind, number>();
  for (const n of graph.nodes) m.set(n.kind, (m.get(n.kind) ?? 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}
