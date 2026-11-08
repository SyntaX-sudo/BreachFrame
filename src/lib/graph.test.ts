import { describe, expect, it } from 'vitest';
import { edgeLabel, filterGraph, highlightFor, isSensitive, kindCounts, layoutGraph, NODE_W } from './graph';
import type { Finding, Graph } from './types';

const graph: Graph = {
  nodes: [
    { id: 'u', kind: 'user', label: 'Alice' },
    { id: 'g', kind: 'group', label: 'Devs' },
    { id: 'r', kind: 'role', label: 'Admin role' },
    { id: 's', kind: 'secret', label: 'DB password' },
    { id: 'x', kind: 'resource', label: 'Bucket', attributes: { sensitivity: 'high' } },
  ],
  edges: [
    { id: 'u|member_of|g', from: 'u', to: 'g', relation: 'member_of' },
    { id: 'g|has_role|r', from: 'g', to: 'r', relation: 'has_role' },
    { id: 'r|grants|s', from: 'r', to: 's', relation: 'grants', permissions: ['get', 'list', 'watch', 'delete'] },
  ],
};

describe('graph utilities', () => {
  it('lays out every node deterministically, left to right', () => {
    const a = layoutGraph(graph);
    const b = layoutGraph(graph);
    expect(a.size).toBe(5);
    for (const [id, p] of a) expect(b.get(id)).toEqual(p);
    expect(a.get('u')!.x).toBeLessThan(a.get('g')!.x);
    expect(a.get('g')!.x).toBeLessThan(a.get('r')!.x);
    expect(a.get('r')!.x + NODE_W).toBeLessThanOrEqual(a.get('s')!.x);
  });

  it('filters by kind and drops dangling edges', () => {
    const f = filterGraph(graph, { kinds: new Set(['user', 'group']) });
    expect(f.nodes.map((n) => n.id)).toEqual(['u', 'g']);
    expect(f.edges.map((e) => e.id)).toEqual(['u|member_of|g']);
  });

  it('filters by search text on label or id', () => {
    expect(filterGraph(graph, { search: 'alice' }).nodes).toHaveLength(1);
    expect(filterGraph(graph, { search: 'DB' }).nodes[0].id).toBe('s');
    expect(filterGraph(graph, {}).nodes).toHaveLength(5);
  });

  it('focuses on a path', () => {
    const f = filterGraph(graph, { focusNodes: new Set(['u', 'g']) });
    expect(f.nodes).toHaveLength(2);
  });

  it('collects highlight sets from findings', () => {
    const findings = [{ path: ['u', 'g'], edgePath: ['u|member_of|g'], nodes: ['x'] } as unknown as Finding];
    const h = highlightFor(findings);
    expect([...h.nodes].sort()).toEqual(['g', 'u', 'x']);
    expect([...h.edges]).toEqual(['u|member_of|g']);
  });

  it('detects sensitive nodes', () => {
    expect(isSensitive(graph.nodes[3])).toBe(true);
    expect(isSensitive(graph.nodes[4])).toBe(true);
    expect(isSensitive(graph.nodes[0])).toBe(false);
  });

  it('formats edge labels with truncated permissions', () => {
    expect(edgeLabel(graph.edges[0])).toBe('member_of');
    expect(edgeLabel(graph.edges[2])).toBe('grants · get, list, watch +1');
  });

  it('counts kinds', () => {
    expect(kindCounts(graph)).toHaveLength(5);
  });
});
